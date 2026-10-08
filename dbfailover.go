package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync/atomic"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
)

const (
	// failbackInterval is how often a portal running on the fallback database
	// checks whether it can go back to the primary.
	failbackInterval = 10 * time.Second

	// Defaults for DSNs that set no timeouts. Without them a dead link blocks
	// a dial or a query for minutes instead of failing over.
	defaultDialTimeout = 5 * time.Second
	defaultIOTimeout   = 10 * time.Second
)

// mysqlDriverConn is the set of driver interfaces go-sql-driver/mysql
// connections implement. failoverConn embeds it so database/sql keeps using
// the context-aware paths.
type mysqlDriverConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
	driver.Pinger
	driver.SessionResetter
	driver.Validator
	driver.NamedValueChecker
}

type dbTarget struct {
	addr      string
	connector driver.Connector
	probe     *sql.DB
}

// failoverConnector opens MySQL connections against a primary and a fallback.
// New connections go to the active target. When it is unreachable they go to
// the other one, which becomes active. Going back to the primary is left to
// watchFailback, because the primary must first replay the writes made on the
// fallback.
type failoverConnector struct {
	targets [2]dbTarget
	active  atomic.Int32
}

func newFailoverConnector(primaryDSN, fallbackDSN string) (*failoverConnector, error) {
	f := &failoverConnector{}
	for i, dsn := range []string{primaryDSN, fallbackDSN} {
		cfg, err := gomysql.ParseDSN(dsn)
		if err != nil {
			return nil, err
		}
		if cfg.Timeout == 0 {
			cfg.Timeout = defaultDialTimeout
		}
		if cfg.ReadTimeout == 0 {
			cfg.ReadTimeout = defaultIOTimeout
		}
		if cfg.WriteTimeout == 0 {
			cfg.WriteTimeout = defaultIOTimeout
		}
		connector, err := gomysql.NewConnector(cfg)
		if err != nil {
			return nil, err
		}
		probe := sql.OpenDB(connector)
		probe.SetMaxOpenConns(1)
		f.targets[i] = dbTarget{addr: cfg.Addr, connector: connector, probe: probe}
	}
	return f, nil
}

func (f *failoverConnector) Connect(ctx context.Context) (driver.Conn, error) {
	active := int(f.active.Load())
	var errs []error
	for _, i := range []int{active, 1 - active} {
		conn, err := f.targets[i].connector.Connect(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.targets[i].addr, err))
			continue
		}
		mc, ok := conn.(mysqlDriverConn)
		if !ok {
			conn.Close()
			return nil, fmt.Errorf("%s: unexpected driver connection type %T", f.targets[i].addr, conn)
		}
		if i != active && f.active.CompareAndSwap(int32(active), int32(i)) {
			log.Printf("db: %s unreachable, switched to %s", f.targets[active].addr, f.targets[i].addr)
		}
		return &failoverConn{mysqlDriverConn: mc, f: f, target: i}, nil
	}
	return nil, errors.Join(errs...)
}

func (f *failoverConnector) Driver() driver.Driver {
	return gomysql.MySQLDriver{}
}

// watchFailback moves new connections back to the primary once it is
// reachable and has replayed every write made on the fallback. Until then the
// portal stays on the fallback, so it never writes to a primary that is behind.
func (f *failoverConnector) watchFailback(ctx context.Context) {
	ticker := time.NewTicker(failbackInterval)
	defer ticker.Stop()
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if f.active.Load() == 0 {
			lastErr = ""
			continue
		}
		err := f.primaryCaughtUp(ctx)
		if err == nil {
			if f.active.CompareAndSwap(1, 0) {
				log.Printf("db: %s caught up, switched back from %s", f.targets[0].addr, f.targets[1].addr)
			}
			lastErr = ""
			continue
		}
		if err.Error() != lastErr {
			log.Printf("db: staying on %s: %v", f.targets[1].addr, err)
			lastErr = err.Error()
		}
	}
}

func (f *failoverConnector) primaryCaughtUp(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, failbackInterval)
	defer cancel()
	fallbackMaster, err := queryStatus(ctx, f.targets[1].probe, "SHOW MASTER STATUS")
	if err != nil {
		return fmt.Errorf("%s: %w", f.targets[1].addr, err)
	}
	primarySlave, err := queryStatus(ctx, f.targets[0].probe, "SHOW SLAVE STATUS")
	if err != nil {
		return fmt.Errorf("%s: %w", f.targets[0].addr, err)
	}
	return checkCaughtUp(primarySlave, fallbackMaster)
}

// checkCaughtUp returns nil when the primary's replication (SHOW SLAVE STATUS)
// has applied the fallback's binlog up to its current position (SHOW MASTER
// STATUS).
func checkCaughtUp(primarySlave, fallbackMaster map[string]string) error {
	if primarySlave["Slave_SQL_Running"] != "Yes" {
		return fmt.Errorf("primary replication SQL thread is not running: %s", primarySlave["Last_SQL_Error"])
	}
	appliedFile, appliedPos := primarySlave["Relay_Master_Log_File"], primarySlave["Exec_Master_Log_Pos"]
	file, pos := fallbackMaster["File"], fallbackMaster["Position"]
	applied, _ := strconv.ParseUint(appliedPos, 10, 64)
	target, _ := strconv.ParseUint(pos, 10, 64)
	if appliedFile != file || applied < target {
		return fmt.Errorf("primary applied %s:%s, fallback is at %s:%s", appliedFile, appliedPos, file, pos)
	}
	return nil
}

// queryStatus runs a SHOW ... STATUS statement and returns its first row by
// column name.
func queryStatus(ctx context.Context, db *sql.DB, query string) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s returned no rows", query)
	}
	values := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range values {
		ptrs[i] = &values[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	status := make(map[string]string, len(cols))
	for i, col := range cols {
		status[col] = values[i].String
	}
	return status, nil
}

// failoverConn is a connection to one target. Once that target is no longer
// active it reports itself invalid, so database/sql closes it instead of
// reusing it.
type failoverConn struct {
	mysqlDriverConn
	f      *failoverConnector
	target int
}

func (c *failoverConn) IsValid() bool {
	return int(c.f.active.Load()) == c.target && c.mysqlDriverConn.IsValid()
}

func (c *failoverConn) ResetSession(ctx context.Context) error {
	if int(c.f.active.Load()) != c.target {
		return driver.ErrBadConn
	}
	return c.mysqlDriverConn.ResetSession(ctx)
}
