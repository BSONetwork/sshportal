package main

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
)

type fakeConn struct{ mysqlDriverConn }

func (fakeConn) IsValid() bool { return true }
func (fakeConn) Close() error  { return nil }

type fakeConnector struct{ up bool }

func (c *fakeConnector) Connect(context.Context) (driver.Conn, error) {
	if !c.up {
		return nil, errors.New("connection refused")
	}
	return fakeConn{}, nil
}

func (c *fakeConnector) Driver() driver.Driver { return nil }

func TestFailoverConnect(t *testing.T) {
	primary, fallback := &fakeConnector{up: true}, &fakeConnector{up: true}
	f := &failoverConnector{targets: [2]dbTarget{
		{addr: "primary", connector: primary},
		{addr: "fallback", connector: fallback},
	}}
	connect := func(wantTarget int) *failoverConn {
		t.Helper()
		conn, err := f.Connect(context.Background())
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		fc := conn.(*failoverConn)
		if fc.target != wantTarget || int(f.active.Load()) != wantTarget {
			t.Fatalf("got conn on target %d, active %d, want %d", fc.target, f.active.Load(), wantTarget)
		}
		return fc
	}

	onPrimary := connect(0)

	primary.up = false
	connect(1)
	if onPrimary.IsValid() {
		t.Error("connection to the old target must be invalid after a failover")
	}

	// The primary coming back is not enough: only watchFailback moves back.
	primary.up = true
	connect(1)

	fallback.up = false
	connect(0)

	primary.up = false
	if _, err := f.Connect(context.Background()); err == nil {
		t.Error("Connect must fail when both targets are down")
	}
}

func TestCheckCaughtUp(t *testing.T) {
	fallbackMaster := map[string]string{"File": "mariadb-bin.000006", "Position": "500146039"}
	for _, tc := range []struct {
		name         string
		primarySlave map[string]string
		wantErr      bool
	}{
		{"caught up", map[string]string{"Slave_SQL_Running": "Yes", "Relay_Master_Log_File": "mariadb-bin.000006", "Exec_Master_Log_Pos": "500146039"}, false},
		{"behind", map[string]string{"Slave_SQL_Running": "Yes", "Relay_Master_Log_File": "mariadb-bin.000006", "Exec_Master_Log_Pos": "500111675"}, true},
		{"older binlog", map[string]string{"Slave_SQL_Running": "Yes", "Relay_Master_Log_File": "mariadb-bin.000005", "Exec_Master_Log_Pos": "900000000"}, true},
		{"sql thread stopped", map[string]string{"Slave_SQL_Running": "No", "Relay_Master_Log_File": "mariadb-bin.000006", "Exec_Master_Log_Pos": "500146039"}, true},
		{"not a replica", map[string]string{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkCaughtUp(tc.primarySlave, fallbackMaster); (err != nil) != tc.wantErr {
				t.Errorf("checkCaughtUp() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
