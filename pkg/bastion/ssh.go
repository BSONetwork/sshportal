package bastion // import "moul.io/sshportal/pkg/bastion"

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
	"math/rand"
	"sync"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"moul.io/sshportal/pkg/crypto"
	"moul.io/sshportal/pkg/dbmodels"
)

type sshportalContextKey string

var authContextKey = sshportalContextKey("auth")

const DIRECT_TCP_KEEPALIVE_DURATION = 120 * time.Second

type authContext struct {
	message         string
	err             error
	user            dbmodels.User
	inputUsername   string
	db              *gorm.DB
	userKey         dbmodels.UserKey
	logsLocation    string
	aclCheckCmd     string
	aesKey          string
	dbDriver, dbURL string
	bindAddr        string
	demo, debug     bool
	authMethod      string
	authSuccess     bool
}

type userType string

const (
	userTypeHealthcheck userType = "healthcheck"
	userTypeBastion     userType = "bastion"
	userTypeInvite      userType = "invite"
	userTypeShell       userType = "shell"
)

func (c authContext) userType() userType {
	switch {
	case c.inputUsername == "healthcheck":
		return userTypeHealthcheck
	case c.inputUsername == c.user.Name || c.inputUsername == c.user.Email || c.inputUsername == "admin":
		return userTypeShell
	case strings.HasPrefix(c.inputUsername, "invite:"):
		return userTypeInvite
	default:
		return userTypeBastion
	}
}

func dynamicHostKey(db *gorm.DB, host *dbmodels.Host) gossh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		if len(host.HostKey) == 0 {
			log.Println("Discovering host fingerprint...")
			return db.Model(host).Update("HostKey", key.Marshal()).Error
		}

		if !bytes.Equal(host.HostKey, key.Marshal()) {
			return fmt.Errorf("ssh: host key mismatch")
		}
		return nil
	}
}

var DefaultChannelHandler ssh.ChannelHandler = func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {}

type DirectTCPCnx struct {
	Conn *gossh.ServerConn
	Ctx ssh.Context
	SessionConfigs []sessionConfig
	LastUsed time.Time
}

type DirectTCPCnxManager struct {
	sync.RWMutex
	Connections map[string]*DirectTCPCnx
}

func (d *DirectTCPCnxManager) GetAndUpdate(hash string) *DirectTCPCnx {
	d.Lock()
	defer d.Unlock()
	if cnx, ok := d.Connections[hash]; ok {
		cnx.LastUsed = time.Now()
		return cnx
	}
	return nil
}

func (d *DirectTCPCnxManager) Add(hash string, cnx *DirectTCPCnx) {
	d.Lock()
	d.Connections[hash] = cnx
	d.Unlock()
}

func newDirectTCPCnxManager() DirectTCPCnxManager {
	manager := DirectTCPCnxManager{
		Connections: map[string]*DirectTCPCnx{},
	}
	go func(d *DirectTCPCnxManager) {
		for {
			d.Lock()
			for h, cnx := range d.Connections {
				if time.Since(cnx.LastUsed) > DIRECT_TCP_KEEPALIVE_DURATION {
					delete(d.Connections, h)
				}
			}
			d.Unlock()
			time.Sleep(DIRECT_TCP_KEEPALIVE_DURATION)
		}
	}(&manager)
	return manager
}

var directTCPManager = newDirectTCPCnxManager()

func hashTCPCnx(parts ...interface{}) string {
	result := ""
	for _, p := range parts {
		result += fmt.Sprintf("%q/", p)
	}
	return result
}

func ChannelHandler(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	actx := ctx.Value(authContextKey).(*authContext)
	hashed := hashTCPCnx(conn.User(), conn.RemoteAddr(), conn.LocalAddr(), actx.user.ID, actx.user.Email)

	switch newChan.ChannelType() {
	case "session":
	case "direct-tcpip":
		if v := directTCPManager.GetAndUpdate(hashed); v != nil {
			if err := multiChannelHandler(v.Conn, newChan, v.Ctx, v.SessionConfigs, 0); err != nil {
				log.Println("Error on direct-tcpip session", conn.User(), actx.user.Email)
			}
			return
		}
	default:
		// TODO: handle direct-tcp (only for ssh scheme)
		if err := newChan.Reject(gossh.UnknownChannelType, "unsupported channel type"); err != nil {
			log.Printf("error: failed to reject channel: %v", err)
		}
		return
	}
	if actx.user.ID == 0 && actx.userType() != userTypeHealthcheck {
		ip, err := net.ResolveTCPAddr(conn.RemoteAddr().Network(), conn.RemoteAddr().String())
		if err == nil {
			log.Printf("Auth failed: sshUser=%q remote=%q", conn.User(), ip.IP.String())
			actx.err = errors.New("access denied")

			ch, _, err2 := newChan.Accept()
			if err2 != nil {
				return
			}
			fmt.Fprintf(ch, "error: %v\n", actx.err)
			_ = ch.Close()
			return
		}
	}

	switch actx.userType() {
	case userTypeBastion:
		log.Printf("New connection(bastion): sshUser=%q remote=%q local=%q dbUser=id:%d,email:%s", conn.User(), conn.RemoteAddr(), conn.LocalAddr(), actx.user.ID, actx.user.Email)
		host, err := dbmodels.HostByName(actx.db, actx.inputUsername)
		if err != nil {
			ch, _, err2 := newChan.Accept()
			if err2 != nil {
				return
			}
			fmt.Fprintf(ch, "error: %v\n", err)
			// FIXME: force close all channels
			_ = ch.Close()
			return
		}

		switch host.Scheme() {
		case dbmodels.BastionSchemeSSH:
			sessionConfigs := make([]sessionConfig, 0)
			currentHost := host
			for currentHost != nil {
				clientConfig, err2 := bastionClientConfig(ctx, currentHost)
				if err2 != nil {
					ch, _, err3 := newChan.Accept()
					if err3 != nil {
						return
					}
					fmt.Fprintf(ch, "error: %v\n", err2)
					// FIXME: force close all channels
					_ = ch.Close()
					return
				}
				sessionConfigs = append([]sessionConfig{{
					Addr:         currentHost.DialAddr(),
					ClientConfig: clientConfig,
					LogsLocation: actx.logsLocation,
					LoggingMode:  currentHost.Logging,
				}}, sessionConfigs...)
				if currentHost.HopID != nil && *currentHost.HopID != 0 {
					var newHost dbmodels.Host
					if err := actx.db.Model(currentHost).Association("Hop").Find(&newHost); err != nil {
						log.Printf("Error: %v", err)
						return
					}
					hostname := newHost.Name
					currentHost, _ = dbmodels.HostByName(actx.db, hostname)
				} else {
					currentHost = nil
				}
			}

			sess := dbmodels.Session{
				UserID: actx.user.ID,
				HostID: host.ID,
				Status: string(dbmodels.SessionStatusActive),
			}

			if err = actx.db.Create(&sess).Error; err != nil {
				ch, _, err2 := newChan.Accept()
				if err2 != nil {
					return
				}
				fmt.Fprintf(ch, "error: %v\n", err)
				_ = ch.Close()
				return
			}

			CnxManager.AddConnection(actx.user.ID, sess.ID, conn)

			if newChan.ChannelType() == "direct-tcpip" {
				directTCPManager.Add(hashed, &DirectTCPCnx{
					Ctx: ctx,
					Conn: conn,
					SessionConfigs: sessionConfigs,
					LastUsed: time.Now(),
				})
				if err := multiChannelHandler(conn, newChan, ctx, sessionConfigs, 0); err != nil {
					log.Println("Error on direct-tcpip session", conn.User(), actx.user.Email)
				}
				return
			}

			go func() {
				err = multiChannelHandler(conn, newChan, ctx, sessionConfigs, sess.ID)
				if err != nil {
					log.Printf("Error on session %v: %v", sess.ID, err)
				}

				now := time.Now()
				sessUpdate := dbmodels.Session{
					Status:    string(dbmodels.SessionStatusClosed),
					ErrMsg:    fmt.Sprintf("%v", err),
					StoppedAt: &now,
				}
				if err == nil {
					sessUpdate.ErrMsg = ""
				}
				actx.db.Model(&sess).Updates(&sessUpdate)
				CnxManager.DelConnection(actx.user.ID, sess.ID)
				conn.Close()
			}()
		case dbmodels.BastionSchemeTelnet:
			tmpSrv := ssh.Server{
				// PtyCallback: srv.PtyCallback,
				Handler: telnetHandler(host),
			}
			DefaultChannelHandler(&tmpSrv, conn, newChan, ctx)
		default:
			ch, _, err2 := newChan.Accept()
			if err2 != nil {
				return
			}
			fmt.Fprintf(ch, "error: unknown bastion scheme: %q\n", host.Scheme())
			// FIXME: force close all channels
			_ = ch.Close()
		}
	default: // shell
		DefaultChannelHandler(srv, conn, newChan, ctx)
	}
}

func bastionClientConfig(ctx ssh.Context, host *dbmodels.Host) (*gossh.ClientConfig, error) {
	actx := ctx.Value(authContextKey).(*authContext)

	crypto.HostDecrypt(actx.aesKey, host)
	if host.SSHKey != nil {
		crypto.SSHKeyDecrypt(actx.aesKey, host.SSHKey)
	}

	clientConfig, err := host.ClientConfig(dynamicHostKey(actx.db, host))
	if err != nil {
		return nil, err
	}

	var tmpUser dbmodels.User
	if err = actx.db.Preload("Groups").Preload("Groups.ACLs").Where("id = ?", actx.user.ID).First(&tmpUser).Error; err != nil {
		return nil, err
	}

	var tmpHost dbmodels.Host
	if err = actx.db.Preload("Groups").Preload("Groups.ACLs").Where("id = ?", host.ID).First(&tmpHost).Error; err != nil {
		return nil, err
	}

	action := checkACLs(tmpUser, &tmpHost, tmpHost.Groups, actx.aclCheckCmd)

	switch action {
	case string(dbmodels.ACLActionAllow):
		// do nothing
	case string(dbmodels.ACLActionDeny):
		return nil, fmt.Errorf("you don't have permission to that host")
	default:
		return nil, fmt.Errorf("invalid ACL action: %q", action)
	}
	return clientConfig, nil
}

func ShellHandler(s ssh.Session, version, gitSha, gitTag string) {
	actx := s.Context().Value(authContextKey).(*authContext)

	if actx.userType() != userTypeHealthcheck {
		log.Printf("New connection(shell): sshUser=%q remote=%q local=%q command=%q dbUser=id:%d,email:%s", s.User(), s.RemoteAddr(), s.LocalAddr(), s.Command(), actx.user.ID, actx.user.Email)
	}

	if actx.err != nil {
		fmt.Fprintf(s, "error: %v\n", actx.err)
		_ = s.Exit(1)
		return
	}

	if actx.message != "" {
		fmt.Fprint(s, actx.message)
	}

	switch actx.userType() {
	case userTypeHealthcheck:
		fmt.Fprintln(s, "OK")
		return
	case userTypeShell:
		internalSessID := uint(rand.Uint32())
		if err := shell(internalSessID, s, version, gitSha, gitTag); err != nil {
			fmt.Fprintf(s, "error: %v\n", err)
			_ = s.Exit(1)
		}
		CnxManager.DelSession(actx.user.ID, internalSessID)
		return
	case userTypeInvite:
		// do nothing (message was printed at the beginning of the function)
		return
	}
	panic("should not happen")
}

func PasswordAuthHandler(db *gorm.DB, logsLocation, aclCheckCmd, aesKey, dbDriver, dbURL, bindAddr string, demo bool) ssh.PasswordHandler {
	return func(ctx ssh.Context, pass string) bool {
		actx := &authContext{
			db:            db,
			inputUsername: ctx.User(),
			logsLocation:  logsLocation,
			aclCheckCmd:   aclCheckCmd,
			aesKey:        aesKey,
			dbDriver:      dbDriver,
			dbURL:         dbURL,
			bindAddr:      bindAddr,
			demo:          demo,
			authMethod:    "password",
		}
		actx.authSuccess = actx.userType() == userTypeHealthcheck
		ctx.SetValue(authContextKey, actx)
		return actx.authSuccess
	}
}

func PrivateKeyFromDB(db *gorm.DB, aesKey string) func(*ssh.Server) error {
	return func(srv *ssh.Server) error {
		var key dbmodels.SSHKey
		if err := dbmodels.SSHKeysByIdentifiers(db, []string{"host"}).First(&key).Error; err != nil {
			return err
		}
		crypto.SSHKeyDecrypt(aesKey, &key)

		signer, err := gossh.ParsePrivateKey([]byte(key.PrivKey))
		if err != nil {
			return err
		}
		srv.AddHostKey(signer)
		return nil
	}
}

func PublicKeyAuthHandler(db *gorm.DB, logsLocation, aclCheckCmd, aesKey, dbDriver, dbURL, bindAddr string, demo bool) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		actx := &authContext{
			db:            db,
			inputUsername: ctx.User(),
			logsLocation:  logsLocation,
			aclCheckCmd:   aclCheckCmd,
			aesKey:        aesKey,
			dbDriver:      dbDriver,
			dbURL:         dbURL,
			bindAddr:      bindAddr,
			demo:          demo,
			authMethod:    "pubkey",
			authSuccess:   true,
		}
		ctx.SetValue(authContextKey, actx)

		// lookup user by key
		db.Where("authorized_key = ?", string(gossh.MarshalAuthorizedKey(key))).First(&actx.userKey)
		if actx.userKey.UserID > 0 {
			db.Preload("Roles").Where("id = ?", actx.userKey.UserID).First(&actx.user)

			if actx.user.Comment == USER_DISABLED {
				actx.err = fmt.Errorf("This account has been disabled")
				return false
			}

			if actx.userType() == userTypeInvite {
				actx.err = fmt.Errorf("invites are only supported for new SSH keys; your ssh key is already associated with the user %q", actx.user.Email)
			}
			return true
		}

		// handle invite "links"
		if actx.userType() == userTypeInvite {
			inputToken := strings.Split(actx.inputUsername, ":")[1]
			if len(inputToken) > 0 {
				db.Where("invite_token = ?", inputToken).First(&actx.user)
			}
			if actx.user.ID > 0 {
				actx.userKey = dbmodels.UserKey{
					UserID:        actx.user.ID,
					Key:           key.Marshal(),
					Comment:       "created by sshportal",
					AuthorizedKey: string(gossh.MarshalAuthorizedKey(key)),
				}
				db.Create(&actx.userKey)

				// token is only usable once
				actx.user.InviteToken = ""
				db.Model(&actx.user).Updates(&actx.user)

				actx.message = fmt.Sprintf("Welcome %s!\n\nYour key is now associated with the user %q.\n", actx.user.Name, actx.user.Email)
			} else {
				actx.user = dbmodels.User{Name: "Anonymous"}
				actx.err = errors.New("your token is invalid or expired")
			}
			return true
		}

		// fallback
		actx.err = errors.New("unknown ssh key")
		actx.user = dbmodels.User{Name: "Anonymous"}
		return false
	}
}
