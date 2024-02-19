package bastion

import (
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"log"
	"moul.io/sshportal/pkg/dbmodels"
	"time"
	"sync"
)

type ConnectionManager struct {
	sync.RWMutex
	ActiveConnections map[uint]map[uint]*gossh.ServerConn
	ActiveSessions map[uint]map[uint]ssh.Session
}

func MakeConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		ActiveConnections: map[uint]map[uint]*gossh.ServerConn{},
		ActiveSessions: map[uint]map[uint]ssh.Session{},
	}
}

func (cm *ConnectionManager) GetActiveConnections(userID uint) (map[uint]*gossh.ServerConn, bool) {
	cm.RLock()
	cnx, ok := cm.ActiveConnections[userID]
	cm.RUnlock()
	return cnx, ok
}

func (cm *ConnectionManager) AddConnection(userID, sid uint, conn *gossh.ServerConn) {
	cm.Lock()
	if _, ok := cm.ActiveConnections[userID]; !ok {
		cm.ActiveConnections[userID] = map[uint]*gossh.ServerConn{}
	}
	cm.ActiveConnections[userID][sid] = conn
	cm.Unlock()
}

func (cm *ConnectionManager) DelConnection(userID, sid uint) {
	cm.Lock()
	delete(cm.ActiveConnections[userID], sid)
	cm.Unlock()
}

func (cm *ConnectionManager) GetActiveSessions(userID uint) (map[uint]ssh.Session, bool) {
	cm.RLock()
	sess, ok := cm.ActiveSessions[userID]
	cm.RUnlock()
	return sess, ok
}

func (cm *ConnectionManager) AddSession(userID, sid uint, sess ssh.Session) {
	cm.Lock()

	cm.Unlock()
}

func (cm *ConnectionManager) DelSession(userID, sid uint) {
	cm.Lock()
	delete(cm.ActiveSessions[userID], sid)
	cm.Unlock()
}

var CnxManager = MakeConnectionManager()

const USER_DISABLED = "DISABLED"

func CleanConnections(db *gorm.DB) {
	for {
		bannedUsers := []dbmodels.User{}
		if err := db.Where("comment = ?", USER_DISABLED).Find(&bannedUsers).Error; err != nil {
			log.Println("Failed to get banned users", err)
		}

		for _, user := range bannedUsers {
			if connections, ok := CnxManager.GetActiveConnections(user.ID); ok {
				for sid, cnx := range connections {
					cnx.Close()
					CnxManager.DelConnection(user.ID, sid)
				}
			}
			if sessions, ok := CnxManager.GetActiveSessions(user.ID); ok {
				for sid, sess := range sessions {
					sess.Close()
					CnxManager.DelSession(user.ID, sid)
				}
			}
		}

		time.Sleep(30 * time.Second) // TODO: VDO: make configurable
	}
}
