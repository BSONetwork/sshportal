package bastion

import (
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"log"
	"moul.io/sshportal/pkg/dbmodels"
	"time"
)

var ActiveConnections = map[uint]map[uint]*gossh.ServerConn{}
var ActiveSessions = map[uint]map[uint]ssh.Session{}

const USER_DISABLED = "DISABLED"

func CleanConnections(db *gorm.DB) {
	for {
		bannedUsers := []dbmodels.User{}
		if err := db.Where("comment = ?", USER_DISABLED).Find(&bannedUsers).Error; err != nil {
			log.Println("Failed to get banned users", err)
		}

		for _, user := range bannedUsers {
			if connections, ok := ActiveConnections[user.ID]; ok {
				for sid, cnx := range connections {
					cnx.Close()
					delete(ActiveConnections[user.ID], sid)
				}
			}
			if sessions, ok := ActiveSessions[user.ID]; ok {
				for sid, sess := range sessions {
					sess.Close()
					delete(ActiveSessions[user.ID], sid)
				}
			}
		}

		time.Sleep(30 * time.Second) // TODO: VDO: make configurable
	}
}
