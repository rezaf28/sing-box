package usermanagement

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/sagernet/sing-box/option"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	userManagement *UserManager
)

type TrackedConn struct {
	net.Conn
	ID int
}

func (c *TrackedConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	atomic.AddInt64(&userManagement.Users[c.ID].TrafficRecv, int64(n))
	return
}

func (c *TrackedConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	atomic.AddInt64(&userManagement.Users[c.ID].TrafficSend, int64(n))
	return
}

type User struct {
	ID                int
	IsEnabled         bool
	Username          string
	Password          string
	UUID              string
	Key               string
	Auth              string
	Flow              string
	IPTable           sync.Map
	IPLimit           uint16
	TrafficLimitTotal int64
	TrafficLimitDown  int64
	TrafficLimitUp    int64
	TrafficSend       int64
	TrafficRecv       int64
	AlterId           int
	Protocols         []string
	Tags              []string
	CreatedAt         int64
	ActivatedAt       int64
	UpdatedAt         int64
	LastUsageAt       int64
	ExpiresAt         int64
}

func NewUserManager(options option.UserManagerOptions) *UserManager {
	if options.UserIPInterval <= 0 {
		options.UserIPInterval = 15 // Set default value to 15
	}

	userManager := &UserManager{
		MaxUser:       options.MaxUser,
		Users:         make(map[int]*User),
		IPRemoveDelay: options.UserIPInterval * 1000, // Convert to milliseconds
	}

	for _, user := range options.UsersList {
		if user.ExpiresAt > time.Now().Unix() {
			user := &User{
				ID:                user.ID,
				IsEnabled:         user.IsEnabled,
				Username:          user.Username,
				Password:          user.Password,
				UUID:              user.UUID,
				Key:               SHA224String(user.Password),
				AlterId:           user.AlterId,
				Auth:              user.Auth,
				Flow:              user.Flow,
				IPLimit:           user.IPLimit,
				TrafficLimitTotal: user.TrafficLimitTotal,
				TrafficLimitDown:  user.TrafficLimitDown,
				TrafficLimitUp:    user.TrafficLimitUp,
				TrafficSend:       0,
				TrafficRecv:       0,
				Protocols:         user.Protocols,
				Tags:              user.Tags,
				CreatedAt:         user.CreatedAt,
				ActivatedAt:       user.ActivatedAt,
				UpdatedAt:         user.UpdatedAt,
				ExpiresAt:         user.ExpiresAt,
			}
			userManager.Users[user.ID] = user
		}
	}
	userManagement = userManager
	return userManager
}

type UserManager struct {
	MaxUser       uint16
	IPRemoveDelay uint16
	Users         map[int]*User
	mu            sync.Mutex
}

func (um *UserManager) AddUser(id int, isEnabled bool, username, password, uuid string,
	alterId int, auth, flow string, ipLimit uint16, trafficLimitTotal, trafficLimitDown, trafficLimitUp, trafficSend, trafficRecv int64,
	protocols, tags []string, createTime, activetime, updateTime, lastusagetime, expiretime int64) (bool, error) {
	um.mu.Lock()
	defer um.mu.Unlock()
	if _, exists := um.Users[id]; exists {
		return false, errors.New("user with this " + strconv.Itoa(id) + " already exists")
	}
	if int(um.MaxUser) <= len(um.Users) {
		return false, errors.New("Users Limit Exceeded")
	}
	for _, user := range um.Users {
		if user.Username == username {
			return false, errors.New("user with this " + username + " already exists")
		}
		if user.Password == password {
			return false, errors.New("user with this " + password + " already exists")
		}
		if user.UUID == uuid {
			return false, errors.New("user with this " + uuid + " already exists")
		}
	}
	if isEnabled {
		if expiretime > time.Now().Unix() {
			um.Users[id] = &User{
				ID:                id,
				IsEnabled:         isEnabled,
				Username:          username,
				Password:          password,
				UUID:              uuid,
				Key:               SHA224String(password),
				AlterId:           alterId,
				Auth:              auth,
				Flow:              flow,
				IPLimit:           ipLimit,
				TrafficLimitTotal: trafficLimitTotal,
				TrafficLimitDown:  trafficLimitDown,
				TrafficLimitUp:    trafficLimitUp,
				TrafficSend:       trafficSend,
				TrafficRecv:       trafficRecv,
				Protocols:         protocols,
				Tags:              tags,
				CreatedAt:         createTime,
				ActivatedAt:       activetime,
				UpdatedAt:         updateTime,
				LastUsageAt:       lastusagetime,
				ExpiresAt:         expiretime,
			}
		} else {
			return false, errors.New("user " + username + " already expired")
		}
	} else {
		return false, errors.New("user " + username + " Disabled!")
	}

	return true, nil
}

func (um *UserManager) UpdateUser(id int, isEnabled bool, username, password, uuid string, alterId int, auth, flow string,
	ipLimit uint16, trafficLimitTotal, trafficLimitDown, trafficLimitUp int64, protocols, tags []string, createTime, activetime, expiretime int64) (bool, error) {
	um.mu.Lock()
	defer um.mu.Unlock()
	if um.Users[id] == nil {
		return false, errors.New("user with ID " + strconv.Itoa(id) + " Not exists")
	}
	for _, user := range um.Users {
		if user.Username == username && user.ID != id {
			return false, errors.New("user with this " + username + " already exists")
		}
		if user.Password == password && user.ID != id {
			return false, errors.New("user with this  " + password + "  already exists")
		}
		if user.UUID == uuid && user.ID != id {
			return false, errors.New("user with this UUID already exists")
		}
	}
	if isEnabled {
		if expiretime > time.Now().Unix() {
			um.Users[id] = &User{
				ID:                id,
				IsEnabled:         isEnabled,
				Username:          username,
				Password:          password,
				UUID:              uuid,
				Key:               SHA224String(password),
				AlterId:           alterId,
				Auth:              auth,
				Flow:              flow,
				IPTable:           um.Users[id].IPTable,
				IPLimit:           ipLimit,
				TrafficLimitTotal: trafficLimitTotal,
				TrafficLimitDown:  trafficLimitDown,
				TrafficLimitUp:    trafficLimitUp,
				TrafficSend:       um.Users[id].TrafficSend,
				TrafficRecv:       um.Users[id].TrafficRecv,
				Protocols:         protocols,
				Tags:              tags,
				CreatedAt:         createTime,
				ActivatedAt:       activetime,
				UpdatedAt:         um.Users[id].UpdatedAt,
				LastUsageAt:       um.Users[id].LastUsageAt,
				ExpiresAt:         expiretime,
			}
		} else {
			return false, errors.New("user " + username + " already expired")
		}
	} else {
		return false, errors.New("user " + username + " Disabled!")
	}

	return true, nil
}

func SHA224String(s string) string {
	hash := sha256.Sum224([]byte(s))
	return hex.EncodeToString(hash[:])
}

func (um *UserManager) GetValidId() int {
	um.mu.Lock()
	defer um.mu.Unlock()
	for i := 0; i < math.MaxInt32; i++ {
		if um.Users[i] == nil {
			return i
		}
	}
	return 0
}

func (um *UserManager) RemoveUser(id int) {
	um.mu.Lock()
	defer um.mu.Unlock()
	delete(um.Users, id)
}

func (um *UserManager) ReachedTrafficLimit(id int) bool {
	user, exists := um.Users[id]
	if !exists {
		return false
	}
	if user.TrafficLimitUp != 0 {
		if user.TrafficSend > user.TrafficLimitUp {
			return true
		}
	}
	if user.TrafficLimitDown != 0 {
		if user.TrafficRecv > user.TrafficLimitDown {
			return true
		}
	}
	if user.TrafficLimitTotal != 0 {
		if (user.TrafficSend + user.TrafficRecv) > user.TrafficLimitTotal {
			return true
		}
	}
	return false
}

func (um *UserManager) UpdateTrafficUsage(id int, conn net.Conn) net.Conn {
	return &TrackedConn{Conn: conn, ID: id}
}
func (um *UserManager) IsUserExist(id int) bool {
	if um.Users[id] != nil {
		if um.Users[id].ID == id {
			return true
		}
	}
	return false
}

func (um *UserManager) IsTagAllowed(id int, tag string) bool {
	if um.Users[id].Tags == nil {
		return true
	}
	for _, tg := range um.Users[id].Tags {
		if tg == tag {
			return true
		}
	}
	return false
}

func (um *UserManager) IsProtocolAllowed(id int, protocol string) bool {
	if um.Users[id].Protocols == nil {
		return true
	}
	for _, p := range um.Users[id].Protocols {
		if p == protocol {
			return true
		}
	}
	return false
}

func (um *UserManager) GetUser(protocol, chainKey string) (*User, error) {
	switch protocol {
	case "trojan":
		for _, user := range um.Users {
			if user.Key == chainKey {
				return user, nil
			}
		}
		return nil, errors.New("User Not Found")
	case "vless":
		for _, user := range um.Users {
			if user.UUID == chainKey {
				return user, nil
			}
		}
		return nil, errors.New("User Not Found")
	case "vmess":
		for _, user := range um.Users {
			if user.UUID == chainKey {
				return user, nil
			}
		}
		return nil, errors.New("User Not Found")
	}
	return nil, errors.New("unknown protocol")
}

func (um *UserManager) GetUserId(protocol, chainKey string) (int, error) {
	switch protocol {
	case "trojan":
		for _, user := range um.Users {
			if user.Key == chainKey {
				return user.ID, nil
			}
		}
		return 0, errors.New("User Not Found")
	}
	return 0, errors.New("unknown protocol")
}

func (um *UserManager) AddIP(protocol, tag, chainKey, ip string) bool {
	um.mu.Lock()
	defer um.mu.Unlock()
	user, err := um.GetUser(protocol, chainKey)
	if err != nil {
		return false
	}

	if !user.IsEnabled {
		return false
	}

	if um.ReachedTrafficLimit(user.ID) {
		return false
	}

	if user.IPLimit <= 0 {
		return true
	}

	if _, found := user.IPTable.Load(ip); found {
		return true
	}

	if um.IPCount(user) >= user.IPLimit {
		return false
	}

	if !um.IsTagAllowed(user.ID, tag) {
		return false
	}

	if !um.IsProtocolAllowed(user.ID, protocol) {
		return false
	}

	user.IPTable.Store(ip, true)
	user.LastUsageAt = time.Now().Unix()

	go um.DelIP(user, ip)
	return true
}

func (um *UserManager) DelIP(user *User, ip string) bool {
	if user.IPLimit <= 0 {
		return true
	}

	if _, found := user.IPTable.Load(ip); !found {
		return false
	}

	time.Sleep(time.Duration(um.IPRemoveDelay) * time.Millisecond)

	user.IPTable.Delete(ip)
	return true
}

func (um *UserManager) IPCount(user *User) uint16 {
	count := 0
	user.IPTable.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return uint16(count)
}
