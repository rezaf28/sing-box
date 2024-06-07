package dbMysql

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"github.com/sagernet/sing-box/common/usermanagement"
	"github.com/sagernet/sing-box/option"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

func getMySQLConfig(options *option.JsonMysql) (*option.JsonMysql, error) {
	// Check if essential fields are present
	if options.Username == "" {
		return nil, errors.New("Mysql Error: username is required")
	}
	if options.Password == "" {
		return nil, errors.New("Mysql Error: password is required")
	}
	if options.Host == "" {
		return nil, errors.New("Mysql Error: host is required")
	}
	if options.DBName == "" {
		return nil, errors.New("Mysql Error: database name is required")
	}

	// Set default values if not present
	if options.Port == 0 {
		options.Port = 3306
	}
	if options.Charset == "" {
		options.Charset = "utf8"
	}
	if options.IntervalUpdate == 0 {
		options.IntervalUpdate = 30
	}

	return options, nil
}

func getTLSVersion(version string) uint16 {
	switch version {
	case "TLS1.0":
		return tls.VersionTLS10
	case "TLS1.1":
		return tls.VersionTLS11
	case "TLS1.2":
		return tls.VersionTLS12
	case "TLS1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12 // Default to TLS1.2 if not specified
	}
}

func NewDBConnection(config *option.JsonMysql) (*sql.DB, error) {
	// Build the DSN
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=true",
		config.Username, config.Password, config.Host, config.Port, config.DBName, config.Charset)

	// Handle SSL configuration
	if config.SSL.IsEnable {
		rootCertPool := x509.NewCertPool()
		pem, err := os.ReadFile(config.SSL.CaPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %v", err)
		}

		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("failed to append CA certificates")
		}

		clientCert := make([]tls.Certificate, 0, 1)
		if config.SSL.CertPath != "" && config.SSL.KeyPath != "" {
			certs, err := tls.LoadX509KeyPair(config.SSL.CertPath, config.SSL.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %v", err)
			}
			clientCert = append(clientCert, certs)
		} else if config.SSL.CertPath == "" && config.SSL.KeyPath == "" {
			// Neither Key nor Cert is set. Proceed without customer cert.
			err := mysql.RegisterTLSConfig("custom", &tls.Config{
				RootCAs:    rootCertPool,
				MinVersion: getTLSVersion(config.SSL.TlsVersion),
				MaxVersion: getTLSVersion(config.SSL.TlsVersion),
			})
			if err != nil {
				return nil, fmt.Errorf(err.Error())
			}

		} else {
			// one of Key or Cert is set but not both, which is ILLEGAL.
			return nil, fmt.Errorf("set both key and cert, or set neither")
		}

		tlsConfig := &tls.Config{
			RootCAs:      rootCertPool,
			Certificates: clientCert,
			MinVersion:   getTLSVersion(config.SSL.TlsVersion),
			MaxVersion:   getTLSVersion(config.SSL.TlsVersion),
		}

		err = mysql.RegisterTLSConfig("custom", tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to register TLS config: %v", err)
		}

		dsn += "&tls=custom"
	}

	// Open the connection
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	// Check the connection
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func CheckAndCreateTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		ID INT AUTO_INCREMENT PRIMARY KEY,
		IsEnabled BOOLEAN,
		SyncKey VARCHAR(255),
		Username VARCHAR(255) UNIQUE,
		Password VARCHAR(255) UNIQUE,
		UUID VARCHAR(255) UNIQUE,
	    AlterId INT UNIQUE,
		Auth VARCHAR(255),
		Flow VARCHAR(255),
		IPLimit SMALLINT UNSIGNED DEFAULT 0,
		TrafficLimitTotal BIGINT DEFAULT 0,
		TrafficLimitDown BIGINT DEFAULT 0,
		TrafficLimitUp BIGINT DEFAULT 0,
		TrafficSend BIGINT DEFAULT 0,
		TrafficRecv BIGINT DEFAULT 0,
		Protocols TEXT,
		Tags TEXT,
		CreatedAt BIGINT DEFAULT 0,
		ActivatedAt BIGINT DEFAULT 0,
		UpdatedAt BIGINT DEFAULT 0,
		LastUsageAt BIGINT DEFAULT 0,
		ExpiresAt BIGINT DEFAULT 0
	);`
	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}
	return nil
}

func fetchUsersFromDB(db *sql.DB, SyncKey string, UserLimit uint16) (map[int]usermanagement.User, error) {
	query := "SELECT ID, IsEnabled, Username, Password, UUID, AlterId, Auth, Flow, IPLimit, TrafficLimitTotal, TrafficLimitDown, TrafficLimitUp, TrafficRecv, TrafficSend, Protocols, Tags, CreatedAt, ActivatedAt, UpdatedAt,LastUsageAt, ExpiresAt FROM users "
	if SyncKey != "" {
		query = query + " WHERE `SyncKey`='" + SyncKey + "' "
	}
	if UserLimit > 0 {
		query = query + " LIMIT " + strconv.Itoa(int(UserLimit))
	}
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make(map[int]usermanagement.User)
	for rows.Next() {
		var user usermanagement.User
		var protocols, tags string
		if err := rows.Scan(&user.ID, &user.IsEnabled, &user.Username, &user.Password, &user.UUID, &user.AlterId, &user.Auth, &user.Flow, &user.IPLimit, &user.TrafficLimitTotal, &user.TrafficLimitDown, &user.TrafficLimitUp, &user.TrafficRecv, &user.TrafficSend, &protocols, &tags, &user.CreatedAt, &user.ActivatedAt, &user.UpdatedAt, &user.LastUsageAt, &user.ExpiresAt); err != nil {
			return nil, err
		}
		if protocols != "" {
			protocols = strings.ReplaceAll(protocols, " ", "")
			user.Protocols = strings.Split(protocols, ",")
		}

		if tags != "" {
			tags = strings.ReplaceAll(tags, " ", "")
			user.Tags = strings.Split(tags, ",")
		}

		users[user.ID] = user
	}
	return users, nil
}

func UpdateServerData(db *sql.DB, userID int, trafficSend, trafficRecv, activatedAt, lastusage, updatedAt int64) error {
	query := `UPDATE users SET TrafficSend = ?, TrafficRecv = ?, ActivatedAt = ?, LastUsageAt = ?, UpdatedAt = ? WHERE id = ?`
	_, err := db.Exec(query, trafficSend, trafficRecv, activatedAt, lastusage, updatedAt, userID)
	if err != nil {
		return fmt.Errorf("failed to update traffic data for user %d: %v", userID, err)
	}
	return nil
}
func isInsideArray(array []int, num int) bool {
	for _, value := range array {
		if value == num {
			return true
		}
	}
	return false
}

func IntervalSync(userManager *usermanagement.UserManager, db *sql.DB, SyncKey string) error {
	users, err := fetchUsersFromDB(db, SyncKey, userManager.MaxUser)
	if err != nil {
		log.Printf("Failed to fetch users: %v", err)
		return err
	}
	if users != nil {
		var IdList []int
		for _, user := range users {
			if userManager.IsUserExist(user.ID) {
				_, err := userManager.UpdateUser(user.ID, user.IsEnabled, user.Username, user.Password, user.UUID, user.AlterId, user.Auth, user.Flow,
					user.IPLimit, user.TrafficLimitTotal, user.TrafficLimitDown, user.TrafficLimitUp, user.Protocols, user.Tags, user.CreatedAt, user.ActivatedAt, user.ExpiresAt)
				if err == nil {
					IdList = append(IdList, user.ID)
					if user.TrafficRecv > 1 && user.ActivatedAt < 1 {
						user.ActivatedAt = time.Now().Unix()
						userManager.Users[user.ID].ActivatedAt = time.Now().Unix()
					}
					err := UpdateServerData(db, user.ID, userManager.Users[user.ID].TrafficSend, userManager.Users[user.ID].TrafficRecv,
						userManager.Users[user.ID].ActivatedAt, userManager.Users[user.ID].LastUsageAt, time.Now().Unix())
					if err != nil {
						log.Printf("Failed to update server data : %v", err)
					}
				} else {
					log.Printf("Failed to update user: %v", err)
				}
			} else {
				_, err := userManager.AddUser(user.ID, user.IsEnabled, user.Username, user.Password, user.UUID, user.AlterId, user.Auth, user.Flow,
					user.IPLimit, user.TrafficLimitTotal, user.TrafficLimitDown, user.TrafficLimitUp, user.TrafficSend, user.TrafficRecv, user.Protocols,
					user.Tags, user.CreatedAt, user.ActivatedAt, user.UpdatedAt, user.LastUsageAt, user.ExpiresAt)
				if err == nil {
					IdList = append(IdList, user.ID)
				}
			}
		}
		for c, _ := range userManager.Users {
			if !isInsideArray(IdList, userManager.Users[c].ID) {
				userManager.RemoveUser(userManager.Users[c].ID)
			}
		}
	}
	return nil
}

func SyncUserData(userManager *usermanagement.UserManager, options option.JsonMysql) {
	config, err := getMySQLConfig(&options)
	if err != nil {
		return
	}
	db, err := NewDBConnection(config)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	err = CheckAndCreateTable(db)
	if err != nil {
		return
	}

	err = IntervalSync(userManager, db, options.SyncKey)
	if err != nil {
		log.Printf("Failed to connect to database: %v", err)
	}

	ticker := time.NewTicker(time.Duration(config.IntervalUpdate) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := IntervalSync(userManager, db, options.SyncKey)
			if err != nil {
				log.Printf("Failed to connect to database: %v", err)
			}
		}
	}
}
