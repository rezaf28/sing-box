package option

type UserManagerOptions struct {
	MaxUser        uint16     `json:"MaxUser"`
	UserIPInterval uint16     `json:"UserIPInterval"`
	UsersList      []JsonUser `json:"UsersList"`
	Mysql          JsonMysql  `json:"mysql"`
}

type JsonUser struct {
	ID                int      `json:"id"`
	IsEnabled         bool     `json:"enabled"`
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	UUID              string   `json:"uuid"`
	AlterId           int      `json:"AlterId"`
	Auth              string   `json:"auth"`
	Flow              string   `json:"flow"`
	IPLimit           uint16   `json:"IPLimit"`
	TrafficLimitTotal int64    `json:"TrafficLimitTotal"`
	TrafficLimitDown  int64    `json:"TrafficLimitDown"`
	TrafficLimitUp    int64    `json:"TrafficLimitUp"`
	Protocols         []string `json:"protocols"`
	Tags              []string `json:"tags"`
	CreatedAt         int64    `json:"CreatedAt"`
	ActivatedAt       int64    `json:"ActivatedAt"`
	UpdatedAt         int64    `json:"UpdatedAt"`
	ExpiresAt         int64    `json:"ExpiresAt"`
}

type JsonMysql struct {
	IsEnable       bool         `json:"enabled"`
	DBName         string       `json:"dbName"`
	Username       string       `json:"username"`
	Password       string       `json:"password"`
	Host           string       `json:"host"`
	Port           int          `json:"port"`
	Charset        string       `json:"charset"`
	SyncKey        string       `json:"SyncKey"`
	IntervalUpdate int          `json:"IntervalUpdate"`
	SSL            jsonMysqlTLS `json:"tls"`
}

type jsonMysqlTLS struct {
	IsEnable   bool   `json:"enabled"`
	CertPath   string `json:"certPath"`
	KeyPath    string `json:"keyPath"`
	CaPath     string `json:"caPath"`
	TlsVersion string `json:"tlsVersion"`
}
