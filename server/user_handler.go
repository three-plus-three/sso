package server

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultUserHandler 缺省 UserHandler
var DefaultUserHandler = createDbUserHandler

type IPChecker interface {
	Contains(net.IP) bool
}

var _ IPChecker = &net.IPNet{}

type User interface {
	Name() string
	Password() string
	IsValid(address string) (bool, error)
	//LockedAt() time.Time
	//BlockIPList() []IPChecker
	Data() map[string]interface{}
}

type UserImpl struct {
	name              string
	password          string
	lockedAt          time.Time
	lockedTimeExpires time.Duration
	ingressIPList     []IPChecker
	data              map[string]interface{}
}

func (u *UserImpl) Name() string {
	return u.name
}

func (u *UserImpl) Password() string {
	return u.password
}

const (
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"
)

func RealIP(req *http.Request) string {
	ra := req.RemoteAddr
	if ip := req.Header.Get(HeaderXForwardedFor); ip != "" {
		ra = ip
	} else if ip := req.Header.Get(HeaderXRealIP); ip != "" {
		ra = ip
	} else {
		ra, _, _ = net.SplitHostPort(ra)
	}
	return ra
}

func (u *UserImpl) IsValid(currentAddr string) (bool, error) {
	if len(u.ingressIPList) != 0 && u.name != "admin" {
		ip := net.ParseIP(currentAddr)
		if ip == nil {
			return false, errors.New("client address is invalid - '" + currentAddr + "'")
		}

		blocked := true
		for _, checker := range u.ingressIPList {
			if checker.Contains(ip) {
				blocked = false
				break
			}
		}
		if blocked {
			return false, ErrUserIPBlocked
		}
	}
	if !u.lockedAt.IsZero() {
		if u.lockedTimeExpires == 0 {
			return false, ErrUserLocked
		}
		if time.Now().Before(u.lockedAt.Add(u.lockedTimeExpires)) {
			return false, ErrUserLocked
		}
	}
	return true, nil
}

func (u *UserImpl) Data() map[string]interface{} {
	return u.data
}

type ipRange struct {
	start, end uint32
}

func (r *ipRange) String() string {
	var a, b [4]byte
	binary.BigEndian.PutUint32(a[:], r.start)
	binary.BigEndian.PutUint32(b[:], r.end)
	return net.IP(a[:]).String() + "-" +
		net.IP(b[:]).String()
}

func (r *ipRange) Contains(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}

	v := binary.BigEndian.Uint32(ip.To4())
	return r.start <= v && v <= r.end
}

func IPRange(start, end net.IP) (IPChecker, error) {
	if start.To4() == nil {
		return nil, errors.New("ip range 不支持 IPv6")
	}
	if end.To4() == nil {
		return nil, errors.New("ip range 不支持 IPv6")
	}
	s := binary.BigEndian.Uint32(start.To4())
	e := binary.BigEndian.Uint32(end.To4())
	return &ipRange{start: s, end: e}, nil
}

func IPRangeWith(start, end string) (IPChecker, error) {
	s := net.ParseIP(start)
	if s == nil {
		return nil, errors.New(start + " is invalid address")
	}
	e := net.ParseIP(end)
	if e == nil {
		return nil, errors.New(end + " is invalid address")
	}
	return IPRange(s, e)
}

type LockedUser struct {
	Name     string
	LockedAt time.Time
}

// UserHandler 读用户配置的 Handler
type UserHandler interface {
	Read(username, address string) ([]User, error)
	Lock(username string) error
	Unlock(username string) error
	Locked() ([]LockedUser, error)
}

type dbUserHandler struct {
	db                   *sql.DB
	querySQL             string
	lockSQL              string
	unlockSQL            string
	lockedSQL            string
	userFieldName        string
	passwordName         string
	whiteIPListFieldName string
	lockedFieldName      string
	lockedTimeExpires    time.Duration
	lockedTimeLayout     string
}

func createDbUserHandler(params interface{}) (UserHandler, error) {
	config, ok := params.(*DbConfig)
	if !ok {
		return nil, errors.New("arguments of UserConfig isn't DbConfig")
	}

	db, err := sql.Open(config.URL())
	if err != nil {
		return nil, err
	}

	lockSQL := ""
	querySQL := "SELECT * FROM users WHERE username = ?"
	unlockSQL := ""
	lockedSQL := ""

	userFieldName := "username"
	passwordName := "password"
	lockedFieldName := "locked_at"

	lockedTimeExpires := time.Duration(0)
	lockedTimeLayout := ""
	whiteIPListFieldName := "white_addresses"

	if config.Params != nil {
		if o, ok := config.Params["username"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 username 的值不是字符串")
			}
			if s = strings.TrimSpace(s); s != "" {
				userFieldName = s
			}
		}

		if o, ok := config.Params["password"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 password 的值不是字符串")
			}
			if s = strings.TrimSpace(s); s != "" {
				passwordName = s
			}
		}

		if o, ok := config.Params["white_address_list"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 white_address_list 的值不是字符串")
			}
			if s = strings.TrimSpace(s); s != "" {
				whiteIPListFieldName = s
			}
		}

		if o, ok := config.Params["locked_at"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 locked_at 的值不是字符串")
			}
			if s = strings.TrimSpace(s); s != "" {
				lockedFieldName = s

				if o, ok := config.Params["locked_format"]; ok && o != nil {
					s, ok := o.(string)
					if !ok {
						return nil, errors.New("数据库配置中的 locked_format 的值不是字符串")
					}
					if strings.TrimSpace(s) != "" {
						lockedTimeLayout = s
					}
				}

				if o, ok := config.Params["locked_time_expires"]; ok && o != nil {
					s, ok := o.(string)
					if !ok {
						return nil, errors.New("数据库配置中的 locked_time_expires 的值不是字符串")
					}
					if s = strings.TrimSpace(s); s != "" {
						duration, err := time.ParseDuration(s)
						if err != nil {
							return nil, errors.New("数据库配置中的 locked_time_expires 的值不是有效的时间间隔")
						}
						lockedTimeExpires = duration
					}
				}
			}
		}

		if o, ok := config.Params["querySQL"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 querySQL 的值不是字符串")
			}
			if strings.TrimSpace(s) != "" {
				querySQL = s
			}
		}

		if o, ok := config.Params["lockSQL"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 lockSQL 的值不是字符串")
			}
			if strings.TrimSpace(s) != "" {
				lockSQL = s
			}
		}

		if o, ok := config.Params["unlockSQL"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 unlockSQL 的值不是字符串")
			}
			if strings.TrimSpace(s) != "" {
				unlockSQL = s
			}
		}

		if o, ok := config.Params["lockedSQL"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 lockedSQL 的值不是字符串")
			}
			if strings.TrimSpace(s) != "" {
				lockedSQL = s
			}
		}
	}

	if config.DbType == "postgres" || config.DbType == "postgresql" {
		querySQL = ReplacePlaceholders(querySQL)
		lockSQL = ReplacePlaceholders(lockSQL)
		unlockSQL = ReplacePlaceholders(unlockSQL)
		lockedSQL = ReplacePlaceholders(lockedSQL)
	}

	return &dbUserHandler{
		db:                   db,
		querySQL:             querySQL,
		lockSQL:              lockSQL,
		unlockSQL:            unlockSQL,
		lockedSQL:            lockedSQL,
		whiteIPListFieldName: whiteIPListFieldName,
		userFieldName:        userFieldName,
		passwordName:         passwordName,
		lockedFieldName:      lockedFieldName,
		lockedTimeExpires:    lockedTimeExpires,
		lockedTimeLayout:     lockedTimeLayout,
	}, nil
}

func (ah *dbUserHandler) toLockedUser(data map[string]interface{}) LockedUser {
	username := fmt.Sprint(data[ah.userFieldName])
	lockedAt, _ := ah.parseTime(data[ah.lockedFieldName])

	return LockedUser{Name: username, LockedAt: lockedAt}
}

func (ah *dbUserHandler) parseTime(o interface{}) (time.Time, error) {
	switch v := o.(type) {
	case []byte:
		if len(v) != 0 {
			lockedAt := parseTime(ah.lockedTimeLayout, string(v))
			if lockedAt.IsZero() {
				return time.Time{}, fmt.Errorf("value of '"+ah.lockedFieldName+"' isn't time - %s", string(v))
			}
			return lockedAt, nil
		}
	case string:
		if v != "" {
			lockedAt := parseTime(ah.lockedTimeLayout, v)
			if lockedAt.IsZero() {
				return time.Time{}, fmt.Errorf("value of '"+ah.lockedFieldName+"' isn't time - %s", o)
			}
			return lockedAt, nil
		}
	case time.Time:
		return v, nil
	}
	return time.Time{}, fmt.Errorf("value of '"+ah.lockedFieldName+"' isn't time - %T:%v", o, o)
}

func (ah *dbUserHandler) toUser(user string, data map[string]interface{}) (User, error) {
	var password string
	if o := data[ah.passwordName]; o != nil {
		s, ok := o.(string)
		if !ok {
			return nil, fmt.Errorf("value of '"+ah.passwordName+"' isn't string - %T", o)
		}
		password = s
	}

	var lockedAt time.Time
	if o := data[ah.lockedFieldName]; o != nil {
		var err error
		lockedAt, err = ah.parseTime(o)
		if err != nil {
			return nil, err
		}
	}

	var ingressIPList []IPChecker
	if o := data[ah.whiteIPListFieldName]; o != nil {
		s, ok := o.(string)
		if !ok {
			return nil, fmt.Errorf("value of '"+ah.whiteIPListFieldName+"' isn't string - %T: %s", o, o)
		}
		var ipList []string
		if err := json.Unmarshal([]byte(s), &ipList); err != nil {
			return nil, fmt.Errorf("value of '"+ah.whiteIPListFieldName+"' isn't []string - %s", o)
		}

		for _, s := range ipList {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if strings.Contains(s, "-") {
				ss := strings.Split(s, "-")
				if len(ss) != 2 {
					return nil, fmt.Errorf("value of '"+ah.whiteIPListFieldName+"' isn't invalid ip range - %s", s)
				}
				checker, err := IPRangeWith(ss[0], ss[1])
				if err != nil {
					return nil, fmt.Errorf("value of '"+ah.whiteIPListFieldName+"' isn't invalid ip range - %s", s)
				}
				ingressIPList = append(ingressIPList, checker)
				continue
			}

			if strings.Contains(s, "/") {
				_, cidr, err := net.ParseCIDR(s)
				if err != nil {
					return nil, fmt.Errorf("value of '"+ah.whiteIPListFieldName+"' isn't invalid ip range - %s", s)
				}
				ingressIPList = append(ingressIPList, cidr)
				continue
			}

			checker, err := IPRangeWith(s, s)
			if err != nil {
				return nil, fmt.Errorf("value of '"+ah.whiteIPListFieldName+"' isn't invalid ip range - %s", s)
			}
			ingressIPList = append(ingressIPList, checker)
		}
	}

	return &UserImpl{
		name:              user,
		password:          password,
		lockedAt:          lockedAt,
		lockedTimeExpires: ah.lockedTimeExpires,
		ingressIPList:     ingressIPList,
		data:              data,
	}, nil
}

func (ah *dbUserHandler) Read(username, address string) ([]User, error) {
	rows, err := ah.db.Query(ah.querySQL, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	var users []User
	for rows.Next() {
		columns, err := rows.Columns()
		if err != nil {
			return nil, err
		}
		var values = make([]interface{}, len(columns))
		var valueRefs = make([]interface{}, len(columns))
		for idx := range values {
			valueRefs[idx] = &values[idx]
		}
		err = rows.Scan(valueRefs...)
		if nil != err {
			return nil, err
		}

		user := map[string]interface{}{}
		for idx, nm := range columns {
			value := values[idx]
			if bs, ok := value.([]byte); ok && bs != nil {
				value = string(bs)
			}
			user[nm] = value
		}
		u, err := ah.toUser(username, user)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if rows.Err() != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
	}
	return users, nil
}

func (ah *dbUserHandler) Locked() ([]LockedUser, error) {
	rows, err := ah.db.Query(ah.lockedSQL)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	var users []LockedUser
	for rows.Next() {
		columns, err := rows.Columns()
		if err != nil {
			return nil, err
		}
		var values = make([]interface{}, len(columns))
		var valueRefs = make([]interface{}, len(columns))
		for idx := range values {
			valueRefs[idx] = &values[idx]
		}
		err = rows.Scan(valueRefs...)
		if nil != err {
			return nil, err
		}

		user := map[string]interface{}{}
		for idx, nm := range columns {
			value := values[idx]
			if bs, ok := value.([]byte); ok && bs != nil {
				value = string(bs)
			}
			user[nm] = value
		}

		users = append(users, ah.toLockedUser(user))
	}
	if rows.Err() != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
	}
	return users, nil
}

func (ah *dbUserHandler) Lock(username string) error {
	if ah.lockSQL == "" {
		return nil
	}

	res, err := ah.db.Exec(ah.lockSQL, time.Now(), username)
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("0 updated")
	}
	return nil
}

func (ah *dbUserHandler) Unlock(username string) error {
	if ah.unlockSQL == "" {
		return nil
	}

	res, err := ah.db.Exec(ah.unlockSQL, username)
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("0 updated")
	}
	return nil
}

func parseTime(layout, s string) time.Time {
	if layout != "" {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t
		}
	}

	for _, layout := range []string{time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00"} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

func ReplacePlaceholders(sql string) string {
	buf := &bytes.Buffer{}
	i := 0
	for {
		p := strings.Index(sql, "?")
		if p == -1 {
			break
		}

		if len(sql[p:]) > 1 && sql[p:p+2] == "??" { // escape ?? => ?
			buf.WriteString(sql[:p])
			buf.WriteString("?")
			if len(sql[p:]) == 1 {
				break
			}
			sql = sql[p+2:]
		} else {
			i++
			buf.WriteString(sql[:p])
			fmt.Fprintf(buf, "$%d", i)
			sql = sql[p+1:]
		}
	}

	buf.WriteString(sql)
	return buf.String()
}
