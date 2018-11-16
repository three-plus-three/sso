package server

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/three-plus-three/modules/netutil"
)

// LockedUser 被锁定的用户
type LockedUser struct {
	Name     string
	LockedAt time.Time
}

// UserHandler 读用户配置的 Handler
type UserHandler interface {
	Read(username string) (User, error)
	Lock(username string) error
	Unlock(username string) error
	Locked() ([]LockedUser, error)
}

type dbUserHandler struct {
	db                   *sql.DB
	externalVerify       VerifyFunc
	verify               func(string, string) error
	querySQL             string
	lockSQL              string
	unlockSQL            string
	lockedSQL            string
	userFieldName        string
	passwordFieldName    string
	whiteIPListFieldName string
	lockedFieldName      string
	lockedTimeExpires    time.Duration
	lockedTimeLayout     string
	caseIgnore           bool
}

func createDbUserHandler(config *Config) (UserHandler, error) {
	userConfig, ok := config.UserConfig.(*DbConfig)
	if !ok {
		return nil, errors.New("arguments of UserConfig isn't DbConfig")
	}

	db, err := sql.Open(userConfig.DbType, userConfig.DbURL)
	if err != nil {
		return nil, err
	}

	verify, err := readVerify(config)
	if err != nil {
		db.Close()
		return nil, err
	}

	querySQL := "SELECT * FROM users WHERE username = ?"
	lockSQL := ""
	unlockSQL := ""
	lockedSQL := ""

	caseIgnore := true
	userFieldName := "username"
	passwordFieldName := "password"
	lockedFieldName := "locked_at"

	lockedTimeExpires := time.Duration(0)
	lockedTimeLayout := ""
	whiteIPListFieldName := "white_addresses"

	if userConfig.Params != nil {
		if s, ok := stringWith(userConfig.Params, "username", ""); !ok {
			return nil, errors.New("数据库配置中的 username 的值不是字符串")
		} else if s != "" {
			userFieldName = s
		}

		if s, ok := stringWith(userConfig.Params, "username_case_ignore", ""); !ok {
			return nil, errors.New("数据库配置中的 username 的值不是字符串")
		} else if s == "false" {
			caseIgnore = false
		}

		if s, ok := stringWith(userConfig.Params, "password", ""); !ok {
			db.Close()
			return nil, errors.New("数据库配置中的 password 的值不是字符串")
		} else if s != "" {
			passwordFieldName = s
		}

		if s, ok := stringWith(userConfig.Params, "white_address_list", ""); !ok {
			db.Close()
			return nil, errors.New("数据库配置中的 white_address_list 的值不是字符串")
		} else if s != "" {
			whiteIPListFieldName = s
		}

		if s, ok := stringWith(userConfig.Params, "locked_at", ""); !ok {
			db.Close()
			return nil, errors.New("数据库配置中的 locked_at 的值不是字符串")
		} else if s != "" {
			lockedFieldName = s

			if s, ok := stringWith(userConfig.Params, "locked_format", ""); !ok {
				db.Close()
				return nil, errors.New("数据库配置中的 locked_format 的值不是字符串")
			} else if s != "" {
				lockedTimeLayout = s
			}

			if s, ok := stringWith(userConfig.Params, "locked_time_expires", ""); !ok {
				db.Close()
				return nil, errors.New("数据库配置中的 locked_time_expires 的值不是字符串")
			} else if s != "" {
				duration, err := time.ParseDuration(s)
				if err != nil {
					return nil, errors.New("数据库配置中的 locked_time_expires 的值不是有效的时间间隔")
				}
				lockedTimeExpires = duration
			}
		}

		if s, ok := stringWith(userConfig.Params, "querySQL", ""); !ok {
			db.Close()
			return nil, errors.New("数据库配置中的 querySQL 的值不是字符串")
		} else if s != "" {
			querySQL = s
		}

		if s, ok := stringWith(userConfig.Params, "lockSQL", ""); !ok {
			db.Close()
			return nil, errors.New("数据库配置中的 lockSQL 的值不是字符串")
		} else if s != "" {
			lockSQL = s
		}

		if s, ok := stringWith(userConfig.Params, "unlockSQL", ""); !ok {
			db.Close()
			return nil, errors.New("数据库配置中的 unlockSQL 的值不是字符串")
		} else if s != "" {
			unlockSQL = s
		}

		if s, ok := stringWith(userConfig.Params, "lockedSQL", ""); !ok {
			db.Close()
			return nil, errors.New("数据库配置中的 lockedSQL 的值不是字符串")
		} else if s != "" {
			lockedSQL = s
		}
	}

	if userConfig.DbType == "postgres" || userConfig.DbType == "postgresql" {
		querySQL = ReplacePlaceholders(querySQL)
		lockSQL = ReplacePlaceholders(lockSQL)
		unlockSQL = ReplacePlaceholders(unlockSQL)
		lockedSQL = ReplacePlaceholders(lockedSQL)
	}

	return &dbUserHandler{
		db:                   db,
		externalVerify:       config.ExternalVerify,
		verify:               verify,
		querySQL:             querySQL,
		lockSQL:              lockSQL,
		unlockSQL:            unlockSQL,
		lockedSQL:            lockedSQL,
		whiteIPListFieldName: whiteIPListFieldName,
		caseIgnore:           caseIgnore,
		userFieldName:        userFieldName,
		passwordFieldName:    passwordFieldName,
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
	if ah.userFieldName != "" {
		if o := data[ah.userFieldName]; o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, fmt.Errorf("value of '"+ah.userFieldName+"' isn't string - %T", o)
			}
			user = s
		}
	}

	var password string
	if ah.passwordFieldName != "" {
		if o := data[ah.passwordFieldName]; o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, fmt.Errorf("value of '"+ah.passwordFieldName+"' isn't string - %T", o)
			}
			password = s
		}
	}

	var lockedAt time.Time
	if o := data[ah.lockedFieldName]; o != nil {
		var err error
		lockedAt, err = ah.parseTime(o)
		if err != nil {
			return nil, err
		}
	}

	var ingressIPList []netutil.IPChecker
	if o := data[ah.whiteIPListFieldName]; o != nil {
		s, ok := o.(string)
		if !ok {
			return nil, fmt.Errorf("value of '"+ah.whiteIPListFieldName+"' isn't string - %T: %s", o, o)
		}
		var ipList []string
		if err := json.Unmarshal([]byte(s), &ipList); err != nil {
			scanner := bufio.NewScanner(strings.NewReader(s))
			for scanner.Scan() {
				bs := scanner.Bytes()
				if len(bs) == 0 {
					continue
				}
				bs = bytes.TrimSpace(bs)
				if len(bs) == 0 {
					continue
				}

				for _, field := range bytes.Split(bs, []byte(",")) {
					if len(field) == 0 {
						continue
					}
					field = bytes.TrimSpace(field)
					if len(field) == 0 {
						continue
					}

					ipList = append(ipList, string(field))
				}
			}
			if err := scanner.Err(); err != nil {
				return nil, fmt.Errorf("value of '"+ah.whiteIPListFieldName+"' isn't []string - %s", o)
			}
		}

		var err error
		ingressIPList, err = netutil.ToCheckers(ipList)
		if err != nil {
			return nil, fmt.Errorf("value of '"+ah.whiteIPListFieldName+"' isn't invalid ip range - %s", s)
		}
	}

	return &UserImpl{
		externalVerify:    ah.externalVerify,
		verify:            ah.verify,
		name:              user,
		password:          password,
		lockedAt:          lockedAt,
		lockedTimeExpires: ah.lockedTimeExpires,
		ingressIPList:     ingressIPList,
		data:              data,
	}, nil
}

func (ah *dbUserHandler) Read(username string) (User, error) {
	rows, err := ah.db.Query(ah.querySQL, username)
	if err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
		if !ah.caseIgnore {
			return nil, nil
		}
		rows, err = ah.db.Query(ah.querySQL, strings.ToLower(username))
		if err != nil {
			if err != sql.ErrNoRows {
				return nil, err
			}
			return nil, nil
		}
		username = strings.ToLower(username)
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

		// 从 data 中删除密码，确保它不会传给客户端
		delete(user, ah.passwordFieldName)
		users = append(users, u)
	}

	if err = rows.Err(); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
	}

	if len(users) == 0 {
		if !ah.caseIgnore {
			return nil, nil
		}

		lowerUser := strings.ToLower(username)
		if lowerUser != username {
			return ah.Read(lowerUser)
		}
		return nil, nil
	}

	if len(users) != 1 {
		return nil, ErrMutiUsers
	}
	return users[0], nil
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

// ReplacePlaceholders 将 sql 语句中的 ? 改成 $x 形式
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
