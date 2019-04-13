package users

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
	"github.com/three-plus-three/sso/users"
)

// DefaultUserManager 缺省 UserManager
var DefaultUserManager = createUserManager

// DbConfig 服务的数据库配置项
type DbConfig struct {
	DbType string
	DbURL  string

	Params map[string]interface{}
}

// LockedUser 被锁定的用户
type LockedUser struct {
	Name     string
	LockedAt time.Time
}

// UserManager 读用户配置的 Handler
type UserManager interface {
	Read(userinfo *UserInfo) (User, error)
	Lock(username string) error
	Unlock(username string) error
	Locked() ([]LockedUser, error)

	FailCount(username string) int

	Auth(u User, userinfo *UserInfo) error
}

func createUserManager(db *sql.DB, userConfig *DbConfig, verify func(string, string) error, externalVerify VerifyFunc) (UserManager, error) {
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
			return nil, errors.New("数据库配置中的 password 的值不是字符串")
		} else if s != "" {
			passwordFieldName = s
		}

		if s, ok := stringWith(userConfig.Params, "white_address_list", ""); !ok {
			return nil, errors.New("数据库配置中的 white_address_list 的值不是字符串")
		} else if s != "" {
			whiteIPListFieldName = s
		}

		if s, ok := stringWith(userConfig.Params, "locked_at", ""); !ok {
			return nil, errors.New("数据库配置中的 locked_at 的值不是字符串")
		} else if s != "" {
			lockedFieldName = s

			if s, ok := stringWith(userConfig.Params, "locked_format", ""); !ok {
				return nil, errors.New("数据库配置中的 locked_format 的值不是字符串")
			} else if s != "" {
				lockedTimeLayout = s
			}

			if s, ok := stringWith(userConfig.Params, "locked_time_expires", ""); !ok {
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
			return nil, errors.New("数据库配置中的 querySQL 的值不是字符串")
		} else if s != "" {
			querySQL = s
		}

		if s, ok := stringWith(userConfig.Params, "lockSQL", ""); !ok {
			return nil, errors.New("数据库配置中的 lockSQL 的值不是字符串")
		} else if s != "" {
			lockSQL = s
		}

		if s, ok := stringWith(userConfig.Params, "unlockSQL", ""); !ok {
			return nil, errors.New("数据库配置中的 unlockSQL 的值不是字符串")
		} else if s != "" {
			unlockSQL = s
		}

		if s, ok := stringWith(userConfig.Params, "lockedSQL", ""); !ok {
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

	return &userManager{
		db:                   db,
		externalVerify:       externalVerify,
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

type userManager struct {
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

func (ah *userManager) SetUserNotFound(userNotFound UserNotFound) {
	ah.userNotFound = userNotFound
}

func (ah *userManager) UserNotFound(userinfo *UserInfo) (map[string]interface{}, error) {
	if ah.userNotFound != nil {
		userData, err := ah.userNotFound(userinfo)
		if err != nil {
			return nil, err
		}
		if userData != nil {
			u, _ := users.StringWith(userData, "user", "")
			if u == "" {
				u, _ = users.StringWith(userData, "username", "")
			}
			if u != "" {
				userinfo.Username = u
			}
		}
	}
	return nil, nil
}

func (ah *userManager) toLockedUser(data map[string]interface{}) LockedUser {
	username := fmt.Sprint(data[ah.userFieldName])
	lockedAt, _ := ah.parseTime(data[ah.lockedFieldName])

	return LockedUser{Name: username, LockedAt: lockedAt}
}

func (ah *userManager) parseTime(o interface{}) (time.Time, error) {
	switch v := o.(type) {
	case []byte:
		if len(v) != 0 {
			lockedAt := ParseTime(ah.lockedTimeLayout, string(v))
			if lockedAt.IsZero() {
				return time.Time{}, fmt.Errorf("value of '"+ah.lockedFieldName+"' isn't time - %s", string(v))
			}
			return lockedAt, nil
		}
	case string:
		if v != "" {
			lockedAt := ParseTime(ah.lockedTimeLayout, v)
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

func (ah *userManager) toUser(user string, data map[string]interface{}) (User, error) {
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

func (ah *userManager) Read(userinfo *UserInfo) (User, error) {
	username := userinfo.Username
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
			userinfo.Username = lowerUser
			return ah.Read(userinfo)
		}
		return nil, nil
	}

	if len(users) != 1 {
		return nil, ErrMutiUsers
	}
	return users[0], nil
}

func (ah *userManager) Locked() ([]LockedUser, error) {
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

func (ah *userManager) Lock(username string) error {
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

func (ah *userManager) Unlock(username string) error {
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

func (ah *userManager) FailCount(username string) int {
	return 0
}

func (ah *userManager) Auth(u User, userinfo *UserInfo) error {
	return u.Auth(userinfo)
}

func Auth(um UserManager, userinfo *UserInfo) (User, error) {
	auth, err := um.Read(userinfo)
	if err != nil {
		return nil, err
	}

	err = um.Auth(auth, &user)
	if err == nil {
		userData = auth.Data()
		user.Username = auth.Name()
	}

	return auth, err
}
