package server

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var DefaultUserHandler = createDbUserHandler
var DefaultAuthenticationHandler = CreateUserAuthenticationHandler

// UserHandler 读用户配置的 Handler
type UserHandler interface {
	ReadUser(username string) ([]map[string]interface{}, error)
	LockUser(username string) error
}

// AuthenticationHandler 验证用户并返回用户信息
type AuthenticationHandler interface {
	Auth(username, password string) (bool, map[string]interface{}, error)
}

func replacePlaceholders(sql string) string {
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

// func createDbAuthenticationHandler(params interface{}) (AuthenticationHandler, error) {
// 	dbConfig := params.(*DbConfig)
// 	userHandler, err := createDbHandler(dbConfig)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return CreateUserAuthenticationHandler(userHandler, dbConfig.Params)
// }

func CreateUserAuthenticationHandler(userHandler UserHandler, config interface{}) (AuthenticationHandler, error) {
	var params map[string]interface{}
	if config != nil {
		m, ok := config.(map[string]interface{})
		if !ok {
			return nil, errors.New("arguments of AuthConfg isn't map")
		}
		params = m
	}

	passwordName := "password"
	lockedFieldName := ""

	lockedTimeExpires := time.Duration(0)
	lockedTimeLayout := ""

	var signingMethod SigningMethod = methodDefault
	var secretKey []byte

	if params != nil {
		if o, ok := params["password"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 password 的值不是字符串")
			}
			if s = strings.TrimSpace(s); s != "" {
				passwordName = s
			}
		}

		if o, ok := params["locked_at"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 locked_at 的值不是字符串")
			}
			if s = strings.TrimSpace(s); s != "" {
				lockedFieldName = s

				if o, ok := params["locked_format"]; ok && o != nil {
					s, ok := o.(string)
					if !ok {
						return nil, errors.New("数据库配置中的 locked_format 的值不是字符串")
					}
					if strings.TrimSpace(s) != "" {
						lockedTimeLayout = s
					}
				}

				if o, ok := params["locked_time_expires"]; ok && o != nil {
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

		if o, ok := params["passwordHashAlg"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 passwordHashAlg 的值不是字符串")
			}

			var hashKey string
			if k, ok := params["passwordHashKey"]; ok && k != nil {
				s, ok := k.(string)
				if !ok {
					return nil, errors.New("数据库配置中的 passwordHashKey 的值不是字符串")
				}
				hashKey = s
			}

			signingMethod = GetSigningMethod(s)
			if signingMethod == nil {
				return nil, errors.New("在数据库配置中的 passwordHashAlg 的算法不支持")
			}
			if hashKey != "" {
				secretKey = []byte(hashKey)
			}
		}
	}

	return &userAuthenticationHandler{
		userHandler:       userHandler,
		passwordName:      passwordName,
		lockedFieldName:   lockedFieldName,
		lockedTimeExpires: lockedTimeExpires,
		lockedTimeLayout:  lockedTimeLayout,
		signingMethod:     signingMethod,
		secretKey:         secretKey,
	}, nil
}

func parseTime(layout, s string) time.Time {
	if layout != "" {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t
		}
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

type userAuthenticationHandler struct {
	userHandler       UserHandler
	passwordName      string
	lockedFieldName   string
	lockedTimeExpires time.Duration
	lockedTimeLayout  string
	signingMethod     SigningMethod
	secretKey         []byte
}

func (ah *userAuthenticationHandler) Auth(username, password string) (bool, map[string]interface{}, error) {
	if username == "" {
		return false, nil, ErrUsernameEmpty
	}

	users, err := ah.userHandler.ReadUser(username)
	if err != nil {
		return false, nil, err
	}
	if len(users) == 0 {
		return false, nil, ErrUserNotFound
	}
	if len(users) != 1 {
		return false, nil, ErrMutiUsers
	}

	var lockedAt time.Time
	if o := users[0][ah.lockedFieldName]; o != nil {
		switch v := o.(type) {
		case []byte:
			if len(v) != 0 {
				lockedAt = parseTime(ah.lockedTimeLayout, string(v))
				if lockedAt.IsZero() {
					return false, nil, fmt.Errorf("value of '"+ah.lockedFieldName+"' isn't time in user config - %T", o)
				}
			}
		case string:
			if v != "" {
				lockedAt = parseTime(ah.lockedTimeLayout, v)
				if lockedAt.IsZero() {
					return false, nil, fmt.Errorf("value of '"+ah.lockedFieldName+"' isn't time in user config - %T", o)
				}
			}
		case time.Time:
			lockedAt = v
		}
	}

	if !lockedAt.IsZero() {
		if ah.lockedTimeExpires == 0 {
			return false, nil, ErrUserLocked
		}
		if time.Now().Before(lockedAt.Add(ah.lockedTimeExpires)) {
			return false, nil, ErrUserLocked
		}
	}

	var exceptedPassword string
	if o := users[0][ah.passwordName]; o != nil {
		s, ok := o.(string)
		if !ok {
			return false, nil, fmt.Errorf("value of '"+ah.passwordName+"' isn't string in user config - %T", o)
		}
		exceptedPassword = s
	}

	if exceptedPassword == "" {
		return false, nil, errors.New("value of '" + ah.passwordName + "' is empty in user config.")
	}

	err = ah.signingMethod.Verify(password, exceptedPassword, ah.secretKey)
	if err != nil {
		if err == ErrSignatureInvalid {
			return false, nil, ErrPasswordNotMatch
		}
		return false, nil, err
	}
	return true, users[0], nil
}

type dbHandler struct {
	db       *sql.DB
	querySQL string
	lockSQL  string
}

// 	dbConfig := params.(*DbConfig)
// 	userHandler, err := createDbHandler(dbConfig)
// 	if err != nil {
// 		return nil, err
// 	}

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

	if config.Params != nil {
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
	}

	if config.DbType == "postgres" || config.DbType == "postgresql" {
		querySQL = replacePlaceholders(querySQL)
		lockSQL = replacePlaceholders(lockSQL)
	}

	return &dbHandler{
		db:       db,
		querySQL: querySQL,
		lockSQL:  lockSQL,
	}, nil
}

func (ah *dbHandler) ReadUser(username string) ([]map[string]interface{}, error) {
	rows, err := ah.db.Query(ah.querySQL, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	var users []map[string]interface{}
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
		users = append(users, user)
	}
	if rows.Err() != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
	}
	return users, nil
}

func (ah *dbHandler) LockUser(username string) error {
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
