package server

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

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

func createDbAuthenticationHandler(params interface{}) (AuthenticationHandler, error) {
	dbConfig := params.(*DbConfig)
	userHandler, err := createDbHandler(dbConfig)
	if err != nil {
		return nil, err
	}
	return CreateUserAuthenticationHandler(userHandler, dbConfig.Params)
}

func CreateUserAuthenticationHandler(userHandler UserHandler, params map[string]interface{}) (AuthenticationHandler, error) {
	passwordName := "password"
	var signingMethod SigningMethod = methodDefault
	var secretKey []byte

	if params != nil {
		if o, ok := params["password"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 password 的值不是字符串")
			}
			if strings.TrimSpace(s) != "" {
				passwordName = s
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
		userHandler:   userHandler,
		passwordName:  passwordName,
		signingMethod: signingMethod,
		secretKey:     secretKey,
	}, nil
}

type userAuthenticationHandler struct {
	userHandler   UserHandler
	passwordName  string
	signingMethod SigningMethod
	secretKey     []byte
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
	db           *sql.DB
	querySQL     string
	passwordName string
}

func createDbHandler(config *DbConfig) (UserHandler, error) {
	db, err := sql.Open(config.URL())
	if err != nil {
		return nil, err
	}

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
	}

	if config.DbType == "postgres" || config.DbType == "postgresql" {
		querySQL = replacePlaceholders(querySQL)
	}

	return &dbHandler{
		db:       db,
		querySQL: querySQL,
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
			if bs, ok := value.([]byte); ok {
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
