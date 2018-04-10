package server

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"time"
)

type OnlineInfo struct {
	Address   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func IsOnlined(onlineList []OnlineInfo, hostAddress string) bool {
	for _, ol := range onlineList {
		if ol.Address == hostAddress {
			return true
		}
	}
	return false
}

type Online interface {
	Query(username string) ([]OnlineInfo, error)
	Save(username, address string) error
	Delete(username, address string) error
}

type emptyOnline struct{}

func (em *emptyOnline) Query(username string) ([]OnlineInfo, error) {
	return nil, nil
}

func (em *emptyOnline) Save(username, address string) error {
	return nil
}

func (em *emptyOnline) Delete(username, address string) error {
	return nil
}

func createEmptyOnline(params interface{}) (Online, error) {
	return &emptyOnline{}, nil
}

func onlineHandler(params interface{}) (Online, error) {
	config, ok := params.(*DbConfig)
	if ok {
		if config.Params != nil {
			if online := config.Params["online"]; online == "db" {
				return createDbOnline(params)
			}
		}
	}

	return createEmptyOnline(params)
}

var DefaultOnlineHandler = onlineHandler

type dbOnline struct {
	db             *sql.DB
	querySQL       string
	queryUserIDSQL string
	countSQL       string
	insertSQL      string
	updateSQL      string
	deleteSQL      string
	withAddress    bool
}

func (do *dbOnline) Query(username string) ([]OnlineInfo, error) {
	rows, err := do.db.Query(do.querySQL, username)
	if err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}

		rows, err = do.db.Query(do.querySQL, strings.ToLower(username))
		if err != sql.ErrNoRows {
			return nil, err
		}
		return nil, nil
	}
	defer rows.Close()

	var onlineList = make([]OnlineInfo, 0, 1)
	for rows.Next() {
		var addr sql.NullString
		var createdAt NullTime
		var updatedAt NullTime

		if err := rows.Scan(&addr, &createdAt, &updatedAt); err != nil {
			return nil, err
		}

		var info OnlineInfo
		if addr.Valid {
			info.Address = addr.String
		}
		if createdAt.Valid {
			info.CreatedAt = createdAt.Time
		}
		if updatedAt.Valid {
			info.UpdatedAt = updatedAt.Time
		}
		onlineList = append(onlineList, info)
	}

	return onlineList, nil
}

func (do *dbOnline) Save(username, address string) error {
	var userID int
	err := do.db.QueryRow(do.queryUserIDSQL, username).Scan(&userID)
	if err != nil {
		if err != sql.ErrNoRows {
			return err
		}

		err = do.db.QueryRow(do.queryUserIDSQL, strings.ToLower(username)).Scan(&userID)
		if err != nil {
			return err
		}
	}
	var count int

	if do.withAddress {
		err = do.db.QueryRow(do.countSQL, userID, address).Scan(&count)
	} else {
		err = do.db.QueryRow(do.countSQL, userID).Scan(&count)
	}
	if err != nil {
		return err
	}

	if count == 0 {
		_, err = do.db.Exec(do.insertSQL, userID, address)
	} else {
		_, err = do.db.Exec(do.updateSQL, address, userID)
	}
	return err
}

func (do *dbOnline) Delete(username, address string) error {
	_, err := do.db.Exec(do.deleteSQL, username, address)
	_, _ = do.db.Exec(do.deleteSQL, strings.ToLower(username), address)
	return err
}

func createDbOnline(params interface{}) (Online, error) {
	config, ok := params.(*DbConfig)
	if !ok {
		return nil, errors.New("arguments of UserConfig isn't DbConfig")
	}

	db, err := sql.Open(config.DbType, config.DbURL)
	if err != nil {
		return nil, err
	}
	querySQL := "SELECT address, created_at, updated_at FROM online_users WHERE " +
		"(updated_at + interval '1 hour') > now() AND " +
		"EXISTS( SELECT * FROM users WHERE online_users.user_id = users.id AND username = ? )"
	queryUserIDSQL := "SELECT id FROM users WHERE username = ?"
	countSQL := "SELECT count(*) FROM online_users WHERE user_id = ?"
	insertSQL := "INSERT INTO online_users(user_id, address, created_at, updated_at) VALUES(?, ?, now(), now())"
	updateSQL := "UPDATE online_users SET address = ?, updated_at = now() WHERE user_id = ?"
	deleteSQL := "DELETE FROM online_users WHERE EXISTS(SELECT * FROM users WHERE online_users.user_id = users.id AND username = ?) AND address = ?"
	withAddress := false

	if config.Params != nil {
		if s, ok := stringWith(config.Params, "online.query", ""); !ok {
			return nil, errors.New("数据库配置中的 online.query 的值不是字符串")
		} else if s != "" {
			querySQL = s
		}

		if s, ok := stringWith(config.Params, "online.queryUser", ""); !ok {
			return nil, errors.New("数据库配置中的 online.queryUser 的值不是字符串")
		} else if s != "" {
			queryUserIDSQL = s
		}

		if s, ok := stringWith(config.Params, "online.count", ""); !ok {
			return nil, errors.New("数据库配置中的 online.count 的值不是字符串")
		} else if s != "" {
			countSQL = s
		}

		if s, ok := stringWith(config.Params, "online.insert", ""); !ok {
			return nil, errors.New("数据库配置中的 online.insert 的值不是字符串")
		} else if s != "" {
			insertSQL = s
		}

		if s, ok := stringWith(config.Params, "online.update", ""); !ok {
			return nil, errors.New("数据库配置中的 online.update 的值不是字符串")
		} else if s != "" {
			updateSQL = s
		}

		if s, ok := stringWith(config.Params, "online.delete", ""); !ok {
			return nil, errors.New("数据库配置中的 online.delete 的值不是字符串")
		} else if s != "" {
			deleteSQL = s
		}

		if s, ok := stringWith(config.Params, "online.withAddress", "false"); !ok {
			return nil, errors.New("数据库配置中的 online.withAddress 的值不是字符串")
		} else if s == "true" {
			withAddress = true
		}
	}

	if config.DbType == "postgres" || config.DbType == "postgresql" {
		querySQL = ReplacePlaceholders(querySQL)
		queryUserIDSQL = ReplacePlaceholders(queryUserIDSQL)
		countSQL = ReplacePlaceholders(countSQL)
		insertSQL = ReplacePlaceholders(insertSQL)
		updateSQL = ReplacePlaceholders(updateSQL)
		deleteSQL = ReplacePlaceholders(deleteSQL)
	}

	return &dbOnline{
		db:             db,
		querySQL:       querySQL,
		queryUserIDSQL: queryUserIDSQL,
		countSQL:       countSQL,
		insertSQL:      insertSQL,
		updateSQL:      updateSQL,
		deleteSQL:      deleteSQL,
		withAddress:    withAddress,
	}, nil
}

// NullTime represents a time.Time that may be null. NullTime implements the
// sql.Scanner interface so it can be used as a scan destination, similar to
// sql.NullString.
type NullTime struct {
	Time  time.Time
	Valid bool // Valid is true if Time is not NULL
}

// Scan implements the Scanner interface.
func (nt *NullTime) Scan(value interface{}) error {
	switch s := value.(type) {
	case time.Time:
		nt.Time = s
		nt.Valid = true
		return nil
	case string:
		return nt.Parse(s)
	case []byte:
		return nt.Parse(string(s))
	default:
		return errors.New("unknow value - " + fmt.Sprintf("%T %s", value, value))
	}
}

func (nt NullTime) Parse(s string) error {
	for _, layout := range []string{} {
		t, err := time.Parse(layout, s)
		if err == nil {
			nt.Time = t
			nt.Valid = true
			return nil
		}
	}
	return errors.New("unknow value - " + s)
}

// Value implements the driver Valuer interface.
func (nt NullTime) Value() (driver.Value, error) {
	if !nt.Valid {
		return nil, nil
	}
	return nt.Time, nil
}

func stringWith(params map[string]interface{}, key, defaultValue string) (string, bool) {
	o, ok := params[key]
	if !ok || o == nil {
		return defaultValue, true
	}

	s, ok := o.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultValue, true
	}
	return s, true
}
