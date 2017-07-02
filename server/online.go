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
	db                *sql.DB
	querySQL          string
	queryUserIDSQL    string
	saveSQL           string
	deleteSQL         string
	deleteWithAddress bool
}

func (do *dbOnline) Query(username string) ([]OnlineInfo, error) {
	rows, err := do.db.Query(do.querySQL, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
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
		return err
	}
	_, err = do.db.Exec(do.saveSQL, userID, address)
	return nil
}

func (do *dbOnline) Delete(username, address string) error {
	var err error
	if do.deleteWithAddress {
		_, err = do.db.Exec(do.deleteSQL, username, address)
	} else {
		_, err = do.db.Exec(do.deleteSQL, username)
	}
	return err
}

func createDbOnline(params interface{}) (Online, error) {
	config, ok := params.(*DbConfig)
	if !ok {
		return nil, errors.New("arguments of UserConfig isn't DbConfig")
	}

	db, err := sql.Open(config.URL())
	if err != nil {
		return nil, err
	}
	querySQL := "SELECT address, created_at, updated_at FROM online_users WHERE " +
		"(updated_at + interval '1 hour') > now() AND " +
		"EXISTS( SELECT * FROM users WHERE online_users.user_id = users.id AND username = ? )"
	queryUserIDSQL := "SELECT id FROM users WHERE username = ?"
	saveSQL := "INSERT INTO online_users(user_id, address, created_at, updated_at) VALUES(?, ?, now(), now())"
	deleteSQL := "DELETE FROM online_users WHERE EXISTS(SELECT * FROM users WHERE online_users.user_id = users.id AND username = ?)"
	deleteWithAddress := false

	if config.Params != nil {
		if o, ok := config.Params["online.query"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 online.query 的值不是字符串")
			}
			if s = strings.TrimSpace(s); s != "" {
				querySQL = s
			}
		}

		if o, ok := config.Params["online.queryUser"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 online.queryUser 的值不是字符串")
			}
			if strings.TrimSpace(s) != "" {
				queryUserIDSQL = s
			}
		}

		if o, ok := config.Params["online.save"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 online.save 的值不是字符串")
			}
			if strings.TrimSpace(s) != "" {
				saveSQL = s
			}
		}

		if o, ok := config.Params["online.delete"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 online.delete 的值不是字符串")
			}
			if strings.TrimSpace(s) != "" {
				deleteSQL = s
			}
		}

		if o, ok := config.Params["online.withAddress"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 online.withAddress 的值不是字符串")
			}
			if strings.TrimSpace(s) != "true" {
				deleteWithAddress = true
			}
		}
	}

	if config.DbType == "postgres" || config.DbType == "postgresql" {
		querySQL = ReplacePlaceholders(querySQL)
		queryUserIDSQL = ReplacePlaceholders(queryUserIDSQL)
		saveSQL = ReplacePlaceholders(saveSQL)
		deleteSQL = ReplacePlaceholders(deleteSQL)
	}

	return &dbOnline{
		db:                db,
		querySQL:          querySQL,
		queryUserIDSQL:    queryUserIDSQL,
		saveSQL:           saveSQL,
		deleteSQL:         deleteSQL,
		deleteWithAddress: deleteWithAddress,
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
