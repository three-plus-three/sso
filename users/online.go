package users

import (
	"database/sql"
	"errors"
	"log"
	"strings"
	"time"
)

type SessionInfo struct {
	ID        int64
	UUID      string
	UserID    string
	Username  string
	Nickname  string
	Address   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Sessions interface {
	Login(userid int64, loginInfo *LoginInfo) (string, error)
	Logout(key string) error

	Query(username string) ([]SessionInfo, error)
}

type dbOnline struct {
	db        *sql.DB
	querySQL  string
	insertSQL string
	deleteSQL string
}

func (do *dbOnline) Query(username string) ([]SessionInfo, error) {
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

	var onlineList = make([]SessionInfo, 0, 1)
	for rows.Next() {
		var info SessionInfo
		var addr sql.NullString
		var createdAt NullTime
		var updatedAt NullTime

		if err := rows.Scan(&info.ID, &info.UUID,
			&info.UserID, &info.Username, &info.Nickname,
			&addr, &createdAt, &updatedAt); err != nil {
			return nil, err
		}

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

func (do *dbOnline) Login(userid int64, loginInfo *LoginInfo) (string, error) {
	uuid := GenerateID()
	_, err := do.db.Exec(do.insertSQL, userid, uuid, loginInfo.Address)
	if err != nil {
		return "", err
	}
	return uuid, nil
}

func (do *dbOnline) Logout(key string) error {
	_, err := do.db.Exec(do.deleteSQL, key)
	return err
}

func CreateDbSession(db *sql.DB, config *DbConfig) (Sessions, error) {
	querySQL := "SELECT ou.uuid, ou.user_id, users.username, users.username, ou.address, ou.created_at, ou.updated_at " +
		"FROM online_users ou join users on ou.user_id = users.id WHERE " +
		"(ou.updated_at + interval '1 hour') > now() AND users.username = ?"
	insertSQL := "INSERT INTO online_users(uuid, user_id, address, created_at, updated_at) VALUES(?, ?, ?, now(), now())"
	deleteSQL := "DELETE FROM online_users WHERE uuid = ?"

	if config.Params != nil {
		if s, ok := stringWith(config.Params, "online.query", ""); !ok {
			return nil, errors.New("数据库配置中的 online.query 的值不是字符串")
		} else if s != "" {
			querySQL = s
		}

		if s, ok := stringWith(config.Params, "online.insert", ""); !ok {
			return nil, errors.New("数据库配置中的 online.insert 的值不是字符串")
		} else if s != "" {
			insertSQL = s
		}

		if s, ok := stringWith(config.Params, "online.delete", ""); !ok {
			return nil, errors.New("数据库配置中的 online.delete 的值不是字符串")
		} else if s != "" {
			deleteSQL = s
		}
	}

	if config.DbType == "postgres" || config.DbType == "postgresql" {
		querySQL = ReplacePlaceholders(querySQL)
		insertSQL = ReplacePlaceholders(insertSQL)
		deleteSQL = ReplacePlaceholders(deleteSQL)
	}

	return &dbOnline{
		db:        db,
		querySQL:  querySQL,
		insertSQL: insertSQL,
		deleteSQL: deleteSQL,
	}, nil
}

type onlineWrapper struct {
	logger        *log.Logger
	inner         UserManager
	online        Sessions
	loginConflict string
}

func (ow *onlineWrapper) Read(loginInfo *LoginInfo) (Authentication, error) {
	var isForce = loginInfo.IsForce()
	switch ow.loginConflict {
	case "force":
		isForce = true
	case "", "auto":
	case "disableForce":
		isForce = false
	default:
	}

	if !isForce && loginInfo.Address != "127.0.0.1" {
		// 判断用户是不是已经在其它主机上登录
		if onlineList, err := ow.online.Query(loginInfo.Username); err != nil {
			return nil, err
		} else if len(onlineList) != 0 {
			found := false
			for _, ol := range onlineList {
				if ol.Address == loginInfo.Address {
					found = true
					break
				}
			}
			if found {
				return nil, &ErrOnline{onlineList: onlineList}
			}
		}
	}

	return ow.inner.Read(loginInfo)
}

func (ow *onlineWrapper) Lock(username string) error {
	return ow.inner.Lock(username)
}

func (ow *onlineWrapper) Unlock(username string) error {
	return ow.inner.Unlock(username)
}

func (ow *onlineWrapper) Locked() ([]LockedUser, error) {
	return ow.inner.Locked()
}

func (ow *onlineWrapper) FailCount(username string) int {
	return ow.inner.FailCount(username)
}

func (ow *onlineWrapper) Auth(auth Authentication, loginInfo *LoginInfo) (*UserInfo, error) {
	return ow.inner.Auth(auth, loginInfo)
}

func OnlineWrap(um UserManager, online Sessions, loginConflict string, logger *log.Logger) UserManager {
	if online == nil {
		return um
	}
	return &onlineWrapper{
		logger:        logger,
		inner:         um,
		online:        online,
		loginConflict: loginConflict,
	}
}