package users

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/runner-mei/log"
)

type SessionInfo struct {
	UUID      string
	UserID    interface{}
	Username  string
	Nickname  string
	Address   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Sessions interface {
	Login(userid interface{}, address, service string) (string, error)
	Logout(key string) error

	LogoutBy(userid interface{}, username string, address string) error

	Query(username string) ([]SessionInfo, error)
}

type EmptySessions struct{}

func (sess EmptySessions) Login(userid interface{}, address, service string) (string, error) {
	return "", nil
}
func (sess EmptySessions) Logout(key string) error {
	return nil
}

func (sess EmptySessions) LogoutBy(userid interface{}, username, address string) error {
	return nil
}

func (sess EmptySessions) Query(username string) ([]SessionInfo, error) {
	return nil, nil
}

type DbOnline struct {
	Db               *sql.DB
	querySQL         string
	queryByUserIDSQL string
	insertSQL        string
	deleteSQL        string
}

func (do *DbOnline) Query(username string) ([]SessionInfo, error) {
	rows, err := do.Db.Query(do.querySQL, username)
	if err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}

		rows, err = do.Db.Query(do.querySQL, strings.ToLower(username))
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		return nil, nil
	}
	defer rows.Close()

	return do.QueryRows(rows)
}

func (do *DbOnline) Read(info *SessionInfo, row interface {
	Scan(values ...interface{}) error
}) error {
	var userid int64
	var uuid sql.NullString
	var addr sql.NullString
	var createdAt NullTime
	var updatedAt NullTime

	if err := row.Scan(&uuid,
		&userid, &info.Username, &info.Nickname,
		&addr, &createdAt, &updatedAt); err != nil {
		return err
	}

	info.UserID = userid

	if uuid.Valid {
		info.UUID = uuid.String
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

	return nil
}

func (do *DbOnline) QueryRows(rows *sql.Rows) ([]SessionInfo, error) {
	var onlineList = make([]SessionInfo, 0, 1)
	for rows.Next() {
		var info SessionInfo
		if err := do.Read(&info, rows); err != nil {
			return nil, err
		}
		onlineList = append(onlineList, info)
	}
	return onlineList, nil
}

func (do *DbOnline) Login(userid interface{}, address, service string) (string, error) {
	if userid == nil {
		return "", errors.New("userid is missing")
	}
	rows, err := do.Db.Query(do.queryByUserIDSQL, userid)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	if rows != nil {
		defer rows.Close()
		sessionList, err := do.QueryRows(rows)
		if err != nil && err != sql.ErrNoRows {
			return "", err
		}

		foundIdx := -1
		for idx, ol := range sessionList {
			if ol.Address == address {
				foundIdx = idx
				break
			}
		}
		if foundIdx >= 0 {
			return sessionList[foundIdx].UUID, nil
		}
	}

	uuid := GenerateID()
	_, err = do.Db.Exec(do.insertSQL, userid, uuid, address)
	if err != nil {
		return "", err
	}
	return uuid, nil
}

func (do *DbOnline) Logout(key string) error {
	_, err := do.Db.Exec(do.deleteSQL, key)
	return err
}

func (do *DbOnline) LogoutBy(userid interface{}, username, address string) error {
	sessList, err := do.Query(username)
	if err != nil {
		return err
	}
	for _, sess := range sessList {
		if sess.Address == address {
			_, err = do.Db.Exec(do.deleteSQL, sess.UUID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func CreateDbSession(dbType string, db *sql.DB, params map[string]interface{}) (*DbOnline, error) {
	querySQL := "SELECT ou.uuid, ou.user_id, users.username, users.username, ou.address, ou.created_at, ou.updated_at " +
		"FROM online_users ou join users on ou.user_id = users.id WHERE " +
		"(ou.updated_at + interval '1 hour') > now() AND users.username = ?"
	queryByUserIDSQL := "SELECT ou.uuid, ou.user_id, users.username, users.username, ou.address, ou.created_at, ou.updated_at " +
		"FROM online_users ou join users on ou.user_id = users.id WHERE " +
		"(ou.updated_at + interval '1 hour') > now() AND users.id = ?"
	insertSQL := "INSERT INTO online_users(user_id, uuid, address, created_at, updated_at) VALUES(?, ?, ?, now(), now())"
	deleteSQL := "DELETE FROM online_users WHERE uuid = ?"

	if params != nil {
		if s, ok := stringWith(params, "online.query", ""); !ok {
			return nil, errors.New("数据库配置中的 online.query 的值不是字符串")
		} else if s != "" {
			querySQL = s
		}

		if s, ok := stringWith(params, "online.queryByUserID", ""); !ok {
			return nil, errors.New("数据库配置中的 online.queryByUserID 的值不是字符串")
		} else if s != "" {
			queryByUserIDSQL = s
		}

		if s, ok := stringWith(params, "online.insert", ""); !ok {
			return nil, errors.New("数据库配置中的 online.insert 的值不是字符串")
		} else if s != "" {
			insertSQL = s
		}

		if s, ok := stringWith(params, "online.delete", ""); !ok {
			return nil, errors.New("数据库配置中的 online.delete 的值不是字符串")
		} else if s != "" {
			deleteSQL = s
		}
	}

	if dbType == "postgres" || dbType == "postgresql" {
		querySQL = ReplacePlaceholders(querySQL)
		queryByUserIDSQL = ReplacePlaceholders(queryByUserIDSQL)
		insertSQL = ReplacePlaceholders(insertSQL)
		deleteSQL = ReplacePlaceholders(deleteSQL)
	}

	return &DbOnline{
		Db:               db,
		querySQL:         querySQL,
		queryByUserIDSQL: queryByUserIDSQL,
		insertSQL:        insertSQL,
		deleteSQL:        deleteSQL,
	}, nil
}

type onlineWrapper struct {
	logger        log.Logger
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
			if !found {
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

func (ow *onlineWrapper) Auth(ctx context.Context, auth Authentication, loginInfo *LoginInfo) (*UserInfo, error) {
	userinfo, err := ow.inner.Auth(ctx, auth, loginInfo)
	if err != nil {
		return userinfo, err
	}

	sessonID, err := ow.online.Login(userinfo.ID, loginInfo.Address, loginInfo.Service)
	if err != nil {
		return userinfo, err
	}
	userinfo.SessonID = sessonID
	return userinfo, err
}

func OnlineWrap(um UserManager, online Sessions, loginConflict string, logger log.Logger) (UserManager, error) {
	if online == nil {
		return um, nil
	}

	if loginConflict != "force" &&
		loginConflict != "" &&
		loginConflict != "auto" &&
		loginConflict != "disableForce" {
		return nil, errors.New("loginConflict is invalid - " + loginConflict)
	}

	return &onlineWrapper{
		logger:        logger,
		inner:         um,
		online:        online,
		loginConflict: loginConflict,
	}, nil
}
