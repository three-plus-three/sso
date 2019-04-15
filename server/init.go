package server

import (
	"database/sql"
	"errors"
	"log"

	"github.com/three-plus-three/sso/users"
)

var DefaultUserHandler = func(config *Config, logger *log.Logger) (UserManager, users.Sessions, error) {
	dbConfig, ok := config.UserConfig.(*DbConfig)
	if !ok {
		return nil, nil, errors.New("arguments of UserConfig isn't DbConfig")
	}

	db, err := sql.Open(dbConfig.DbType, dbConfig.DbURL)
	if err != nil {
		return nil, nil, err
	}

	noClose := false
	defer func() {
		if !noClose {
			db.Close()
		}
	}()

	params, _ := config.AuthConfig.(map[string]interface{})
	verify, err := users.ReadVerify(params)
	if err != nil {
		return nil, nil, err
	}

	userManager, err := users.DefaultUserManager(db, dbConfig, verify, config.ExternalVerify)
	if err != nil {
		return nil, nil, err
	}
	userManager = users.NotfoundWrap(userManager, config.UserNotFound, logger)

	online, err := users.CreateDbSession(db, dbConfig)
	if err != nil {
		return nil, nil, err
	}

	userManager = users.OnlineWrap(userManager, online, config.LoginConflict, logger)
	userManager = users.FailCounterWrap(userManager, config.MaxLoginFailCount, logger)
	userManager = users.CaptchaWrap(userManager, logger)
	noClose = true
	return userManager, online, nil
}
