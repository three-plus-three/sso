package users

import "log"

type SimpleAuthentication struct {
	IsNew    bool
	UserData map[string]interface{}
}

func (u *SimpleAuthentication) Auth(loginInfo *LoginInfo) (*UserInfo, error) {
	return &UserInfo{
		LoginInfo: *loginInfo,
		IsNew:     u.IsNew,
		Data:      u.UserData,
	}, nil
}

type notfoundWrapper struct {
	logger       *log.Logger
	inner        UserManager
	userNotFound UserNotFound
}

func (nfw *notfoundWrapper) Read(loginInfo *LoginInfo) (Authentication, error) {
	u, err := nfw.inner.Read(loginInfo)
	if nfw.userNotFound == nil {
		return u, err
	}

	if err != nil {
		if err != ErrUserNotFound {
			return nil, err
		}
	} else if u != nil {
		return u, nil
	}

	isNew, userData, err := nfw.userNotFound(loginInfo)
	if err != nil {
		return nil, err
	}
	return &SimpleAuthentication{IsNew: isNew, UserData: userData}, nil
}

func (nfw *notfoundWrapper) Lock(username string) error {
	return nfw.inner.Lock(username)
}

func (nfw *notfoundWrapper) Unlock(username string) error {
	return nfw.inner.Unlock(username)
}

func (nfw *notfoundWrapper) Locked() ([]LockedUser, error) {
	return nfw.inner.Locked()
}

func (nfw *notfoundWrapper) FailCount(username string) int {
	return nfw.inner.FailCount(username)
}

func (nfw *notfoundWrapper) Auth(auth Authentication, loginInfo *LoginInfo) (*UserInfo, error) {
	return nfw.inner.Auth(auth, loginInfo)
}

func NotfoundWrap(um UserManager, userNotFound UserNotFound, logger *log.Logger) UserManager {
	return &notfoundWrapper{
		logger:       logger,
		inner:        um,
		userNotFound: userNotFound,
	}
}
