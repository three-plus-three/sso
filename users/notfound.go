package users

import "log"

type notfoundWrapper struct {
	logger       *log.Logger
	inner        UserManager
	userNotFound UserNotFound
}

func (ow *notfoundWrapper) Read(userinfo *UserInfo) (User, error) {
	return ow.inner.Read(userinfo)
}

func (ow *notfoundWrapper) Lock(username string) error {
	return ow.inner.Lock(username)
}

func (ow *notfoundWrapper) Unlock(username string) error {
	return ow.inner.Unlock(username)
}

func (ow *notfoundWrapper) Locked() ([]LockedUser, error) {
	return ow.inner.Locked()
}

func (ow *notfoundWrapper) FailCount(username string) int {
	return ow.inner.FailCount(username)
}

func (ow *notfoundWrapper) Auth(auth User, userinfo *UserInfo) error {
	return ow.inner.Auth(auth, userinfo)
}

func NotfoundWrap(um UserManager, userNotFound UserNotFound, logger *log.Logger) UserManager {
	if online == nil {
		return um
	}
	return &notfoundWrapper{
		logger:       logger,
		inner:        um,
		userNotFound: userNotFound,
	}
}
