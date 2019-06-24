package users

import (
	"context"
	"sync"

	"github.com/runner-mei/log"
)

type failCounterWrapper struct {
	logger            log.Logger
	inner             UserManager
	failCounter       FailCounter
	maxLoginFailCount int
}

func (fcw *failCounterWrapper) Read(loginInfo *LoginInfo) (Authentication, error) {
	return fcw.inner.Read(loginInfo)
}

func (fcw *failCounterWrapper) Lock(username string) error {
	return fcw.inner.Lock(username)
}

func (fcw *failCounterWrapper) Unlock(username string) error {
	err := fcw.inner.Unlock(username)
	if err == nil {
		fcw.failCounter.Zero(username)
	}
	return err
}

func (fcw *failCounterWrapper) Locked() ([]LockedUser, error) {
	return fcw.inner.Locked()
}

func (fcw *failCounterWrapper) FailCount(username string) int {
	return fcw.failCounter.Count(username)
}

func (fcw *failCounterWrapper) Auth(ctx context.Context, auth Authentication, loginInfo *LoginInfo) (*UserInfo, error) {
	userInfo, err := fcw.inner.Auth(ctx, auth, loginInfo)
	if err == nil {
		fcw.failCounter.Zero(loginInfo.Username)
	} else {
		if err == ErrPasswordNotMatch {
			fcw.lockUserIfNeed(loginInfo)
		}
	}
	return userInfo, err
}

func (fcw *failCounterWrapper) lockUserIfNeed(loginInfo *LoginInfo) {
	fcw.failCounter.Fail(loginInfo.Username)
	var failCount = fcw.failCounter.Count(loginInfo.Username)
	if failCount > fcw.maxLoginFailCount && "admin" != loginInfo.Username {
		if err := fcw.inner.Lock(loginInfo.Username); err != nil {
			fcw.logger.Info("lock user fail", log.String("username", loginInfo.Username), log.Error(err))
		}
	}
}

type FailCounter interface {
	Users() []string
	Fail(username string)
	Count(username string) int
	Zero(username string)
}

type memFailCounter struct {
	lock  sync.Mutex
	users map[string]int
}

func (mem *memFailCounter) Zero(username string) {
	mem.lock.Lock()
	defer mem.lock.Unlock()
	delete(mem.users, username)
}

func (mem *memFailCounter) Fail(username string) {
	mem.lock.Lock()
	defer mem.lock.Unlock()
	count := mem.users[username]
	count++
	mem.users[username] = count
}

func (mem *memFailCounter) Count(username string) int {
	mem.lock.Lock()
	defer mem.lock.Unlock()
	return mem.users[username]
}

func (mem *memFailCounter) Users() []string {
	mem.lock.Lock()
	defer mem.lock.Unlock()
	users := make([]string, 0, len(mem.users))
	for k := range mem.users {
		users = append(users, k)
	}
	return users
}

var createFailCounter = func() FailCounter {
	return &memFailCounter{users: map[string]int{}}
}

func FailCounterWrap(um UserManager, maxLoginFailCount int, logger log.Logger) UserManager {
	if maxLoginFailCount <= 0 {
		maxLoginFailCount = 3
	}

	return &failCounterWrapper{
		logger:            logger,
		inner:             um,
		failCounter:       createFailCounter(),
		maxLoginFailCount: maxLoginFailCount,
	}
}
