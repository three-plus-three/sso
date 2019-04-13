package users

import (
	"log"
	"sync"
)

type failCounterWrapper struct {
	logger            *log.Logger
	inner             UserManager
	failCounter       FailCounter
	maxLoginFailCount int
}

func (fcw *failCounterWrapper) Read(username string) (User, error) {
	return fcw.inner.Read(username)
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

func (fcw *failCounterWrapper) Auth(auth User, userinfo *UserInfo) error {
	err := auth.Auth(userinfo)
	if err == nil {
		fcw.failCounter.Zero(userinfo.Username)
	} else {
		if err == ErrPasswordNotMatch {
			fcw.lockUserIfNeed(userinfo)
		}
	}
	return err
}

func (fcw *failCounterWrapper) lockUserIfNeed(userinfo *UserInfo) {
	fcw.failCounter.Fail(userinfo.Username)
	var failCount = fcw.failCounter.Count(userinfo.Username)
	if failCount > fcw.maxLoginFailCount && "admin" != userinfo.Username {
		if err := fcw.inner.Lock(userinfo.Username); err != nil {
			fcw.logger.Println("lock", userinfo.Username, "fail,", err)
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

func FailCounterWrap(um UserManager, maxLoginFailCount int, logger *log.Logger) UserManager {
	return &failCounterWrapper{
		logger:            logger,
		inner:             um,
		failCounter:       createFailCounter(),
		maxLoginFailCount: maxLoginFailCount,
	}
}
