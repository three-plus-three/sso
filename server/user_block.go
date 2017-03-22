package server

import (
	"sync"
)

type UserLocks interface {
	FailOne(username string)
	Count(username string) int
}

type memLocks struct {
	lock  sync.Mutex
	users map[string]int
}

func (mem *memLocks) FailOne(username string) {
	mem.lock.Lock()
	defer mem.lock.Unlock()
	count := mem.users[username]
	count++
	mem.users[username] = count
}

func (mem *memLocks) Count(username string) int {
	mem.lock.Lock()
	defer mem.lock.Unlock()
	return mem.users[username]
}

var CreateUserLocks = func() UserLocks {
	return &memLocks{users: map[string]int{}}
}
