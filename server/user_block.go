package server

import (
	"sync"
)

type UserLocks interface {
	Users() []string
	Fail(username string)
	Count(username string) int
	Zero(username string)
}

type memLocks struct {
	lock  sync.Mutex
	users map[string]int
}

func (mem *memLocks) Zero(username string) {
	mem.lock.Lock()
	defer mem.lock.Unlock()
	delete(mem.users, username)
}

func (mem *memLocks) Fail(username string) {
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

func (mem *memLocks) Users() []string {
	mem.lock.Lock()
	defer mem.lock.Unlock()
	users := make([]string, 0, len(mem.users))
	for k := range mem.users {
		users = append(users, k)
	}
	return users
}

var CreateUserLocks = func() UserLocks {
	return &memLocks{users: map[string]int{}}
}
