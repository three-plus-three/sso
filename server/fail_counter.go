package server

import (
	"sync"
)

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
