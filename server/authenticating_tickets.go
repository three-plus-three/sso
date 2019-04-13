package server

import (
	"sync"
	"time"

	"github.com/three-plus-three/sso/users"
)

type authenticatingTicket struct {
	ID        string
	Service   string
	Ticket    *Ticket
	CreatedAt time.Time
}

type authenticatingTickets struct {
	timeout time.Duration
	mutex   sync.Mutex
	tickets map[string]*authenticatingTicket
}

func (at *authenticatingTickets) new(ticket *Ticket, service string) string {
	t := &authenticatingTicket{
		ID:        "ST-" + users.GenerateID(),
		Service:   service,
		Ticket:    ticket,
		CreatedAt: time.Now(),
	}

	at.mutex.Lock()
	at.tickets[t.ID] = t

	ticketCount := len(at.tickets)
	if ticketCount > 100 {
		at.removeExpiredWithLocked(time.Now(), at.timeout)
	} else if ticketCount > 5 {
		at.removeExpiredWithLocked(time.Now(), 5*time.Second)
	}
	at.mutex.Unlock()
	return t.ID
}

func (at *authenticatingTickets) fetchAndValidate(id string, service string) (*Ticket, error) {
	var t *authenticatingTicket
	at.mutex.Lock()
	t = at.tickets[id]
	if t == nil {
		at.mutex.Unlock()
		return nil, ErrServiceTicketNotFound
	}
	delete(at.tickets, id)
	at.mutex.Unlock()

	if t == nil {
		return nil, ErrServiceTicketNotFound
	}
	if time.Now().Sub(t.CreatedAt) > at.timeout {
		return nil, ErrServiceTicketExpired
	}
	if service != "" && t.Service == service {
		return nil, ErrUnauthorizedService
	}
	return t.Ticket, nil
}

func (at *authenticatingTickets) removeExpired() {
	now := time.Now()
	at.mutex.Lock()
	defer at.mutex.Unlock()
	at.removeExpiredWithLocked(now, at.timeout)
}

func (at *authenticatingTickets) removeExpiredWithLocked(now time.Time, timeout time.Duration) {
	var expiredList []string
	for id, t := range at.tickets {
		if now.Sub(t.CreatedAt) > timeout {
			expiredList = append(expiredList, id)
		}
	}

	for _, id := range expiredList {
		delete(at.tickets, id)
	}
}
