package main

import (
	"net"
	"strings"
	"sync"
	"time"
)

type ipSetEntry struct {
	addr net.IP
	time time.Time
}

type ipSet struct {
	list    []ipSetEntry
	timeout time.Duration
	rw      sync.RWMutex
}

type hostSetEntry struct {
	addr string
	time time.Time
}

type hostSet struct {
	list    []hostSetEntry
	timeout time.Duration
	rw      sync.RWMutex
}

type routeEntry struct {
	route  int
	server int
	count  int
	failed int
	mu     sync.Mutex
}

type routingTable struct {
	table map[string]*routeEntry
	mu    sync.Mutex // for adding / removing entries only, use entry-level locks to edit entries
}

func (set *ipSet) add(ip net.IP) {
	set.rw.Lock()
	set.list = append(set.list, ipSetEntry{ip, time.Now()})
	set.rw.Unlock()
}

func (set *ipSet) contain(ip net.IP) bool {
	set.rw.Lock()
	defer set.rw.Unlock()
	for i := len(set.list) - 1; i >= 0; i-- {
		if dur := time.Since(set.list[i].time); dur.Minutes() < -1 || dur > set.timeout {
			set.list = set.list[i+1:]
			return false
		} else if set.list[i].addr.Equal(ip) {
			return true
		}
	}
	return false
}

func (set *hostSet) add(host string) {
	if host == "" {
		return
	}
	set.rw.Lock()
	set.list = append(set.list, hostSetEntry{strings.ToLower(host), time.Now()})
	set.rw.Unlock()
}

func (set *hostSet) contain(host string) bool {
	set.rw.Lock()
	defer set.rw.Unlock()
	lower := strings.ToLower(host)
	for i := len(set.list) - 1; i >= 0; i-- {
		if dur := time.Since(set.list[i].time); dur.Minutes() < -1 || dur > set.timeout {
			set.list = set.list[i+1:]
			return false
		} else if set.list[i].addr == lower {
			return true
		}
	}
	return false
}

// Unlock and save or update new route
func (e *routeEntry) update(route, server int) {
	e.route = route
	e.server = server
	e.count++
	e.failed = 0
	e.mu.Unlock()
}

// Reset failed count on existing route
func (e *routeEntry) refresh(route, server int) {
	e.mu.Lock()
	if e.route == route && e.server == server {
		e.failed = 0
	}
	e.mu.Unlock()
}

func (t *routingTable) del(key string, delay bool, failedRoute, failedServer int) {
	// Suppose usual reconnect interval is 3-5 seconds, then the delay should be less
	if delay {
		time.Sleep(time.Second * 2)
	}
	// map lookup must be wrapped by locks as map does not allow concurrent read and write, even though the result can't be nil
	t.mu.Lock()
	entry := t.table[key]
	t.mu.Unlock()
	// This line may block
	entry.mu.Lock()
	// Always minus 1 so that other process can know the entry obtained is zombie
	entry.count--
	if entry.route == failedRoute && entry.server == failedServer {
		entry.failed++
	}
	if entry.count == 0 {
		t.mu.Lock()
		delete(t.table, key)
		t.mu.Unlock()
	}
	entry.mu.Unlock()
}

// Note: The only things allowed without locking the table is adding count or updating route
func (t *routingTable) addOrLock(key string) (route, server int, exist bool, entry *routeEntry) {
	for {
		t.mu.Lock()
		if entry = t.table[key]; entry == nil || entry.failed >= 2 {
			// Lock entry until route is updated
			if entry == nil {
				entry = new(routeEntry)
				entry.mu.Lock()
				t.table[key] = entry
				t.mu.Unlock()
			} else {
				t.mu.Unlock()
				// Next line may block
				entry.mu.Lock()
				// By this time entry could be already deleted or changed
				if entry.count == 0 || entry.failed < 2 {
					entry.mu.Unlock()
					continue
				}
			}
			return
		} else {
			t.mu.Unlock()
			// Locking entry may block, so unlock table first
			entry.mu.Lock()
			// But this may result in locking a deleted entry, so check if it's zombie
			if entry.count == 0 || entry.failed >= 2 {
				entry.mu.Unlock()
				continue
			}
			entry.count++
			route = entry.route
			server = entry.server
			entry.mu.Unlock()
			exist = true
			return
		}
	}
}

// Unlock as new route cannot be found
func (t *routingTable) unlock(key string, entry *routeEntry) {
	if entry.count == 0 {
		t.mu.Lock()
		delete(t.table, key)
		t.mu.Unlock()
	}
	entry.mu.Unlock()
}
