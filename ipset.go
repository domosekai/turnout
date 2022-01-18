package main

import (
	"net"
	"strings"
	"sync"
	"time"
)

type ipSetEntry struct {
	addr    net.IP
	port    string
	time    time.Time
	enabled bool
}

type ipSet struct {
	list    []ipSetEntry
	timeout time.Duration
	rw      sync.RWMutex
}

type hostSetEntry struct {
	addr    string
	port    string
	time    time.Time
	enabled bool
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
	count int
	mu    sync.Mutex // for adding / removing entries only, use entry-level locks to edit entries
}

func (set *ipSet) add(ip net.IP, port string) {
	set.rw.Lock()
	set.list = append(set.list, ipSetEntry{ip, port, time.Now(), true})
	set.rw.Unlock()
}

func (set *ipSet) find(ip net.IP, port string, del bool) bool {
	set.rw.Lock()
	defer set.rw.Unlock()
	for i := len(set.list) - 1; i >= 0; i-- {
		if dur := time.Since(set.list[i].time); dur.Minutes() < -1 || dur > set.timeout {
			set.list = set.list[i+1:]
			return false
		} else if set.list[i].addr.Equal(ip) && (set.list[i].port == "" || set.list[i].port == port) {
			if !del && set.list[i].enabled {
				return true
			}
			if del && set.list[i].enabled {
				set.list[i].enabled = false
			}
		}
	}
	return false
}

func (set *ipSet) clear() {
	set.rw.Lock()
	set.list = nil
	set.rw.Unlock()
}

func (set *hostSet) add(host, port string) {
	if host == "" {
		return
	}
	set.rw.Lock()
	set.list = append(set.list, hostSetEntry{strings.ToLower(host), port, time.Now(), true})
	set.rw.Unlock()
}

func (set *hostSet) find(host, port string, del bool) bool {
	set.rw.Lock()
	defer set.rw.Unlock()
	lower := strings.ToLower(host)
	for i := len(set.list) - 1; i >= 0; i-- {
		if dur := time.Since(set.list[i].time); dur.Minutes() < -1 || dur > set.timeout {
			set.list = set.list[i+1:]
			return false
		} else if set.list[i].addr == lower && (set.list[i].port == "" || set.list[i].port == port) {
			if !del && set.list[i].enabled {
				return true
			}
			if del && set.list[i].enabled {
				set.list[i].enabled = false
			}
		}
	}
	return false
}

func (set *hostSet) clear() {
	set.rw.Lock()
	set.list = nil
	set.rw.Unlock()
}

// Unlock and save or update new route
func (e *routeEntry) save(route, server int) {
	e.route = route
	e.server = server
	e.count++
	e.failed = 0
	e.mu.Unlock()
}

// Reset failed count on existing route
func (e *routeEntry) reset(route, server int) (ok bool) {
	e.mu.Lock()
	// By this time existing route can be changed
	if e.route == route && e.server == server {
		e.failed = 0
		ok = true
	} else {
		ok = false
	}
	e.mu.Unlock()
	return
}

func (t *routingTable) del(key string, delay bool, failedRoute, failedServer int) {
	// This delay should be longer than reasonable reconnection interval to prevent breakage
	if delay {
		time.Sleep(time.Second * 30)
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
		t.count--
		t.mu.Unlock()
	}
	entry.mu.Unlock()
}

// Note: The only things allowed without locking the table is adding count or updating route
func (t *routingTable) addOrLock(key string, matched int) (route, server int, exist bool, entry *routeEntry) {
	for {
		t.mu.Lock()
		if entry = t.table[key]; entry == nil || entry.failed >= 2 || (matched != 0 && entry.route != matched) {
			// Lock entry until route is updated
			if entry == nil {
				entry = new(routeEntry)
				entry.mu.Lock()
				t.table[key] = entry
				t.count++
				t.mu.Unlock()
			} else {
				t.mu.Unlock()
				// Next line may block
				entry.mu.Lock()
				// By this time entry could be already deleted or changed
				if entry.count == 0 || entry.failed < 2 && (matched == 0 || entry.route == matched) {
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
			if entry.count == 0 || entry.failed >= 2 || (matched != 0 && entry.route != matched) {
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
		t.count--
		t.mu.Unlock()
	}
	entry.mu.Unlock()
}
