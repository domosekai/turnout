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

func (e *routeEntry) saveNew(route, server int) {
	e.route = route
	e.server = server
	e.count = 1
	e.mu.Unlock()
}

func (t *routingTable) del(dest, host string, delay bool, total int) {
	var key string
	if host != "" {
		key = host
	} else {
		key = dest
	}
	if delay {
		time.Sleep(time.Second * 10)
	}
	t.mu.Lock()
	entry := t.table[key]
	if entry == nil {
		logger.Printf("%d: Error: entry is nil for %s %s", total, dest, host)
		t.mu.Unlock()
		return
	}
	entry.mu.Lock()
	// Always minus 1 so that other process can know the entry obtained is zombie
	entry.count--
	if entry.count == 0 {
		delete(t.table, key)
	}
	entry.mu.Unlock()
	t.mu.Unlock()
}

func (t *routingTable) addOrNew(dest, host string) (route, server int, matched bool, newEntry *routeEntry) {
	var key string
	if host != "" {
		key = host
	} else {
		key = dest
	}
	for {
		t.mu.Lock()
		if entry := t.table[key]; entry == nil {
			// Lock new entry until route is confirmed, releasing table lock
			newEntry = new(routeEntry)
			newEntry.mu.Lock()
			t.table[key] = newEntry
			t.mu.Unlock()
			return
		} else {
			t.mu.Unlock()
			entry.mu.Lock()
			if entry.count == 0 {
				// zombie entry
				entry.mu.Unlock()
				continue
			}
			entry.count++
			logger.Printf("Route %s %s increased to %d", dest, host, entry.count)
			route = entry.route
			server = entry.server
			entry.mu.Unlock()
			matched = true
			return
		}
	}
	return
}

func (t *routingTable) unlockAndDel(dest, host string, newEntry *routeEntry) {
	var key string
	if host != "" {
		key = host
	} else {
		key = dest
	}
	t.mu.Lock()
	delete(t.table, key)
	newEntry.mu.Unlock()
	t.mu.Unlock()
}
