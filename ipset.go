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
