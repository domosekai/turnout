// Released under MIT License
// Copyright (c) 2020 domosekai

// Custom routing rules

package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type ipRule struct {
	ipnet6 net.IPNet
	route  int
}

type ipRuleList struct {
	rules     []ipRule
	elseRoute int
	rw        sync.RWMutex
}

type hostRule struct {
	exact  string
	left   string
	middle string
	right  string
	domain string
	any    bool
	route  int
}

type hostRuleList struct {
	rules []hostRule
	rw    sync.RWMutex
}

var (
	ipRules   ipRuleList
	hostRules hostRuleList
	httpRules hostRuleList
)

type byByte []ipRule

func (n byByte) Len() int { return len(n) }
func (n byByte) Less(i, j int) bool {
	for b := 0; b < net.IPv6len; b++ {
		if n[i].ipnet6.IP[b] < n[j].ipnet6.IP[b] {
			return true
		} else if n[i].ipnet6.IP[b] > n[j].ipnet6.IP[b] {
			return false
		}
	}
	return false
}
func (n byByte) Swap(i, j int) { n[i], n[j] = n[j], n[i] }

func (list *ipRuleList) parseIPList(file string) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	list.rw.Lock()
	defer list.rw.Unlock()
	list.rules = nil
	list.elseRoute = 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		r := strings.Split(scanner.Text(), " ")
		if len(r) < 2 {
			continue
		}
		route, err := strconv.Atoi(r[0])
		if err != nil {
			continue
		}
		var ipstr string
		if r[1] == "ELSE" {
			list.elseRoute = route
			continue
		}
		if !strings.Contains(r[1], "/") {
			// Not CIDR
			if strings.Contains(r[1], ":") {
				ipstr = r[1] + "/128"
			} else {
				ipstr = r[1] + "/32"
			}
		} else {
			// CIDR
			ipstr = r[1]
		}
		// ParseCIDR returns 16-byte net.IP and 4 or 16-byte net.IPNet (both IP and Mask)
		if _, ipnet, err := net.ParseCIDR(ipstr); err != nil {
			log.Fatalf("Invalid IP rule: %s", scanner.Text())
		} else {
			switch len(ipnet.Mask) {
			case net.IPv4len:
				list.rules = append(list.rules, ipRule{net.IPNet{IP: ipnet.IP.To16(), Mask: mark4to6(ipnet.Mask)}, route})
			case net.IPv6len:
				list.rules = append(list.rules, ipRule{*ipnet, route})
			}
		}
	}
}

func (list *hostRuleList) parseHostList(file string) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	list.rw.Lock()
	defer list.rw.Unlock()
	list.rules = nil
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		r := strings.Split(scanner.Text(), " ")
		if len(r) < 2 {
			continue
		}
		route, err := strconv.Atoi(r[0])
		if err != nil {
			continue
		}
		if r[1] == "*" {
			list.rules = append(list.rules, hostRule{any: true, route: route})
			continue
		}
		if strings.HasPrefix(r[1], "\"") && strings.HasSuffix(r[1], "\"") {
			d := strings.TrimSuffix(strings.TrimPrefix(r[1], "\""), "\"")
			if d != "" {
				list.rules = append(list.rules, hostRule{exact: strings.ToLower(d), route: route})
			}
			continue
		}
		if strings.Contains(r[1], "**") {
			log.Fatalf("Invalid host rule: %s", scanner.Text())
		}
		b1 := strings.HasPrefix(r[1], "*")
		b2 := strings.HasSuffix(r[1], "*")
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(r[1], "*"), "*"), "*")
		switch len(parts) {
		case 1:
			if b1 && b2 {
				list.rules = append(list.rules, hostRule{middle: strings.ToLower(parts[0]), route: route})
			} else if b1 && !b2 {
				list.rules = append(list.rules, hostRule{right: strings.ToLower(parts[0]), route: route})
			} else if !b1 && b2 {
				list.rules = append(list.rules, hostRule{left: strings.ToLower(parts[0]), route: route})
			} else {
				// Treat as dnsmasq-style domain if no wildcard
				list.rules = append(list.rules, hostRule{domain: strings.ToLower(parts[0]), route: route})
			}
		case 2:
			if b1 && !b2 {
				list.rules = append(list.rules, hostRule{middle: strings.ToLower(parts[0]), right: strings.ToLower(parts[1]), route: route})
			} else if !b1 && b2 {
				list.rules = append(list.rules, hostRule{left: strings.ToLower(parts[0]), middle: strings.ToLower(parts[1]), route: route})
			} else if !b1 && !b2 {
				list.rules = append(list.rules, hostRule{left: strings.ToLower(parts[0]), right: strings.ToLower(parts[1]), route: route})
			}
		case 3:
			if !b1 && !b2 {
				list.rules = append(list.rules, hostRule{left: strings.ToLower(parts[0]), middle: strings.ToLower(parts[1]), right: strings.ToLower(parts[2]), route: route})
			}
		default:
			log.Fatalf("Invalid host rule: %s", scanner.Text())
		}
	}
}

func (list *hostRuleList) parseHTTPRules(str string) {
	list.rw.Lock()
	defer list.rw.Unlock()
	list.rules = nil
	for _, s := range strings.Split(str, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if s == "*" {
			list.rules = append(list.rules, hostRule{any: true, route: 2})
			continue
		}
		if strings.Contains(s, "**") {
			continue
		}
		b1 := strings.HasPrefix(s, "*")
		b2 := strings.HasSuffix(s, "*")
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(s, "*"), "*"), "*")
		switch len(parts) {
		case 1:
			if b1 && b2 {
				list.rules = append(list.rules, hostRule{middle: strings.ToLower(parts[0]), route: 2})
			} else if b1 && !b2 {
				list.rules = append(list.rules, hostRule{right: strings.ToLower(parts[0]), route: 2})
			} else {
				// Assume no asterisk as left match
				list.rules = append(list.rules, hostRule{left: strings.ToLower(parts[0]), route: 2})
			}
		case 2:
			if b1 && !b2 {
				list.rules = append(list.rules, hostRule{middle: strings.ToLower(parts[0]), right: strings.ToLower(parts[1]), route: 2})
			} else if !b1 && b2 {
				list.rules = append(list.rules, hostRule{left: strings.ToLower(parts[0]), middle: strings.ToLower(parts[1]), route: 2})
			} else if !b1 && !b2 {
				list.rules = append(list.rules, hostRule{left: strings.ToLower(parts[0]), right: strings.ToLower(parts[1]), route: 2})
			}
		case 3:
			if !b1 && !b2 {
				list.rules = append(list.rules, hostRule{left: strings.ToLower(parts[0]), middle: strings.ToLower(parts[1]), right: strings.ToLower(parts[2]), route: 2})
			}
		default:
			log.Fatalf("Invalid HTTP rule: %s", s)
		}
	}
}

func mark4to6(mark net.IPMask) net.IPMask {
	var prefix = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	p := make(net.IPMask, net.IPv6len)
	copy(p, prefix)
	p[12] = mark[0]
	p[13] = mark[1]
	p[14] = mark[2]
	p[15] = mark[3]
	return p
}

func cmpIPIPNet6(ip net.IP, ipnet net.IPNet) int { // based on net.Contains()
	for i := 0; i < net.IPv6len; i++ {
		if a, b := ip[i]&ipnet.Mask[i], ipnet.IP[i]&ipnet.Mask[i]; a < b {
			return -1
		} else if a > b {
			return 1
		}
	}
	return 0
}

func (list *ipRuleList) findRouteForIP(ip net.IP) int { // based on sort.Search()
	list.rw.RLock()
	defer list.rw.RUnlock()
	for i, j := 0, len(list.rules); i < j; {
		switch k := int(uint(i+j) >> 1); cmpIPIPNet6(ip.To16(), list.rules[k].ipnet6) { // i <= k < j
		case -1:
			j = k
		case 0:
			return list.rules[k].route
		case 1:
			i = k + 1
		}
	}
	if list.elseRoute != 0 {
		return list.elseRoute
	}
	return 0
}

func (list *hostRuleList) findRouteForText(text string, ignoreCase bool) int {
	list.rw.RLock()
	defer list.rw.RUnlock()
	if ignoreCase {
		text = strings.ToLower(text)
	}
	for _, v := range list.rules {
		if v.any {
			return v.route
		}
		if v.exact != "" {
			if v.exact == text {
				return v.route
			}
			continue
		}
		if v.domain != "" {
			if text == v.domain || strings.HasSuffix(text, "."+v.domain) {
				return v.route
			}
			continue
		}
		h := text
		if v.left != "" {
			if strings.HasPrefix(h, v.left) {
				h = strings.TrimPrefix(h, v.left)
			} else {
				continue
			}
		}
		if v.right != "" {
			if strings.HasSuffix(h, v.right) {
				h = strings.TrimSuffix(h, v.right)
			} else {
				continue
			}
		}
		if v.middle != "" {
			if !strings.Contains(h, v.middle) {
				continue
			}
		}
		return v.route
	}
	return 0
}

func readIPRules(list *ipRuleList, file string) {
	list.parseIPList(file)
	list.rw.RLock()
	if list.rules != nil {
		logger.Printf("Loaded %d IP rules", len(list.rules))
		sort.Sort(byByte(list.rules))
	}
	if list.elseRoute != 0 {
		logger.Printf("Unmatched IPs will use route %d", list.elseRoute)
	}
	list.rw.RUnlock()
}

func readHostRules(list *hostRuleList, file string) {
	list.parseHostList(file)
	list.rw.RLock()
	if list.rules != nil {
		logger.Printf("Loaded %d host rules", len(list.rules))
	}
	list.rw.RUnlock()
}

func readHTTPRules(list *hostRuleList, str string) {
	list.parseHTTPRules(str)
	list.rw.RLock()
	if list.rules != nil {
		logger.Printf("Loaded %d HTTP rules", len(list.rules))
	}
	list.rw.RUnlock()
}
