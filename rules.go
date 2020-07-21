// Released under MIT License
// Copyright (c) 2020 domosekai

// Custom routing rules

package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

type ipRule struct {
	ipnet6 net.IPNet
	route  int
}

type hostRule struct {
	exact  string
	left   string
	middle string
	right  string
	any    bool
	route  int
}

var (
	ipRules   []ipRule
	hostRules []hostRule
	httpRules []hostRule
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

func parseIPList(file string) (rules []ipRule) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		r := strings.Split(scanner.Text(), " ")
		if len(r) < 2 {
			continue
		}
		route, err := strconv.Atoi(r[0])
		if err != nil || route == 0 {
			continue
		}
		var ipstr string
		if !strings.Contains(r[1], "/") {
			if strings.Contains(r[1], ":") {
				ipstr = r[1] + "/128"
			} else {
				ipstr = r[1] + "/32"
			}
		} else {
			ipstr = r[1]
		}
		// ParseCIDR returns 16-byte net.IP and 4 or 16-byte net.IPNet (both IP and Mask)
		if _, ipnet, err := net.ParseCIDR(ipstr); err != nil {
			log.Fatalf("Invalid IP rule: %s", scanner.Text())
		} else {
			switch len(ipnet.Mask) {
			case net.IPv4len:
				rules = append(rules, ipRule{net.IPNet{IP: ipnet.IP.To16(), Mask: mark4to6(ipnet.Mask)}, route})
			case net.IPv6len:
				rules = append(rules, ipRule{*ipnet, route})
			}
		}
	}
	return
}

func parseHostList(file string) (rules []hostRule) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		r := strings.Split(scanner.Text(), " ")
		if len(r) < 2 {
			continue
		}
		route, err := strconv.Atoi(r[0])
		if err != nil || route == 0 {
			continue
		}
		if r[1] == "*" {
			rules = append(rules, hostRule{any: true, route: route})
			continue
		}
		if strings.Contains(r[1], "**") {
			continue
		}
		b1 := strings.HasPrefix(r[1], "*")
		b2 := strings.HasSuffix(r[1], "*")
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(r[1], "*"), "*"), "*")
		switch len(parts) {
		case 1:
			if b1 && b2 {
				rules = append(rules, hostRule{middle: strings.ToLower(parts[0]), route: route})
			} else if b1 && !b2 {
				rules = append(rules, hostRule{right: strings.ToLower(parts[0]), route: route})
			} else if !b1 && b2 {
				rules = append(rules, hostRule{left: strings.ToLower(parts[0]), route: route})
			} else {
				rules = append(rules, hostRule{exact: strings.ToLower(parts[0]), route: route})
			}
		case 2:
			if b1 && !b2 {
				rules = append(rules, hostRule{middle: strings.ToLower(parts[0]), right: strings.ToLower(parts[1]), route: route})
			} else if !b1 && b2 {
				rules = append(rules, hostRule{left: strings.ToLower(parts[0]), middle: strings.ToLower(parts[1]), route: route})
			} else if !b1 && !b2 {
				rules = append(rules, hostRule{left: strings.ToLower(parts[0]), right: strings.ToLower(parts[1]), route: route})
			}
		case 3:
			if !b1 && !b2 {
				rules = append(rules, hostRule{left: strings.ToLower(parts[0]), middle: strings.ToLower(parts[1]), right: strings.ToLower(parts[2]), route: route})
			}
		default:
			log.Fatalf("Invalid host rule: %s", scanner.Text())
		}
	}
	return
}

func parseHTTPRules(str string) (rules []hostRule) {
	for _, s := range strings.Split(str, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if s == "*" {
			rules = append(rules, hostRule{any: true, route: 2})
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
				rules = append(rules, hostRule{middle: strings.ToLower(parts[0]), route: 2})
			} else if b1 && !b2 {
				rules = append(rules, hostRule{right: strings.ToLower(parts[0]), route: 2})
			} else {
				// Assume no asterisk as left match
				rules = append(rules, hostRule{left: strings.ToLower(parts[0]), route: 2})
			}
		case 2:
			if b1 && !b2 {
				rules = append(rules, hostRule{middle: strings.ToLower(parts[0]), right: strings.ToLower(parts[1]), route: 2})
			} else if !b1 && b2 {
				rules = append(rules, hostRule{left: strings.ToLower(parts[0]), middle: strings.ToLower(parts[1]), route: 2})
			} else if !b1 && !b2 {
				rules = append(rules, hostRule{left: strings.ToLower(parts[0]), right: strings.ToLower(parts[1]), route: 2})
			}
		case 3:
			if !b1 && !b2 {
				rules = append(rules, hostRule{left: strings.ToLower(parts[0]), middle: strings.ToLower(parts[1]), right: strings.ToLower(parts[2]), route: 2})
			}
		default:
			log.Fatalf("Invalid HTTP rule: %s", s)
		}
	}
	return
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

func findRouteForIP(ip net.IP, rules []ipRule) int { // based on sort.Search()
	if rules == nil {
		return 0
	}
	for i, j := 0, len(rules); i < j; {
		switch k := int(uint(i+j) >> 1); cmpIPIPNet6(ip.To16(), rules[k].ipnet6) { // i <= k < j
		case -1:
			j = k
		case 0:
			return rules[k].route
		case 1:
			i = k + 1
		}
	}
	return 0
}

func findRouteForText(text string, rules []hostRule, ignoreCase bool) int {
	if rules == nil {
		return 0
	}
	if ignoreCase {
		text = strings.ToLower(text)
	}
	for _, v := range rules {
		if v.any {
			return v.route
		}
		if v.exact != "" {
			if v.exact == text {
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
