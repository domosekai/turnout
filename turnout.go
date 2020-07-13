// Released under MIT License
// Copyright (c) 2020 domosekai

// Main program

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
)

var tranAddr = flag.String("b", "", "Listening address for transparent proxy (Linux only) (e.g. 0.0.0.0:2222, [::]:2222)")
var httpAddr = flag.String("h", "", "Listening address for HTTP proxy (e.g. 0.0.0.0:8080, [::]:8080)")
var socksAddr = flag.String("s", "", "SOCKS5 server address for route 2 (e.g. 127.0.0.1:1080, [::1]:1080)")

//var ifname2 = flag.String("if", "", "Network interface for secondary route (e.g. eth1, wlan1)")
//var dns2Addr = flag.String("dns", "8.8.8.8:53", "DNS nameserver for the secondary interface (no need for SOCKS) (e.g. 8.8.8.8)")
var tproxy = flag.Bool("t", false, "Use TPROXY mode in addition to REDIRECT mode for transparent proxy (Linux only)")
var hostFile = flag.String("host", "", "File containing custom rules based on hostnames.")
var ipFile = flag.String("ip", "", "File containing custom rules based on IP/CIDRs. Use with caution as DNS results can be bogus.")
var r1Priority = flag.Uint("T0", 1, "Time (seconds) during which route 1 is prioritized. Only used in TLS connections.")
var r1Timeout = flag.Uint("T1", 2, "Connection timeout (seconds) for route 1. In non-TLS connections this is also the maximum delay before switching to route 2.")
var r2Timeout = flag.Uint("T2", 5, "Connection timeout (seconds) for route 2")
var force4 = flag.Bool("4", false, "Force IPv4 for connections out of route 1")
var logFile = flag.String("log", "", "Path to log file. By default logs are written to standard output.")
var logAppend = flag.Bool("append", false, "Append to log file if exists")
var tickInterval = flag.Uint("tick", 15, "Status logging interval (minutes)")
var slowSpeed = flag.Uint("slow", 0, "Download speed limit (kB/s) on route 1. Slower destinations will be added to slow list (to be routed via 2).")
var slowTimeout = flag.Uint("slowtime", 30, "Timeout (minutes) for entries in the slow host/IP list")
var slowClose = flag.Bool("slowclose", false, "Close low speed connections immediately on route 1")
var blockedTimeout = flag.Uint("blocktime", 30, "Timeout (minutes) for entries in the blocked host/IP list")
var quiet = flag.Bool("quiet", false, "Suppress output")
var version = "unknown"
var builddate = "unknown"

var (
	logger   *log.Logger
	wg       sync.WaitGroup
	mu       sync.Mutex
	open     [3]int
	sent     [3]int64
	received [3]int64
	//dns2     string
)

func main() {
	flag.Parse()
	if flag.NArg() > 0 || len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr, "Turnout v%s (build %s) usage:\n", version, builddate)
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *logFile != "" {
		var f *os.File
		var err error
		if *logAppend {
			f, err = os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		} else {
			f, err = os.Create(*logFile)
		}
		if err != nil {
			log.Fatalf("Failed to create log file. Error: %s", err)
		}
		defer f.Close()
		logger = log.New(f, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	} else if *quiet {
		logger = log.New(ioutil.Discard, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	} else {
		logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	if runtime.GOOS == "linux" {
		if *tranAddr == "" && *httpAddr == "" {
			log.Fatal("Neither transparent proxy or HTTP proxy is specified.")
		}
	} else if *tranAddr != "" {
		log.Fatal("Transparent proxy is only supported in Linux.")
	} else if *httpAddr == "" {
		log.Fatal("No HTTP proxy is specified.")
	}
	/*if *socksAddr == "" && *ifname2 == "" {
		log.Fatal("A SOCKS server or network interface is needed as upstream.")
	} else if *socksAddr != "" && *ifname2 != "" {
		log.Fatal("You have specified both a SOCKS server and a network interface. Only one is allowed.")
	}*/
	if *socksAddr == "" {
		log.Fatal("A SOCKS5 server is needed as upstream.")
	}
	if _, ok := checkAddr(*tranAddr, false); !ok {
		log.Fatalf("Invalid transparent proxy address %s", *tranAddr)
	}
	if _, ok := checkAddr(*httpAddr, false); !ok {
		log.Fatalf("Invalid HTTP proxy address %s", *httpAddr)
	}
	if *socksAddr != "" {
		if _, ok := checkAddr(*socksAddr, false); !ok {
			log.Fatalf("Invalid SOCKS5 proxy address %s", *socksAddr)
		} else {
			logger.Printf("SOCKS5 server for secondary route is %s", *socksAddr)
		}
	}
	/*if *ifname2 != "" {
		if _, err := net.InterfaceByName(*ifname2); err != nil {
			log.Fatalf("Invalid interface name %s", *ifname2)
		} else {
			logger.Printf("Network interface for secondary route is %s", *ifname2)
		}
		if dns, ok := checkAddr(*dns2Addr, true); !ok {
			log.Fatalf("Invalid DNS nameserver %s", *dns2Addr)
		} else {
			dns2 = dns
			logger.Printf("Secondary route will use %s as DNS nameserver", dns)
		}
	}*/
	if *ipFile != "" {
		ipRules = parseIPList(*ipFile)
		if ipRules != nil {
			logger.Printf("Loaded %d IP rules", len(ipRules))
			sort.Sort(byByte(ipRules))
		}
	}
	if *hostFile != "" {
		hostRules = parseHostList(*hostFile)
		if hostRules != nil {
			logger.Printf("Loaded %d host rules", len(hostRules))
		}
	}
	slowIPSet.timeout = time.Minute * time.Duration(*slowTimeout)
	slowHostSet.timeout = time.Minute * time.Duration(*slowTimeout)
	blockedIPSet.timeout = time.Minute * time.Duration(*blockedTimeout)
	blockedHostSet.timeout = time.Minute * time.Duration(*blockedTimeout)
	total := 0
	dispatch(&total)
	if *tickInterval > 0 {
		go func() {
			c := time.Tick(time.Minute * time.Duration(*tickInterval))
			for range c {
				logger.Printf("STATUS Open connections: Local %d Remote %d / %d", open[0], open[1], open[2])
				logger.Printf("STATUS Route 1 Sent %.1fMB Recv %.1fMB / Route 2 Sent %.1fMB Recv %.1fMB",
					float64(sent[1])/1000000, float64(received[1])/1000000, float64(sent[2])/1000000, float64(received[2])/1000000)
			}
		}()
	}
	wg.Wait()
}

func checkAddr(str string, dns bool) (string, bool) {
	if str == "" {
		return "", true
	}
	_, _, err := net.SplitHostPort(str)
	if err == nil {
		return str, true
	}
	if !dns {
		return "", false
	}
	if _, _, err := net.SplitHostPort(str + ":53"); err == nil {
		return str + ":53", true
	}
	if _, _, err := net.SplitHostPort("[" + str + "]:53"); err == nil {
		return "[" + str + "]:53", true
	}
	return "", false
}
