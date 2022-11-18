// Released under MIT License
// Copyright (c) 2020 domosekai

// Main program

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

var tranAddr = flag.String("b", "", "Listening address and port for transparent proxy (Linux only) (e.g. 0.0.0.0:2222, [::]:2222)")
var httpAddr = flag.String("h", "", "Listening address and port for HTTP proxy (e.g. 0.0.0.0:8080, [::]:8080)")
var socksAddr = flag.String("s", "", "Priority 1 proxy(s) for route 2. Multiple servers will be attempted simultaneously to find the fastest route. Use s2 and s3 if you need fail-over only. (e.g. 127.0.0.1:1080,user:pass@127.0.0.1:1081)")
var socksAddr2 = flag.String("s2", "", "Priority 2 proxy(s) for route 2. These servers will only be used if priority 1 servers have failed.")
var socksAddr3 = flag.String("s3", "", "Priority 3 proxy(s) for route 2. These servers will only be used if priority 2 servers have failed.")
var specialAddr = flag.String("p", "", "Special proxy(s) for route 3. These servers will only be used for specified destinations.")

// var ifname2 = flag.String("if", "", "Network interface for secondary route (e.g. eth1, wlan1)")
// var dns2Addr = flag.String("dns", "8.8.8.8:53", "DNS nameserver for the secondary interface (no need for SOCKS) (e.g. 8.8.8.8)")
var tproxy = flag.Bool("t", false, "Use TPROXY in addition to REDIRECT mode for transparent proxy (Linux only)")
var hostFile = flag.String("host", "", "File containing custom rules based on hostnames")
var ipFile = flag.String("ip", "", "File containing custom rules based on IP/CIDRs")
var r1Priority = flag.Float64("T0", 1, "Time (seconds) during which route 1 is prioritized (TLS only)")
var r1Timeout = flag.Uint("T1", 3, "Connection timeout (seconds) for route 1")
var r2Timeout = flag.Uint("T2", 5, "Connection timeout (seconds) for each server on route 2")
var force4 = flag.Bool("4", false, "Force IPv4 connections out of route 1")
var logFile = flag.String("log", "", "Path to log file")
var logAppend = flag.Bool("append", false, "Append to log file if exists")
var tickInterval = flag.Uint("tick", 30, "Logging interval (minutes) for status report")
var speedPorts = flag.String("speedport", "80,443", "Ports subject to download speed check")
var slowSpeed = flag.Uint("slow", 0, "Download speed limit (kB/s) on route 1. Slower destinations will be put in a list and use route 2 from next time.")
var slowTimeout = flag.Uint("slowtime", 30, "Timeout (minutes) for entries in the slow list")
var slowClose = flag.Bool("slowclose", false, "Close low speed connections immediately on route 1 (may break connections)")
var slowDry = flag.Bool("slowdry", false, "Report low speed but do not switch route automatically")
var blockedTimeout = flag.Uint("blocktime", 30, "Timeout (minutes) for entries in the blocked list")
var dnsOK = flag.Bool("dnsok", false, "Trust system DNS resolver (allowing fast IP rule matching)")
var fastSwitch = flag.Bool("fastswitch", false, "Do not enforce same route to a given destination (may break some websites)")
var verbose = flag.Bool("verbose", false, "Verbose logging")
var httpBadStatus = flag.String("badhttp", "", "Drop specified (non-TLS) HTTP response from route 1 (e.g. 403,404,5*)")
var firstByteDelay = flag.Uint("fbdelay", 0, "Additional delay (ms) applied after first byte is received on route 1")
var version = "unknown"
var builddate = "unknown"

type localConn struct {
	source, dest  string
	sport, dport  string
	host          string
	key           string
	conn          net.Conn
	buf           *bufio.Reader
	mode, network string
	total         int
}

type remoteConn struct {
	conn          *net.Conn
	first         []byte
	firstIsFull   bool
	firstReq      *http.Request
	reqs          chan *http.Request
	route, server int
	ruleBased     bool
	hasConnection bool
	tls           bool
	lastReq       time.Time
	sent          int64
}

type server struct {
	addr *url.URL
	pri  int
}

var (
	logger   *log.Logger
	wg       sync.WaitGroup
	mu       sync.Mutex
	open     [4]int // open connections
	jobs     [4]int // working goroutines
	sent     [4]int64
	received [4]int64
	proxies  []server
	priority [4][]int
	chkPorts []string
	rt       routingTable
	//dns2     string
)

func main() {
	flag.Parse()
	if flag.NArg() > 0 || len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr, "Turnout %s (build %s) usage:\n", version, builddate)
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
	} else {
		logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	if runtime.GOOS == "linux" {
		if *tranAddr == "" && *httpAddr == "" {
			log.Fatal("Neither transparent proxy or HTTP proxy is specified")
		}
	} else if *tranAddr != "" {
		log.Fatal("Transparent proxy is only supported in Linux")
	} else if *httpAddr == "" {
		log.Fatal("No HTTP proxy is specified")
	}
	if *tranAddr != "" {
		if s, ok := parseAddr(*tranAddr, false); !ok {
			log.Fatalf("Invalid transparent proxy address %s", *tranAddr)
		} else {
			*tranAddr = s
		}
	}
	if *httpAddr != "" {
		if s, ok := parseAddr(*httpAddr, false); !ok {
			log.Fatalf("Invalid HTTP proxy address %s", *httpAddr)
		} else {
			*httpAddr = s
		}
	}
	/*if *socksAddr == "" && *ifname2 == "" {
		log.Fatal("A proxy or network interface is needed as upstream")
	} else if *socksAddr != "" && *ifname2 != "" {
		log.Fatal("You have specified both a proxy and a network interface. Only one is allowed")
	}*/
	if parseProxy(*socksAddr, 1) == 0 {
		log.Fatal("At least 1 proxy is needed as upstream")
	}
	if parseProxy(*socksAddr2, 2) > 0 {
		parseProxy(*socksAddr3, 3)
	}
	parseProxy(*specialAddr, 0)
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
		readIPRules(&ipRules, *ipFile)
	}
	if *hostFile != "" {
		readHostRules(&hostRules, *hostFile)
	}
	if *httpBadStatus != "" {
		readHTTPRules(&httpRules, *httpBadStatus)
	}
	if strings.ContainsAny(*speedPorts, "0123456789") {
		chkPorts = strings.Split(strings.Trim(*speedPorts, ","), ",")
		logger.Printf("Loaded %d speed check ports", len(chkPorts))
	}
	rt.table = make(map[string]*routeEntry)
	slowIPSet.timeout = time.Minute * time.Duration(*slowTimeout)
	slowHostSet.timeout = time.Minute * time.Duration(*slowTimeout)
	blockedIPSet.timeout = time.Minute * time.Duration(*blockedTimeout)
	blockedHostSet.timeout = time.Minute * time.Duration(*blockedTimeout)

	// Listen for signal to clear cache and re-read rules
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	go func() {
		for range sigs {
			logger.Println("Received signal to reload files and clear cache")
			if *ipFile != "" {
				readIPRules(&ipRules, *ipFile)
			}
			if *hostFile != "" {
				readHostRules(&hostRules, *hostFile)
			}
			slowIPSet.clear()
			slowHostSet.clear()
			blockedIPSet.clear()
			blockedHostSet.clear()
			logger.Println("Slow and blocked lists flushed")
		}
	}()

	// Main process
	total := 0
	dispatch(&total)
	if *tickInterval > 0 {
		go func() {
			c := time.Tick(time.Minute * time.Duration(*tickInterval))
			for range c {
				logger.Printf("STATUS Open connections per route: Local %d Remote %d / %d Special %d", open[0], open[1], open[2], open[3])
				logger.Printf("STATUS Route 1 Sent %.1f MB Recv %.1f MB / Route 2 Sent %.1f MB Recv %.1f MB / Special Sent %.1f MB Recv %.1f MB",
					float64(sent[1])/1000000, float64(received[1])/1000000, float64(sent[2])/1000000, float64(received[2])/1000000, float64(sent[3])/1000000, float64(received[3])/1000000)
				if *verbose {
					logger.Printf("STATUS Routing entries: %d Active dispatchers: %d Workers per route: %d / %d / %d", rt.count, jobs[0], jobs[1], jobs[2], jobs[3])
				}
			}
		}()
	}
	wg.Wait()
}

func parseAddr(str string, dns bool) (string, bool) {
	s := strings.TrimSpace(str)
	if s == "" {
		return "", false
	}
	_, _, err := net.SplitHostPort(s)
	if err == nil {
		return s, true
	}
	if !dns {
		return "", false
	}
	if _, _, err := net.SplitHostPort(s + ":53"); err == nil {
		return s + ":53", true
	}
	if _, _, err := net.SplitHostPort("[" + s + "]:53"); err == nil {
		return "[" + s + "]:53", true
	}
	return "", false
}

func parseProxy(str string, pri int) int {
	if str == "" {
		return 0
	}
	for _, s := range strings.Split(str, ",") {
		// Assume SOCKS5 if no scheme is given (backward compatibility)
		if !strings.Contains(s, "//") {
			s = "socks5://" + s
		}
		if addr, err := url.Parse(s); err != nil {
			log.Fatalf("Invalid proxy %s: %s", s, err)
		} else {
			addr.Scheme = strings.ToLower(addr.Scheme)
			switch addr.Scheme {
			case "", "socks", "socks5", "socks5h":
				addr.Scheme = "socks5"
			case "http", "https":
			default:
				log.Fatalf("Unsupported proxy scheme %s", addr.Scheme)
			}
			if pri > 0 {
				logger.Printf("%s server %s (Priority %d)", addr.Scheme, addr.Host, pri)
				proxies = append(proxies, server{addr, pri})
				priority[pri] = append(priority[pri], len(proxies)-1)
			} else {
				// pri == 0 for special
				logger.Printf("%s special server %s", addr.Scheme, addr.Host)
				proxies = append(proxies, server{addr, pri})
			}
		}
	}
	return len(priority[pri])
}
