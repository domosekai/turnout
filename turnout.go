// Released under MIT License
// Copyright (c) 2020 domosekai

// Main program

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

var tranAddr = flag.String("b", "", "Listening address and port for transparent proxy (Linux only) (e.g. 0.0.0.0:2222, [::]:2222)")
var httpAddr = flag.String("h", "", "Listening address and port for HTTP proxy (e.g. 0.0.0.0:8080, [::]:8080)")
var socksListenAddr = flag.String("socks", "", "Listening address and port for SOCKS5 proxy (e.g. 0.0.0.0:1080, [::]:1080)")
var configFile = flag.String("c", "", "Path to JSON config file containing proxy servers")
var tproxy = flag.Bool("t", false, "Use TPROXY in addition to REDIRECT mode for transparent proxy (Linux only)")
var hostFile = flag.String("host", "", "File containing custom rules based on hostnames")
var ipFile = flag.String("ip", "", "File containing custom rules based on IP/CIDRs")
var r1Priority = flag.Float64("T0", 1, "Time (seconds) during which route 1 is prioritized (TLS only)")
var r1Timeout = flag.Uint("T1", 3, "Connection timeout (seconds) for route 1")
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
var shdnsAddr = flag.String("shdns", "", "shdns address and port for reverse DNS lookup")
var version = "unknown"
var builddate = "unknown"

type localConn struct {
	source        *net.TCPAddr // for transparent socket (source spoofing)
	dest, dport   string
	host          string
	key           string
	destIsIP      bool
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
	successive    bool
	lastReq       time.Time
	sent          int64
}

type server struct {
	addr    *url.URL
	route   int  // 2 or 3
	tier    int  // tier index within its route
	timeout uint // connection timeout in seconds
}

var (
	logger      Logger
	wg          sync.WaitGroup
	mu          sync.Mutex
	open        [4]int // open connections
	jobs        [4]int // working goroutines
	sent        [4]int64
	received    [4]int64
	proxies     []server
	route2Tiers [][]int // route2Tiers[tier] = indices into proxies
	route3Tiers [][]int // route3Tiers[tier] = indices into proxies
	maxTiers2   int
	maxTiers3   int
	chkPorts    []string
	rt          routingTable
	shdns       *net.UDPAddr
)

type config struct {
	Route2 [][][]interface{} `json:"route2"`
	Route3 [][][]interface{} `json:"route3"`
}

func main() {
	flag.Parse()
	if flag.NArg() > 0 || len(os.Args) == 1 || *configFile == "" {
		fmt.Fprintf(os.Stderr, "Turnout %s (build %s) usage:\n", version, builddate)
		flag.PrintDefaults()
		os.Exit(1)
	}
	logger.Open(*logFile, *logAppend)
	defer logger.Close()
	if runtime.GOOS == "linux" {
		if *tranAddr == "" && *httpAddr == "" && *socksListenAddr == "" {
			log.Fatal("Neither transparent proxy, HTTP proxy or SOCKS5 proxy is specified")
		}
	} else if *tranAddr != "" {
		log.Fatal("Transparent proxy is only supported in Linux")
	} else if *httpAddr == "" && *socksListenAddr == "" {
		log.Fatal("No HTTP proxy or SOCKS5 proxy is specified")
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
	if *socksListenAddr != "" {
		if s, ok := parseAddr(*socksListenAddr, false); !ok {
			log.Fatalf("Invalid SOCKS5 proxy address %s", *socksListenAddr)
		} else {
			*socksListenAddr = s
		}
	}
	parseConfig(*configFile)
	if *shdnsAddr != "" {
		if _, _, err := net.SplitHostPort(*shdnsAddr); err == nil {
			shdns, _ = net.ResolveUDPAddr("udp", *shdnsAddr)
		}
	}
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

	go listenSignal()

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

func parseConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read config file %s: %s", path, err)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Failed to parse config file %s: %s", path, err)
	}
	if len(cfg.Route2) == 0 {
		log.Fatal("At least 1 tier with 1 proxy is needed in route2")
	}
	for _, tier := range cfg.Route2 {
		if len(tier) == 0 {
			log.Fatal("Empty tier in route2")
		}
	}
	for _, tier := range cfg.Route3 {
		if len(tier) == 0 {
			log.Fatal("Empty tier in route3")
		}
	}

	// Parse Route 2 proxies
	for ti, tier := range cfg.Route2 {
		var indices []int
		for _, raw := range tier {
			s := parseProxyURL(raw, 2, ti)
			proxies = append(proxies, s)
			indices = append(indices, len(proxies)-1)
		}
		route2Tiers = append(route2Tiers, indices)
	}
	maxTiers2 = len(route2Tiers)

	// Parse Route 3 proxies
	for ti, tier := range cfg.Route3 {
		var indices []int
		for _, raw := range tier {
			s := parseProxyURL(raw, 3, ti)
			proxies = append(proxies, s)
			indices = append(indices, len(proxies)-1)
		}
		route3Tiers = append(route3Tiers, indices)
	}
	maxTiers3 = len(route3Tiers)
}

func parseProxyURL(raw []interface{}, route, tier int) server {
	if len(raw) < 2 {
		log.Fatalf("Proxy entry must be [url, timeout]: %v", raw)
	}
	urlStr, ok := raw[0].(string)
	if !ok {
		log.Fatalf("Proxy URL must be a string: %v", raw[0])
	}
	timeoutF, ok := raw[1].(float64)
	if !ok {
		log.Fatalf("Proxy timeout must be a number: %v", raw[1])
	}
	if timeoutF != float64(int(timeoutF)) || timeoutF <= 0 {
		log.Fatalf("Proxy timeout must be a positive integer: %v", raw[1])
	}
	timeout := uint(timeoutF)

	// Assume SOCKS5 if no scheme is given
	if !strings.Contains(urlStr, "//") {
		urlStr = "socks5://" + urlStr
	}
	addr, err := url.Parse(urlStr)
	if err != nil {
		log.Fatalf("Invalid proxy %s: %s", urlStr, err)
	}
	if addr.Port() == "" {
		log.Fatalf("Port number is missing: %s", urlStr)
	}
	addr.Scheme = strings.ToLower(addr.Scheme)
	switch addr.Scheme {
	case "", "socks", "socks5", "socks5h":
		addr.Scheme = "socks5"
	case "http", "https":
	default:
		log.Fatalf("Unsupported proxy scheme %s", addr.Scheme)
	}
	routeName := fmt.Sprintf("Route %d", route)
	logger.Printf("%s server %s (%s, Tier %d, Timeout %ds)", addr.Scheme, addr.Host, routeName, tier, timeout)
	return server{addr: addr, route: route, tier: tier, timeout: timeout}
}
