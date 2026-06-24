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
	"sort"
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
var logFile = flag.String("log", "", "Path to log file")
var logAppend = flag.Bool("append", false, "Append to log file if exists")
var tickInterval = flag.Uint("tick", 30, "Logging interval (minutes) for status report")
var speedPorts = flag.String("speedport", "80,443", "Ports subject to download speed check")
var slowSpeed = flag.Uint("slow", 0, "Download speed limit (kB/s) on route 1. Slower destinations will be put in a list and use blocked route from next time.")
var slowTimeout = flag.Uint("slowtime", 30, "Timeout (minutes) for entries in the slow list")
var slowClose = flag.Bool("slowclose", false, "Close low speed connections immediately on route 1 (may break connections)")
var slowDry = flag.Bool("slowdry", false, "Report low speed but do not switch route automatically")
var blockedTimeout = flag.Uint("blocktime", 30, "Timeout (minutes) for entries in the blocked list")
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
	conn          net.Conn
	buf           *bufio.Reader
	mode, network string
	total         int
}

type remoteConn struct {
	conn          net.Conn
	first         []byte
	firstIsFull   bool
	firstReq      *http.Request
	reqs          chan *http.Request
	srv           *server
	ruleBased     bool
	hasConnection bool
	tls           bool
	successive    bool
	lastReq       time.Time
	sent          int64
}

type server struct {
	id      int
	addr    *url.URL // nil for direct route
	route   int
	tier    int
	timeout int
	force4  bool // direct only: force IPv4
}

type autoConfig struct {
	Primary   int `json:"primary"`
	Secondary int `json:"secondary"`
	Priority  int `json:"priority"`
}

type routeSpec struct {
	ID      int        `json:"id"`
	Direct  bool       `json:"direct"`
	Timeout int        `json:"timeout"`
	Force4  bool       `json:"force4"`
	Tiers   [][]string `json:"tiers"`
}

type routeConfig struct {
	id      int
	direct  bool
	timeout int
	tiers   [][]*server // tiers[tier] = servers in that tier
}

type routeResult struct {
	ok    bool
	srv   *server
	out   net.Conn
	stop2 bool
}

type doSignal struct {
	srv *server // nil = abort all
}

var (
	logger        Logger
	wg            sync.WaitGroup
	mu            sync.Mutex
	open          = make(map[int]int)
	jobs          = make(map[int]int)
	sent          = make(map[int]int64)
	received      = make(map[int]int64)
	routes        = make(map[int]*routeConfig)
	servers       []*server // indexed by server id (1-based for proxies, 0 unused)
	autoCfg       autoConfig
	blockedRoutes []int
	totalTimeout  int
	chkPorts      []string
	rt            routingTable
	shdns         *net.UDPAddr
)

type config struct {
	Routes       []routeSpec `json:"routes"`
	Auto         autoConfig  `json:"auto"`
	BlockedRoute string      `json:"blockedRoute"`
	Timeout      int         `json:"timeout"`
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
				ids := sortedRouteIDs()

				// Line 1: Open connections
				connParts := []string{fmt.Sprintf("Local: %d", open[0])}
				for _, id := range ids {
					connParts = append(connParts, fmt.Sprintf("R%d: %d", id, open[id]))
				}
				logger.Printf("STATUS Open connections: %s, Routing entries: %d", strings.Join(connParts, ", "), rt.count)

				// Line 2: Traffic
				trafficParts := make([]string, 0, len(ids))
				for _, id := range ids {
					trafficParts = append(trafficParts, fmt.Sprintf("R%d: %.1f / %.1f MB", id, float64(sent[id])/1e6, float64(received[id])/1e6))
				}
				logger.Printf("STATUS Sent / Received: %s", strings.Join(trafficParts, ", "))

				// Line 3: Jobs
				jobParts := make([]string, 0, len(ids))
				for _, id := range ids {
					jobParts = append(jobParts, fmt.Sprintf("R%d: %d", id, jobs[id]))
				}
				logger.Printf("STATUS Dispatchers: %d, Workers %s", jobs[0], strings.Join(jobParts, ", "))
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
	if len(cfg.Routes) == 0 {
		log.Fatal("At least one route is required")
	}

	// Parse routes
	hasDirect := false
	servers = make([]*server, 1) // index 0 reserved for direct route
	for _, spec := range cfg.Routes {
		if spec.ID <= 0 {
			log.Fatalf("Route ID must be positive: %d", spec.ID)
		}
		if _, exists := routes[spec.ID]; exists {
			log.Fatalf("Duplicate route ID: %d", spec.ID)
		}
		if spec.Direct {
			if spec.ID != 1 {
				log.Fatal("Direct route must have id 1")
			}
			if spec.Timeout == 0 {
				spec.Timeout = 3
			}
			directSrv := &server{
				id:      0,
				addr:    nil,
				route:   spec.ID,
				tier:    0,
				timeout: spec.Timeout,
				force4:  spec.Force4,
			}
			servers[0] = directSrv
			routes[spec.ID] = &routeConfig{
				id:      spec.ID,
				direct:  true,
				timeout: spec.Timeout,
				tiers:   [][]*server{{directSrv}},
			}
			hasDirect = true
			logger.Printf("Route %d: Direct (Timeout %ds, Force4 %v)", spec.ID, spec.Timeout, spec.Force4)
		} else {
			if spec.Timeout == 0 {
				log.Fatalf("Route %d: timeout is required", spec.ID)
			}
			if len(spec.Tiers) == 0 {
				log.Fatalf("Route %d: at least one tier is required", spec.ID)
			}
			rc := &routeConfig{
				id:      spec.ID,
				timeout: spec.Timeout,
			}
			for ti, tier := range spec.Tiers {
				if len(tier) == 0 {
					log.Fatalf("Route %d: empty tier %d", spec.ID, ti)
				}
				var tierServers []*server
				for _, serverURL := range tier {
					addr := parseProxyURL(serverURL)
					s := &server{
						addr:    addr,
						route:   spec.ID,
						tier:    ti,
						timeout: spec.Timeout,
					}
					logger.Printf("%s server %s (Route %d, Tier %d, Timeout %ds)", addr.Scheme, addr.Host, spec.ID, ti, spec.Timeout)
					servers = append(servers, s)
					s.id = len(servers) - 1
					tierServers = append(tierServers, s)
				}
				rc.tiers = append(rc.tiers, tierServers)
			}
			routes[spec.ID] = rc
		}
	}
	if !hasDirect {
		log.Fatal("A direct route (id 1) is required")
	}

	// Parse auto config
	autoCfg = cfg.Auto
	if autoCfg.Primary == 0 {
		autoCfg.Primary = 1
	}
	if autoCfg.Secondary == 0 {
		autoCfg.Secondary = 2
	}
	if autoCfg.Priority == 0 {
		autoCfg.Priority = 1
	}
	if _, ok := routes[autoCfg.Primary]; !ok {
		log.Fatalf("Auto primary route %d not found", autoCfg.Primary)
	}
	if !routes[autoCfg.Primary].direct {
		log.Fatalf("Auto primary route %d must be a direct route", autoCfg.Primary)
	}
	if _, ok := routes[autoCfg.Secondary]; !ok {
		log.Fatalf("Auto secondary route %d not found", autoCfg.Secondary)
	}
	if autoCfg.Primary == autoCfg.Secondary {
		log.Fatalf("Auto primary and secondary routes must be different")
	}

	// Parse blockedRoute
	if cfg.BlockedRoute == "" {
		blockedRoutes = []int{2, 1}
	} else {
		var err error
		blockedRoutes, err = parseRoutes(cfg.BlockedRoute)
		if err != nil {
			log.Fatalf("Invalid blockedRoute: %v", err)
		}
	}
	for _, r := range blockedRoutes {
		if r <= 0 {
			log.Fatalf("Blocked route must be positive: %d", r)
		}
		if _, ok := routes[r]; !ok {
			log.Fatalf("Blocked route %d not found", r)
		}
	}
	logger.Printf("Blocked routes: %v", blockedRoutes)

	totalTimeout = cfg.Timeout
	if totalTimeout == 0 {
		totalTimeout = 20
	}
	if totalTimeout < 0 {
		log.Fatalf("Invalid total timeout %d", totalTimeout)
	}
}

func parseProxyURL(urlStr string) *url.URL {
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
	return addr
}

func sortedRouteIDs() []int {
	ids := make([]int, 0, len(routes))
	for id := range routes {
		if id != 0 {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	return ids
}
