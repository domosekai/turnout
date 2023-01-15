// Released under MIT License
// Copyright (c) 2020 domosekai

// Relay functions for both modes

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	http_dialer "github.com/mwitkow/go-http-dialer"
	"golang.org/x/net/proxy"
)

const (
	initialSize       = 10000
	bufferSize        = 4096 // Not effective if speed detection is disabled (system default buffer size will be used)
	minSampleInterval = 3    // Due to slow start, this seconds are needed for meaningful speed detection
	maxSampleInterval = 30   // Too long sample period might not mean anything
	minSpeed          = 1    // Average speed below this kB/s is likely to have special purpose
	blockSafeTime     = 2    // After this many seconds it is less likely to be reset by firewall
)

var (
	blockedIPSet   ipSet
	blockedHostSet hostSet
	slowIPSet      ipSet
	slowHostSet    hostSet
)

// Wait for first byte from client, should usually come immediately with ACK in the 3-way handshake, or never come (FTP)
func (lo *localConn) getFirstByte() {

	// Set initial timeout to a large value (git may have more than 1s delay)
	lo.conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	first := make([]byte, initialSize)
	n, err := lo.buf.Read(first)
	if err == nil {
		if *verbose {
			logger.Printf("%s %5d:  *            First %d bytes from client", lo.mode, lo.total, n)
		}
	} else if !strings.Contains(err.Error(), "time") {
		if *verbose {
			logger.Printf("%s %5d:  *            Failed to read first byte from client. Error: %s", lo.mode, lo.total, err)
		}
		return
	}
	lo.conn.SetReadDeadline(time.Time{})

	// Prepare remote connection
	var re remoteConn
	re.firstIsFull = true

	// TLS
	if n >= recordHeaderLen && recordType(first[0]) == recordTypeHandshake {

		// Check completeness as it does not make sense to send an incomplete TLS Handshake
		len := int(first[3])<<8 | int(first[4])
		if n < len+recordHeaderLen {
			n1 := len + recordHeaderLen - n
			if *verbose {
				logger.Printf("%s %5d:  *            TLS handshake incomplete. Fetching another %d bytes from client", lo.mode, lo.total, n1)
			}
			buf := make([]byte, n1)
			lo.conn.SetReadDeadline(time.Now().Add(time.Second * 3))
			_, err = io.ReadFull(lo.buf, buf)
			lo.conn.SetReadDeadline(time.Time{})
			if err == nil {
				first = append(first[:n], buf...)
				n += n1
				if *verbose {
					logger.Printf("%s %5d:  *            First %d bytes from client", lo.mode, lo.total, n)
				}
			}
		}

		// Client Hello
		if err == nil && n > recordHeaderLen && first[recordHeaderLen] == typeClientHello {
			if m := new(clientHelloMsg); m.unmarshal(first[recordHeaderLen:n]) {
				if m.serverName != "" {
					if *verbose {
						logger.Printf("%s %5d:  *            %s SNI %s", lo.mode, lo.total, m.verString, m.serverName)
					}
					if host, _ := normalizeHostname(m.serverName, lo.dport); net.ParseIP(host) == nil {
						lo.host = host
					}
				} else if m.esni {
					if *verbose {
						logger.Printf("%s %5d:  *            %s ESNI", lo.mode, lo.total, m.verString)
					}
				} else {
					if *verbose {
						logger.Printf("%s %5d:  *            %s Client Hello", lo.mode, lo.total, m.verString)
					}
				}
				re.tls = true
				re.firstIsFull = false
			}
		}

	} else if n > 0 {

		// HTTP
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(first[:n])))

		// Check completeness
		if err != nil && errors.Is(err, io.ErrUnexpectedEOF) {
			if *verbose {
				logger.Printf("%s %5d:  *            HTTP header incomplete. Continue fetching from client", lo.mode, lo.total)
			}
			lo.conn.SetReadDeadline(time.Now().Add(time.Second * 1))
			n1, _ := io.ReadFull(lo.buf, first[n:])
			lo.conn.SetReadDeadline(time.Time{})
			if n1 > 0 {
				n += n1
				if *verbose {
					logger.Printf("%s %5d:  *            First %d bytes from client", lo.mode, lo.total, n)
				}
				req, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(first[:n])))
			}
		}

		if err == nil {
			if *verbose {
				logger.Printf("%s %5d:  *            HTTP %s Host %s Content-length %d", lo.mode, lo.total, req.Method, req.Host, req.ContentLength)
			}
			if host, _ := normalizeHostname(req.Host, lo.dport); net.ParseIP(host) == nil {
				lo.host = host
			}
			re.firstReq = req
			if req.ContentLength == 0 {
				re.firstIsFull = false
			}
		}
	}

	if n > 0 && n < initialSize && !re.tls && re.firstReq == nil {
		// Allow subsequent reads within very short period of time
		lo.conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		n1, _ := io.ReadFull(lo.buf, first[n:])
		lo.conn.SetReadDeadline(time.Time{})
		n += n1
	}

	// Only use host as connection and routing key if dest is IP
	if net.ParseIP(lo.dest) != nil && lo.host != "" {
		lo.key = net.JoinHostPort(lo.host, lo.dport)
	} else {
		lo.key = net.JoinHostPort(lo.dest, lo.dport)
	}

	re.first = first[:n]
	if re.getRouteFor(*lo) {
		re.relayLocalFor(*lo)
	}

}

func normalizeHostname(host, defaultPort string) (string, string) {
	h := strings.TrimSuffix(host, ".")
	if strings.HasSuffix(h, "]") {
		h = strings.TrimSuffix(h, "]")
		h = strings.TrimPrefix(h, "[")
	}
	if h == "" {
		return "", defaultPort
	}
	if host, port, err := net.SplitHostPort(h); err == nil {
		return host, port
	}
	return h, defaultPort
}

func (re *remoteConn) getRouteFor(lo localConn) bool {
	mu.Lock()
	jobs[0]++
	mu.Unlock()
	defer func() {
		mu.Lock()
		jobs[0]--
		mu.Unlock()
	}()
	start := make([]chan bool, 4) // one channel for each route / priority
	for i := range start {
		start[i] = make(chan bool)
	}
	try1 := make(chan int, 1)
	try2 := make(chan int, len(proxies))
	stop2 := make(chan bool, 1)
	do1 := make(chan int, 1)
	do2 := make(chan int, 1)
	var out1 net.Conn
	out2 := make([]net.Conn, len(proxies))
	ok1, ok2 := -1, -1
	var available1, available2 int

	// Match rules
	var route int
	var server int
	if lo.host != "" {
		route, re.ruleBased = matchHost(lo.total, lo.mode, lo.host, lo.dport)
	}
	if route == 0 {
		if ip := net.ParseIP(lo.dest); ip != nil {
			// dest is IP, match IP rules if dns is ok or hostname is not sniffed
			if lo.host == "" || *dnsOK {
				route, re.ruleBased = matchIP(lo.total, lo.mode, ip, lo.dport)
			}
		} else {
			// dest is hostname
			route, re.ruleBased = matchHost(lo.total, lo.mode, lo.dest, lo.dport)
		}
	}
	if route < 0 || route > 3 {
		if *verbose {
			logger.Printf("%s %5d:  *            Route to %s is invalid or blocked", lo.mode, lo.total, lo.key)
		}
		return false
	}

	// Get existing route or a locked route
	var entry *routeEntry
	var exist bool
	if !*fastSwitch {
		if r, s, e, n := rt.addOrLock(lo.key, route); e {
			route = r
			server = s
			if *verbose {
				logger.Printf("%s %5d: EXT           Connections to %s exist. Select route %d server %d", lo.mode, lo.total, lo.key, route, server)
			}
			exist = true
			entry = n
		} else {
			entry = n
		}
	}

	// Dispatch workers
	net1 := lo.network
	net2 := lo.network
	if *force4 {
		net1 = "tcp4"
	}
	totalTimeout := 1
	if route == 0 || route == 1 {
		go re.handleRemote(lo, &out1, net1, int(*r1Timeout), 1, 1, start[0], try1, do1, stop2)
		totalTimeout += int(*r1Timeout)
		available1 = 1
	}
	if route == 0 || route == 2 || route == 3 {
		if server == 0 {
			if route == 3 {
				s := len(proxies)
				go re.handleRemote(lo, &out2[s-1], net2, int(*r2Timeout), 3, s, start[1], try2, do2, stop2)
				totalTimeout += int(*r2Timeout)
				available2 = 1
			} else {
				for i, v := range proxies {
					if v.pri != 0 {
						go re.handleRemote(lo, &out2[i], net2, int(*r2Timeout), 2, i+1, start[v.pri], try2, do2, stop2)
						totalTimeout += int(*r2Timeout)
						available2++
					}
				}
			}
		} else {
			go re.handleRemote(lo, &out2[server-1], net2, int(*r2Timeout), route, server, start[1], try2, do2, stop2)
			totalTimeout += int(*r2Timeout)
			available2 = 1
		}
	}

	// Send signal to workers
	successive := !re.tls
	switch route {
	case 0:
		start[0] <- true
		if !successive && server == 0 {
			for range priority[1] {
				start[1] <- true
			}
		}
	case 1:
		start[0] <- true
	case 2:
		if !successive && server == 0 {
			for range priority[1] {
				start[1] <- true
			}
		} else {
			start[1] <- true
		}
	case 3:
		start[1] <- true
	}

	// Wait for first byte from server
	timer1 := time.NewTimer(time.Duration(float64(time.Second) * *r1Priority)) // during which route 1 is prioritized
	timer2 := time.NewTimer(time.Second * time.Duration(totalTimeout))
	wait := true
	var server2 int
	var count2 int
	for {
		// Make sure no channel is written twice without return
		// and no goroutine will wait forever
		select {
		// This is before route 1 sends status, when it found the IP matches some rule
		case bad2 := <-stop2:
			if bad2 && available2 > 0 {
				do2 <- 0
				available2 = 0
			}
		// Route 1 sends status, bad2 is set by this time
		case ok1 = <-try1:
			if ok1 > 0 {
				if !*fastSwitch {
					if !exist {
						if *verbose {
							logger.Printf("%s %5d:     NEW     1 Save route 1 server 1 for %s", lo.mode, lo.total, lo.key)
						}
						entry.save(1, 1)
					} else {
						if entry.reset(1, 1) {
							if *verbose {
								logger.Printf("%s %5d:      *      1 Reset counter for %s", lo.mode, lo.total, lo.key)
							}
						}
					}
				}
				do1 <- 1
				if available2 > 0 {
					do2 <- 0
				}
				re.route = 1
				re.conn = &out1
				return true
			}
			available1--
			if available2 > 0 {
				if successive {
					start[1] <- true
				}
				if server2 > 0 {
					if !*fastSwitch {
						if !exist {
							if *verbose {
								logger.Printf("%s %5d:     NEW     2 Save route 2 server %d for %s", lo.mode, lo.total, server2, lo.key)
							}
							entry.save(2, server2)
						} else {
							if entry.reset(2, server2) {
								if *verbose {
									logger.Printf("%s %5d:      *      2 Reset counter for %s", lo.mode, lo.total, lo.key)
								}
							}
						}
					}
					do2 <- server2
					re.route = 2
					re.conn = &out2[server2-1]
					re.server = server2
					return true
				}
			} else {
				if !*fastSwitch {
					if !exist {
						logger.Printf("%s %5d:     ERR       No available route to %s", lo.mode, lo.total, lo.key)
						rt.unlock(lo.key, entry)
					} else {
						logger.Printf("%s %5d:     ERR     1 Existing route to %s failed", lo.mode, lo.total, lo.key)
						rt.del(lo.key, false, route, server)
					}
				} else {
					logger.Printf("%s %5d:     ERR       No available route to %s", lo.mode, lo.total, lo.key)
				}
				return false
			}
		// Route 2 sends status from any server
		case ok2 = <-try2:
			count2++
			if ok2 > 0 && available2 > 0 && server2 == 0 {
				server2 = ok2
				if available1 == 0 {
					var r int
					if route == 3 {
						r = 3
					} else {
						r = 2
					}
					if !*fastSwitch {
						if !exist {
							if *verbose {
								logger.Printf("%s %5d:     NEW     %d Save route %d server %d for %s", lo.mode, lo.total, r, r, server2, lo.key)
							}
							entry.save(r, server2)
						} else {
							if entry.reset(r, server2) {
								if *verbose {
									logger.Printf("%s %5d:      *      %d Reset counter for %s", lo.mode, lo.total, r, lo.key)
								}
							}
						}
					}
					do2 <- server2
					re.route = r
					re.conn = &out2[server2-1]
					re.server = server2
					return true
				} else if !wait {
					if !*fastSwitch {
						if !exist {
							if *verbose {
								logger.Printf("%s %5d:     NEW     2 Save route 2 server %d for %s", lo.mode, lo.total, server2, lo.key)
							}
							entry.save(2, server2)
						} else {
							if entry.reset(2, server2) {
								if *verbose {
									logger.Printf("%s %5d:      *      2 Reset counter for %s", lo.mode, lo.total, lo.key)
								}
							}
						}
					}
					do2 <- server2
					do1 <- 0
					re.route = 2
					re.conn = &out2[server2-1]
					re.server = server2
					return true
				}
			} else {
				if ok2 == 0 {
					available2--
				}
				if available2 > 0 && server2 == 0 {
					if successive {
						if count2 < len(priority[1]) {
							start[1] <- true
						} else if count2 < len(priority[1])+len(priority[2]) {
							start[2] <- true
						} else if count2 < len(priority[1])+len(priority[2])+len(priority[3]) {
							start[3] <- true
						}
					} else if count2 == len(priority[1]) {
						for range priority[2] {
							start[2] <- true
						}
					} else if count2 == len(priority[1])+len(priority[2]) {
						for range priority[3] {
							start[3] <- true
						}
					}
				} else if available1 == 0 {
					if !*fastSwitch {
						if !exist {
							logger.Printf("%s %5d:     ERR       No available route to %s", lo.mode, lo.total, lo.key)
							rt.unlock(lo.key, entry)
						} else {
							logger.Printf("%s %5d:     ERR     %d Existing route to %s failed", lo.mode, lo.total, route, lo.key)
							rt.del(lo.key, false, route, server)
						}
					} else {
						logger.Printf("%s %5d:     ERR       No available route to %s", lo.mode, lo.total, lo.key)
					}
					return false
				}
			}
		// Priority period for route 1 ends
		case <-timer1.C:
			wait = false
			if server2 > 0 && available2 > 0 {
				if !*fastSwitch {
					if !exist {
						if *verbose {
							logger.Printf("%s %5d:     NEW     2 Save route 2 server %d for %s", lo.mode, lo.total, server2, lo.key)
						}
						entry.save(2, server2)
					} else {
						if entry.reset(2, server2) {
							if *verbose {
								logger.Printf("%s %5d:      *      2 Reset counter for %s", lo.mode, lo.total, lo.key)
							}
						}
					}
				}
				do2 <- server2
				if available1 > 0 {
					do1 <- 0
				}
				re.route = 2
				re.conn = &out2[server2-1]
				re.server = server2
				return true
			}
		case <-timer2.C:
			if available1 > 0 {
				do1 <- 0
			}
			if available2 > 0 {
				do2 <- 0
			}
			if !*fastSwitch {
				if !exist {
					logger.Printf("%s %5d:     ERR       No available route to %s", lo.mode, lo.total, lo.key)
					rt.unlock(lo.key, entry)
				} else {
					logger.Printf("%s %5d:     ERR     %d Existing route to %s failed", lo.mode, lo.total, route, lo.key)
					rt.del(lo.key, false, route, server)
				}
			} else {
				logger.Printf("%s %5d:     ERR       No available route to %s", lo.mode, lo.total, lo.key)
			}
			return false
		}
	}
}

func (re *remoteConn) relayLocalFor(lo localConn) {
	totalBytes := int64(len(re.first))
	var err error
	for {
		p := make([]byte, bufferSize)
		var bytes int
		bytes, err = lo.buf.Read(p)
		if err == nil {
			bytes, err = (*re.conn).Write(p[:bytes])
		} else {
			bytes, _ = (*re.conn).Write(p[:bytes])
		}
		totalBytes += int64(bytes)
		if err != nil {
			break
		}
		// Only set time if successfully sent
		re.lastReq = time.Now()
	}
	if err == nil || errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "time") {
		if *verbose {
			logger.Printf("%s %5d:          *    Local connection closed. Sent %d bytes.", lo.mode, lo.total, totalBytes)
		}
	} else if strings.Contains(err.Error(), "reset") {
		if *verbose {
			logger.Printf("%s %5d:          *    Local connection reset. Sent %d bytes.", lo.mode, lo.total, totalBytes)
		}
		if tcp, ok := (*re.conn).(*net.TCPConn); ok {
			tcp.SetLinger(0)
		}
	} else {
		if *verbose {
			logger.Printf("%s %5d:         ERR   Local connection closed. Sent %d bytes. Error: %s", lo.mode, lo.total, totalBytes, err)
		}
	}
	mu.Lock()
	sent[re.route] += totalBytes
	mu.Unlock()
	(*re.conn).Close()
}

func (re *remoteConn) handleRemote(lo localConn, out *net.Conn, network string, timeout, route, server int, start chan bool, try, do chan int, stop2 chan bool) {
	mu.Lock()
	jobs[route]++
	mu.Unlock()
	select {
	case <-start:
		re.doRemote(lo, out, network, timeout, route, server, try, do, stop2)
	case s := <-do:
		do <- s
	}
	mu.Lock()
	jobs[route]--
	mu.Unlock()
}

func (re *remoteConn) doRemote(lo localConn, out *net.Conn, network string, timeout, route, server int, try, do chan int, stop2 chan bool) {
	var err error
	if route == 1 {
		dp := net.JoinHostPort(lo.dest, lo.dport)
		if *verbose {
			logger.Printf("%s %5d:  *          %d Dialing to %s %s", lo.mode, lo.total, route, network, dp)
		}
		*out, err = net.DialTimeout(network, dp, time.Second*time.Duration(timeout))
	} else if proxies[server-1].addr.Scheme == "socks5" {
		// SOCKS5
		server := proxies[server-1]
		// URL.Host is hostname:port
		addr := server.addr.Host
		var dialer proxy.Dialer
		var auth *proxy.Auth
		if server.addr.User != nil {
			auth = new(proxy.Auth)
			auth.User = server.addr.User.Username()
			if p, ok := server.addr.User.Password(); ok {
				auth.Password = p
			}
		}
		dialer, err = proxy.SOCKS5("tcp", addr, auth, &net.Dialer{Timeout: time.Second * time.Duration(timeout)})
		if err != nil {
			logger.Printf("%s %5d: ERR         %d Failed to dial server %s. Error: %s", lo.mode, lo.total, route, addr, err)
			try <- 0
			return
		}
		if *verbose {
			logger.Printf("%s %5d:  *          %d Dialing to %s %s via %s", lo.mode, lo.total, route, network, lo.key, addr)
		}
		*out, err = dialer.Dial(network, lo.key)
	} else {
		// HTTP or HTTPS
		server := proxies[server-1]
		addr := server.addr.Host
		var auth http_dialer.ProxyAuthorization
		if server.addr.User != nil {
			user := server.addr.User.Username()
			password, _ := server.addr.User.Password()
			auth = http_dialer.AuthBasic(user, password)
		}
		// Optional TLS configuration
		tlsConfig := tls.Config{
			//			MinVersion: tls.VersionTLS10,
			//			NextProtos: []string{"http/1.1"},
		}
		dialer := http_dialer.New(server.addr,
			http_dialer.WithProxyAuth(auth),
			http_dialer.WithTls(&tlsConfig),
			http_dialer.WithConnectionTimeout(time.Second*time.Duration(timeout)))
		if *verbose {
			logger.Printf("%s %5d:  *          %d Dialing to %s %s via %s", lo.mode, lo.total, route, network, lo.key, addr)
		}
		// HTTP dialer only accepts tcp as network
		*out, err = dialer.Dial("tcp", lo.key)
	}
	// Binding to interface is not available on Go natively, you have to use raw methods for each platform (SO_BINDTODEVICE on Linux, bind() on Windows) and do communication in raw
	// Binding to local address may not affect the routing on Linux (you can see packets out of main route with wrong source address)
	// On Windows Vista and later the routing works but the resolver is not routed and perhaps you need to set up a dialer for the resolver separately
	/*else {
		var inf *net.Interface
		inf, err = net.InterfaceByName(*ifname2)
		if err != nil {
			logger.Printf("%s %5d: ERR         %d Failed to find the specified network interface. Error: %s", mode, total, route, err)
			try <- false
			return
		}
		var addrs []net.Addr
		addrs, err = inf.Addrs()
		if err != nil {
			logger.Printf("%s %5d: ERR         %d Failed to find a local address of the specified network interface. Error: %s", mode, total, route, err)
			try <- false
			return
		}
		dialer := net.Dialer{
			Timeout:   time.Second * time.Duration(timeout),
			LocalAddr: &net.TCPAddr{IP: addrs[1].(*net.IPNet).IP},
			Resolver: &net.Resolver{
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Second * time.Duration(timeout),
					}
					return d.DialContext(ctx, "udp", dns2)
				},
			},
		}
		if host != "" {
			dp = net.JoinHostPort(host, port)
		} else {
			dp = net.JoinHostPort(dest, port)
		}
		logger.Printf("%s %5d:  *          %d Dialing to %s %s", mode, total, route, network, dp)
		*out, err = dialer.Dial(network, dp)
	}*/
	if err != nil {
		if strings.Contains(err.Error(), "time") {
			if *verbose {
				logger.Printf("%s %5d: SYN         %d Initial connection timeout", lo.mode, lo.total, route)
			}
		} else if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "reset") {
			// Linux: "connect: connection refused"
			// Windows: "connectex: No connection could be made because the target machine actively refused it."
			if *verbose {
				logger.Printf("%s %5d: RST         %d Initial connection reset", lo.mode, lo.total, route)
			}
			/*if route == 1 && !re.ruleBased {
				if ip := net.ParseIP(lo.dest); ip != nil && (lo.host == "" || *dnsOK) {
					logger.Printf("%s %5d: ADD         %d TCP reset detected, %s %s port %s added to blocked list", lo.mode, lo.total, route, lo.host, ip, lo.dport)
					blockedIPSet.add(ip, lo.dport)
				} else if lo.host != "" {
					logger.Printf("%s %5d: ADD         %d TCP reset detected, %s port %s added to blocked list", lo.mode, lo.total, route, lo.host, lo.dport)
				}
				blockedHostSet.add(lo.host, lo.dport)
			}*/
		} else if strings.Contains(err.Error(), "no such host") {
			if *verbose {
				logger.Printf("%s %5d: NXD         %d Domain lookup failed", lo.mode, lo.total, route)
			}
		} else {
			if *verbose {
				logger.Printf("%s %5d: ERR         %d Failed to dial server. Error: %s", lo.mode, lo.total, route, err)
			}
		}
		try <- 0
		return
	}
	if *verbose {
		logger.Printf("%s %5d:  *          %d TCP connection established", lo.mode, lo.total, route)
	}
	mu.Lock()
	open[route]++
	mu.Unlock()
	del := false
	defer func() {
		(*out).Close()
		mu.Lock()
		open[route]--
		mu.Unlock()
		if del {
			rt.del(lo.key, true, 0, 0)
			if *verbose {
				logger.Printf("%s %5d:          *  %d Deleted route to %s", lo.mode, lo.total, route, lo.key)
			}
		}
	}()

	if route == 1 && !re.ruleBased && *dnsOK && lo.mode == "H" && lo.host != "" {
		// dest is hostname, match IP rules before sending first byte if DNS is ok
		if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
			var newRoute int
			newRoute, re.ruleBased = matchIP(lo.total, lo.mode, tcpAddr.IP, lo.dport)
			switch newRoute {
			case 0:
			case 1:
				stop2 <- true
			case 2:
				try <- 0
				return
			default:
				stop2 <- true
				try <- 0
				return
			}
		}
	}

	// Send first byte to server
	if len(re.first) > 0 {
		(*out).SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		if _, err := (*out).Write(re.first); err != nil {
			if *verbose {
				logger.Printf("%s %5d: ERR         %d Failed to send first byte to server. Error: %s", lo.mode, lo.total, route, err)
			}
			try <- 0
			return
		}
		(*out).SetWriteDeadline(time.Time{})
	}
	sentTime := time.Now()

	// Wait for response from server
	firstIn := make([]byte, initialSize)
	var firstResp *http.Response
	bufOut := bufio.NewReader(*out)
	n := 0
	if re.firstIsFull {
		(*out).SetReadDeadline(time.Now().Add(time.Millisecond * 300))
	} else {
		(*out).SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
	}
	var ttfb time.Duration
	if lo.mode == "H" && re.firstReq != nil {
		firstResp, err = http.ReadResponse(bufOut, re.firstReq)
		ttfb = time.Since(sentTime)
	} else {
		n, err = bufOut.Read(firstIn)
		ttfb = time.Since(sentTime)
		if n > 0 && *verbose {
			logger.Printf("%s %5d:      *      %d First %d bytes from server. TTFB %d ms.", lo.mode, lo.total, route, n, ttfb.Milliseconds())
		}
		// Continue reading for a short period of time to detect delayed reset
		if err == nil && route == 1 && !re.ruleBased && n > 0 && n < initialSize {
			(*out).SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(*firstByteDelay)))
			var n1 int
			n1, err = io.ReadFull(bufOut, firstIn[n:])
			n += n1
			if err != nil && strings.Contains(err.Error(), "time") {
				err = nil
			}
		}
	}
	(*out).SetReadDeadline(time.Time{})

	if err != nil {
		// If request is only partially sent, timeout is normal
		if !re.firstIsFull || !strings.Contains(err.Error(), "time") {
			if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
				if *verbose {
					logger.Printf("%s %5d:     RST     %d First byte reset", lo.mode, lo.total, route)
				}
				/*if route == 1 && !re.ruleBased {
					if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
						if lo.host == "" || *dnsOK {
							logger.Printf("%s %5d:     ADD     %d TCP reset detected, %s %s port %s added to blocked list", lo.mode, lo.total, route, lo.host, tcpAddr.IP, lo.dport)
							blockedIPSet.add(tcpAddr.IP, lo.dport)
						} else {
							logger.Printf("%s %5d:     ADD     %d TCP reset detected, %s port %s added to blocked list", lo.mode, lo.total, route, lo.host, lo.dport)
						}
						blockedHostSet.add(lo.host, lo.dport)
					}
				}*/
			} else if strings.Contains(err.Error(), "time") {
				if *verbose {
					logger.Printf("%s %5d:     PSH     %d First byte timeout", lo.mode, lo.total, route)
				}
			} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if *verbose {
					logger.Printf("%s %5d:     FIN     %d First byte from server is EOF", lo.mode, lo.total, route)
				}
			} else if !strings.Contains(err.Error(), "closed") {
				if *verbose {
					logger.Printf("%s %5d:     ERR     %d Connection closed before receiving first byte. Error: %s", lo.mode, lo.total, route, err)
				}
			} else {
				if *verbose {
					logger.Printf("%s %5d:     ERR     %d Error in receiving first byte. Error: %s", lo.mode, lo.total, route, err)
				}
			}
			try <- 0
			return
		}
	} else {
		// If there is response, remove full flag
		re.firstIsFull = false
		if lo.mode == "H" && re.firstReq != nil {
			if *verbose {
				logger.Printf("H %5d:      *      %d HTTP Status %s Content-length %d. TTFB %d ms.", lo.total, route, firstResp.Status, firstResp.ContentLength, ttfb.Milliseconds())
			}
			if route == 1 && !re.ruleBased && httpRules.findRouteForText(firstResp.Status, false) == 2 {
				if *verbose {
					logger.Printf("%s %5d:      *      %d HTTP status in blocklist", lo.mode, lo.total, route)
				}
				try <- 0
				return
			}
		} else {
			if re.firstReq != nil {
				if resp, err := readResponseStatus(bufio.NewReader(bytes.NewReader(firstIn[:n]))); err == nil {
					if *verbose {
						logger.Printf("%s %5d:      *      %d HTTP Status %s", lo.mode, lo.total, route, resp.Status)
					}
					if route == 1 && !re.ruleBased && httpRules.findRouteForText(resp.Status, false) == 2 {
						if *verbose {
							logger.Printf("%s %5d:      *      %d HTTP status in blocklist", lo.mode, lo.total, route)
						}
						try <- 0
						return
					}
				} else {
					if *verbose {
						logger.Printf("%s %5d:     ERR     %d Bad HTTP response from %s. Error: %s", lo.mode, lo.total, route, lo.key, err)
					}
					if route == 1 && !re.ruleBased {
						try <- 0
						return
					}
				}
			}
			if re.tls {
				if n > recordHeaderLen && recordType(firstIn[0]) == recordTypeHandshake && firstIn[recordHeaderLen] == typeServerHello {
					// No need to parse length and send exactly one record because there could be multiple messages in one handshake record
					// Just remove trailing check in unmarshal functions
					if m := new(serverHelloMsg); m.unmarshal(firstIn[recordHeaderLen:n]) {
						if *verbose {
							logger.Printf("%s %5d:      *      %d %s Server Hello", lo.mode, lo.total, route, m.verString)
						}
					}
				} else if n > recordHeaderLen+1 && recordType(firstIn[0]) == recordTypeAlert {
					if *verbose {
						logger.Printf("%s %5d:     ERR     %d TLS Alert from %s: %s", lo.mode, lo.total, route, lo.key, alertText[alert(firstIn[recordHeaderLen+1])])
					}
				} else {
					if *verbose {
						logger.Printf("%s %5d:     ERR     %d Bad TLS handshake from %s", lo.mode, lo.total, route, lo.key)
					}
					if route == 1 && !re.ruleBased {
						try <- 0
						return
					}
				}
			}
		}
	}

	// Match IP rules after TLS and HTTP check if DNS is not OK and hostname is available
	if route == 1 && !re.ruleBased && !*dnsOK && lo.host != "" {
		if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
			var newRoute int
			newRoute, re.ruleBased = matchIP(lo.total, lo.mode, tcpAddr.IP, lo.dport)
			switch newRoute {
			case 0:
			case 1:
				stop2 <- true
			case 2:
				try <- 0
				return
			default:
				stop2 <- true
				try <- 0
				return
			}
		}
	}

	try <- server

	// Wait for signal to go ahead
	doServer := <-do
	do <- doServer
	if doServer == server {
		// Drain channel so that sender will not block
		defer func() {
			for len(re.reqs) > 0 {
				<-re.reqs
			}
			if !*fastSwitch {
				del = true
			}
		}()
		// Set last request time to sent time before writeing response to client
		// Do not set initially at client side as it's racy
		re.lastReq = sentTime
		if *verbose {
			logger.Printf("%s %5d:     CON     %d Continue %s %s -> %s", lo.mode, lo.total, route, (*out).LocalAddr().Network(), (*out).LocalAddr(), (*out).RemoteAddr())
		}
		if lo.mode == "H" && re.firstReq != nil {
			var totalBytes, accum int64
			accumStart := re.lastReq
			for {
				var resp *http.Response
				if firstResp != nil {
					resp = firstResp
					firstResp = nil
				} else {
					var err error
					if _, err = bufOut.ReadByte(); err == nil {
						if re.firstIsFull {
							bufOut.UnreadByte()
							resp, err = http.ReadResponse(bufOut, re.firstReq)
							re.firstIsFull = false
						} else if len(re.reqs) > 0 {
							bufOut.UnreadByte()
							resp, err = http.ReadResponse(bufOut, <-re.reqs)
						} else {
							err = errors.New("HTTP response received with no matching request")
						}
					}
					if err != nil {
						totalTime := time.Since(sentTime)
						if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "closed") {
							if *verbose {
								logger.Printf("H %5d:          *  %d Remote connection closed. Received %d bytes in %.1f s.", lo.total, route, totalBytes, totalTime.Seconds())
							}
							/*t := time.Since(re.lastReq).Seconds()
							if route == 1 && !re.ruleBased && t > 30 && totalBytes > 0 && totalBytes < 1000 {
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:         ERR %d Connection to %s %s likely cut off, %.1f s since last request", lo.total, route, lo.host, tcpAddr, t)
									/*logger.Printf("H %5d:         ADD %d Connection likely cut off, %.1f s since last request, %s %s added to blocked list", total, route, t, host, tcpAddr.IP)
									blockedIPSet.add(tcpAddr.IP)
									blockedHostSet.add(host)
								}
							}*/
						} else if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
							if *verbose {
								logger.Printf("H %5d:         RST %d Remote connection reset. Received %d bytes in %.1f s, %.1f s since last request. Error: %s", lo.total, route, totalBytes, totalTime.Seconds(), time.Since(re.lastReq).Seconds(), err)
							}
							if route == 1 && !re.ruleBased && totalTime.Seconds() < blockSafeTime {
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									if lo.host == "" || *dnsOK {
										logger.Printf("H %5d:         ADD %d TCP reset detected, %s %s port %s added to blocked list", lo.total, route, lo.host, tcpAddr.IP, lo.dport)
										blockedIPSet.add(tcpAddr.IP, lo.dport)
									} else {
										logger.Printf("H %5d:         ADD %d TCP reset detected, %s port %s added to blocked list", lo.total, route, lo.host, lo.dport)
									}
									blockedHostSet.add(lo.host, lo.dport)
								}
							}
							if tcp, ok := lo.conn.(*net.TCPConn); ok {
								tcp.SetLinger(0)
							}
						} else {
							if *verbose {
								logger.Printf("H %5d:         ERR %d Remote connection closed. Received %d bytes in %.1f s. Error: %s", lo.total, route, totalBytes, totalTime.Seconds(), err)
							}
						}
						mu.Lock()
						received[route] += totalBytes
						mu.Unlock()
						(*out).Close()
						if len(re.reqs) > 0 {
							lo.conn.Close()
						}
						return
					}
					if *verbose {
						logger.Printf("H %5d:      *      %d HTTP Status %s Content-length %d", lo.total, route, resp.Status, resp.ContentLength)
					}
				}
				header, _ := httputil.DumpResponse(resp, false)
				if !re.hasConnection {
					buf := bufio.NewReader(bytes.NewReader(header))
					c := []byte("Connection:")
					p := []byte("Proxy-")
					var h []byte
					for {
						line, err := buf.ReadSlice('\n')
						if err != nil {
							break
						}
						if bytes.HasPrefix(line, c) {
							h = append(h, p...)
							h = append(h, line...)
						} else {
							h = append(h, line...)
						}
					}
					header = h
				}
				_, err := lo.conn.Write(header)
				totalBytes += int64(len(header))
				if err != nil {
					if *verbose {
						logger.Printf("H %5d:     ERR     %d Failed to write HTTP header to client. Error: %s", lo.total, route, err)
					}
					totalBytes += int64(bufOut.Buffered())
					bufOut.Discard(bufOut.Buffered())
					(*out).Close()
					lo.conn.Close()
					continue
				}
				if accumStart.Before(re.lastReq) {
					accumStart = re.lastReq
					accum = 0
				}
				if resp.ContentLength == -1 && len(resp.TransferEncoding) > 0 && resp.TransferEncoding[0] == "chunked" {
					cr := newChunkedReader(bufOut)
					n, bytes, err := cr.copyTo(lo, *re, (*out).RemoteAddr(), route, accum)
					accum += bytes
					totalBytes += bytes
					if err == nil || errors.Is(err, io.EOF) {
						if *verbose {
							logger.Printf("H %5d:      *      %d Parsed %d chunks and %d bytes", lo.total, route, n, bytes)
						}
					} else {
						if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") ||
							strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") || errors.Is(err, io.ErrUnexpectedEOF) {
							if *verbose {
								logger.Printf("H %5d:     RST     %d Chunks parsing reset by server, %.1f s since last request. Error: %s", lo.total, route, time.Since(re.lastReq).Seconds(), err)
							}
							if route == 1 && !re.ruleBased {
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:     ADD     %d TCP reset detected, %s %s port %s added to blocked list", lo.total, route, lo.host, tcpAddr.IP, lo.dport)
									blockedIPSet.add(tcpAddr.IP, lo.dport)
									blockedHostSet.add(lo.host, lo.dport)
								}
							}
							if tcp, ok := lo.conn.(*net.TCPConn); ok {
								tcp.SetLinger(0)
							}
						} else {
							if *verbose {
								logger.Printf("H %5d:     ERR     %d Parsed %d chunks and %d bytes but failed to write to client. Error: %s", lo.total, route, n, bytes, err)
							}
						}
						totalBytes += int64(bufOut.Buffered())
						bufOut.Discard(bufOut.Buffered())
						(*out).Close()
						lo.conn.Close()
						continue
					}
					// Write trailer
					var trailer []byte
					for {
						line, err := bufOut.ReadSlice('\n')
						trailer = append(trailer, line...)
						totalBytes += int64(len(line))
						if len(line) == 2 || err != nil {
							lo.conn.Write(trailer)
							break
						}
					}
				} else if resp.ContentLength != 0 && resp.Request.Method != "HEAD" {
					bytes, err := re.writeTo(lo, resp.Body, true, (*out).RemoteAddr(), route, accum)
					accum += bytes
					totalBytes += bytes
					resp.Body.Close()
					if err != nil && !errors.Is(err, io.EOF) {
						// Linux: "read: connection reset by peer"
						// Windows: "wsarecv: An existing connection was forcibly closed by the remote host."
						if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") ||
							strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") || errors.Is(err, io.ErrUnexpectedEOF) {
							if *verbose {
								logger.Printf("H %5d:     RST     %d HTTP body fetching reset by server, %.1f s since last request. Error: %s", lo.total, route, time.Since(re.lastReq).Seconds(), err)
							}
							if route == 1 && !re.ruleBased {
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:     ADD     %d TCP reset detected, %s %s port %s added to blocked list", lo.total, route, lo.host, tcpAddr.IP, lo.dport)
									blockedIPSet.add(tcpAddr.IP, lo.dport)
									blockedHostSet.add(lo.host, lo.dport)
								}
							}
							if tcp, ok := lo.conn.(*net.TCPConn); ok {
								tcp.SetLinger(0)
							}
						} else {
							if *verbose {
								logger.Printf("H %5d:     ERR     %d Failed to write HTTP body to client. Error: %s", lo.total, route, err)
							}
						}
						totalBytes += int64(bufOut.Buffered())
						bufOut.Discard(bufOut.Buffered())
						(*out).Close()
						lo.conn.Close()
						continue
					}
				}
				if resp.Close {
					defer lo.conn.Close()
				}
			}
		} else {
			lo.conn.Write(firstIn[:n])
			bytes, err := re.writeTo(lo, bufOut, false, (*out).RemoteAddr(), route, int64(n))
			totalBytes := int64(n) + bytes + int64(bufOut.Buffered())
			totalTime := time.Since(sentTime)
			if err == nil || errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "time") {
				if *verbose {
					logger.Printf("%s %5d:          *  %d Remote connection closed. Received %d bytes in %.1f s.", lo.mode, lo.total, route, totalBytes, totalTime.Seconds())
				}
				//t := time.Since(re.lastReq).Seconds()
				/*if route == 1 && !re.ruleBased && re.tls && totalBytes == int64(n) && totalTime.Seconds() > 30 && !re.lastReq.Equal(sentTime) {
					if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
						if lo.host == "" || *dnsOK {
							logger.Printf("%s %5d:         ADD %d TLS handshake cut off, %s %s port %s added to blocked list", lo.mode, lo.total, route, lo.host, tcpAddr.IP, lo.dport)
							blockedIPSet.add(tcpAddr.IP, lo.dport)
						} else {
							logger.Printf("%s %5d:         ADD %d TLS handshake cut off, %s port %s added to blocked list", lo.mode, lo.total, route, lo.host, lo.dport)
						}
						blockedHostSet.add(lo.host, lo.dport)
					}
				} else if route == 1 && !re.ruleBased && t > 30 && totalBytes > 0 && totalBytes < 1000 {
					if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
						logger.Printf("%s %5d:         ERR %d Connection to %s %s likely cut off, %.1f s since last request", lo.mode, lo.total, route, lo.host, tcpAddr, t)
						/*logger.Printf("%s %5d:         ADD %d Connection likely cut off, %.1f s since last request, %s %s added to blocked list", mode, total, route, t, host, tcpAddr.IP)
						blockedIPSet.add(tcpAddr.IP)
						blockedHostSet.add(host)
					}
				}*/
			} else if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
				if *verbose {
					logger.Printf("%s %5d:         RST %d Remote connection reset. Received %d bytes in %.1f s, %.1f s since last request. Error: %s", lo.mode, lo.total, route, totalBytes, totalTime.Seconds(), time.Since(re.lastReq).Seconds(), err)
				}
				if route == 1 && !re.ruleBased && totalTime.Seconds() < blockSafeTime {
					if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
						if lo.host == "" || *dnsOK {
							logger.Printf("%s %5d:         ADD %d TCP reset detected, %s %s port %s added to blocked list", lo.mode, lo.total, route, lo.host, tcpAddr.IP, lo.dport)
							blockedIPSet.add(tcpAddr.IP, lo.dport)
						} else {
							logger.Printf("%s %5d:         ADD %d TCP reset detected, %s port %s added to blocked list", lo.mode, lo.total, route, lo.host, lo.dport)
						}
						blockedHostSet.add(lo.host, lo.dport)
					}
				}
				if tcp, ok := lo.conn.(*net.TCPConn); ok {
					tcp.SetLinger(0)
				}
			} else {
				if *verbose {
					logger.Printf("%s %5d:         ERR %d Remote connection closed. Received %d bytes in %.1f s. Error: %s", lo.mode, lo.total, route, totalBytes, totalTime.Seconds(), err)
				}
			}
			mu.Lock()
			received[route] += totalBytes
			mu.Unlock()
			lo.conn.Close()
		}
	}
}

func matchHost(total int, mode, host, port string) (route int, ruleBased bool) {
	if hostRules.rules != nil {
		route = hostRules.findRouteForText(host, true)
		if route != 0 {
			if *verbose {
				logger.Printf("%s %5d: RUL           Host rule matched for %s. Select route %d", mode, total, host, route)
			}
			ruleBased = true
			return
		}
	}
	if blockedHostSet.find(host, port, false) {
		route = 2
		if *verbose {
			logger.Printf("%s %5d: SET           Host %s port %s found in blocked list. Select route %d", mode, total, host, port, route)
		}
		return
	}
	if slowHostSet.find(host, port, false) {
		route = 2
		if *verbose {
			logger.Printf("%s %5d: SET           Host %s port %s found in slow list. Select route %d", mode, total, host, port, route)
		}
		return
	}
	return
}

func matchIP(total int, mode string, ip net.IP, port string) (route int, ruleBased bool) {
	if ipRules.rules != nil {
		route = ipRules.findRouteForIP(ip)
		if route != 0 {
			if *verbose {
				logger.Printf("%s %5d: RUL           IP rule matched for %s. Select route %d", mode, total, ip, route)
			}
			ruleBased = true
			return
		}
	}
	if blockedIPSet.find(ip, port, false) {
		route = 2
		if *verbose {
			logger.Printf("%s %5d: SET           IP %s port %s found in blocked list. Select route %d", mode, total, ip, port, route)
		}
		return
	}
	if slowIPSet.find(ip, port, false) {
		route = 2
		if *verbose {
			logger.Printf("%s %5d: SET           IP %s port %s found in slow list. Select route %d", mode, total, ip, port, route)
		}
		return
	}
	return
}

func (re *remoteConn) writeTo(lo localConn, out io.Reader, single bool, addr net.Addr, route int, lastBytes int64) (bytes int64, err error) {
	if route == 1 && *slowSpeed > 0 && !re.ruleBased && contain(chkPorts, lo.dport) {
		var sample int64
		sampleStart := time.Now()
		req := lastBytes
		reqStart := re.lastReq
		sessionStart := re.lastReq
		var slow, added bool
		var speed, aveSpeed, totalSpeed, reqTime float64
		var recovered int
		for {
			p := make([]byte, bufferSize)
			var n int
			n, err = out.Read(p)
			bytes += int64(n)
			d := time.Since(sessionStart)
			if d > 0 {
				totalSpeed = float64(bytes) / 1000 / time.Since(sessionStart).Seconds()
			}
			if sampleStart.Before(re.lastReq) {
				sampleStart = re.lastReq
				sample = 0
			}
			if !single && reqStart.Before(re.lastReq) {
				reqStart = re.lastReq
				req = 0
			}
			t := time.Now()
			if err == nil {
				_, err = lo.conn.Write(p[:n])
			} else if bytes > 0 {
				lo.conn.Write(p[:n])
			}
			d = time.Since(t)
			sampleStart = sampleStart.Add(d)
			reqStart = reqStart.Add(d)
			if err != nil {
				break
			}
			if !added && slow {
				logger.Printf("%s %5d:     SLO     %d Slow connection to %s %s at %.1f kB/s, %.1f kB/s since last request, %.1f kB/s overall", lo.mode, lo.total, route, lo.host, addr, speed, aveSpeed, totalSpeed)
				if tcpAddr := addr.(*net.TCPAddr); tcpAddr != nil && !*slowDry {
					slowIPSet.add(tcpAddr.IP, "")
					slowHostSet.add(lo.host, "")
					if *slowClose {
						lo.conn.Close()
					}
				}
				added = true
			}
			sample += int64(n)
			req += int64(n)
			// If n = bufferSize, either connection is too fast or client is slow
			if n < bufferSize {
				sampleTime := time.Since(sampleStart).Seconds()
				reqTime = time.Since(reqStart).Seconds()
				if sampleTime > 0 && reqTime > 0 {
					speed = float64(sample) / 1000 / sampleTime
					aveSpeed = float64(req) / 1000 / reqTime
					if sampleTime > minSampleInterval {
						if sampleTime < maxSampleInterval {
							if (totalSpeed < float64(*slowSpeed) && aveSpeed < float64(*slowSpeed) && speed < float64(*slowSpeed) || speed < float64(*slowSpeed)*0.3) && aveSpeed > minSpeed && totalSpeed > minSpeed {
								// Set flag to add to list only if this read is not the final one
								slow = true
								// Reset recovery counter
								recovered = 0
							}
						}
						sampleStart = time.Now()
						sample = 0
					}
					if slow && reqTime > 0.2 && aveSpeed > float64(*slowSpeed)*1.2 && speed > float64(*slowSpeed) {
						recovered += 1
						// Remove from slow list if speed has recovered for 3 consecutive sampling periods
						if recovered >= 3 {
							logger.Printf("%s %5d:     SLO     %d Speed to %s %s recovered to %.1f kB/s, %.1f kB/s since last request, %.1f kB/s overall", lo.mode, lo.total, route, lo.host, addr, speed, aveSpeed, totalSpeed)
							slow = false
							added = false
							if tcpAddr := addr.(*net.TCPAddr); tcpAddr != nil && !*slowDry {
								slowIPSet.find(tcpAddr.IP, "", true)
								slowHostSet.find(lo.host, "", true)
							}
						}
					}
				}
			}
		}
	} else {
		bytes, err = io.Copy(lo.conn, out)
	}
	return
}

func contain(strs []string, s string) bool {
	for _, v := range strs {
		if v == s {
			return true
		}
	}
	return false
}
