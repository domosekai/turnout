// Released under MIT License
// Copyright (c) 2020 domosekai

// Relay functions for both modes

package main

import (
	"bufio"
	"bytes"
	"context"
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

func NewRemoteConnectionFor(lo *localConn) *remoteConn {
	re := &remoteConn{
		mode:    lo.mode,
		network: lo.network,
		total:   lo.total,
		dest:    lo.dest,
		dport:   lo.dport,
		done:    make(chan struct{}),
	}

	if net.ParseIP(lo.dest) == nil {
		re.host = lo.dest
	}

	return re
}

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

	// Set a shorter timeout for subsequent reads
	lo.conn.SetReadDeadline(time.Now().Add(time.Second))

	// Prepare remote connection
	re := NewRemoteConnectionFor(lo)
	re.firstIsFull = true
	re.successive = true

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
			var n2 int
			n2, err = io.ReadFull(lo.buf, buf)
			if n2 > 0 {
				if n+n2 > initialSize {
					first = append(first[:n], buf[:n2]...)
				} else {
					copy(first[n:], buf[:n2])
				}
				n += n2
				if *verbose {
					logger.Printf("%s %5d:  *            Another %d bytes from client", lo.mode, lo.total, n2)
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
						re.host = host
					}
				} else if m.esni {
					if *verbose {
						logger.Printf("%s %5d:  *            %s ESNI", lo.mode, lo.total, m.verString)
					}
				} else if m.ech {
					if *verbose {
						logger.Printf("%s %5d:  *            %s ECH", lo.mode, lo.total, m.verString)
					}
				} else {
					if *verbose {
						logger.Printf("%s %5d:  *            %s Client Hello", lo.mode, lo.total, m.verString)
					}
				}
				if m.earlyData {
					if *verbose {
						logger.Printf("%s %5d:  *            %s Early Data", lo.mode, lo.total, m.verString)
					}
				}
				re.tls = true
				re.firstIsFull = false
				if !m.earlyData {
					re.successive = false
				}
			}
		}

	} else if n > 0 {

		if n < initialSize {
			re.firstIsFull = false
		}

		// Make a concatenated reader
		second := new(bytes.Buffer)
		tee := io.TeeReader(lo.buf, second)
		rd := io.MultiReader(bytes.NewReader(first[:n]), tee)

		// HTTP
		req, err := http.ReadRequest(bufio.NewReader(rd))
		n2 := second.Len()
		if n2 > 0 {
			if n+n2 > initialSize {
				first = append(first[:n], second.Bytes()...)
			} else {
				copy(first[n:], second.Bytes())
			}
			n += n2
			if *verbose {
				logger.Printf("%s %5d:  *            Another %d bytes from client", lo.mode, lo.total, n2)
			}
		}

		if err == nil {
			if *verbose {
				logger.Printf("%s %5d:  *            HTTP %s Host %s Content-length %d", lo.mode, lo.total, req.Method, req.Host, req.ContentLength)
			}
			if host, _ := normalizeHostname(req.Host, lo.dport); net.ParseIP(host) == nil {
				re.host = host
			}
			re.http = true
			if req.ContentLength != 0 {
				re.firstIsFull = true
			}
		}

	} else {
		// assume server should send something first if client is silent (e.g. SMTP)
		re.firstIsFull = false
		re.successive = false
	}

	if n > 0 && n < initialSize && !re.tls && !re.http {
		// read within time limit, do nothing if a second read has timed out
		n1, _ := io.ReadFull(lo.buf, first[n:])
		n += n1
		if n < initialSize {
			re.firstIsFull = false
		}
	}

	lo.conn.SetReadDeadline(time.Time{})

	// Reverse lookup for hostname
	if re.host == "" {
		if ip := net.ParseIP(lo.dest); ip != nil {
			if host := getHostnameFromIP(ip); host != "" {
				if *verbose {
					logger.Printf("%s %5d:  *            Hostname resolved to %s", lo.mode, lo.total, host)
				}
				re.host = host
			}
		}
	}

	re.first = first[:n]
	if re.getRouteFor(lo.conn) {
		re.relayLocalFor(lo.buf)
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

func (re *remoteConn) getRouteFor(loConn net.Conn) bool {
	mu.Lock()
	jobs[0]++
	mu.Unlock()
	defer func() {
		mu.Lock()
		jobs[0]--
		mu.Unlock()
	}()

	type workerInfo struct {
		srv *server
	}

	type workerGroup struct {
		workers []workerInfo
		start   chan bool
	}

	// Prefer hostname to IP as routing key
	var key string
	if re.host != "" {
		key = net.JoinHostPort(re.host, re.dport)
	} else {
		key = net.JoinHostPort(re.dest, re.dport)
	}

	// Match rules
	var matchedRoutes []int
	if re.host != "" {
		matchedRoutes, re.ruleBased = matchHost(re.total, re.mode, re.host, re.dport)
	}
	if len(matchedRoutes) == 0 {
		if ip := net.ParseIP(re.dest); ip != nil {
			// dest is IP, match IP rules if host hasn't matched
			matchedRoutes, re.ruleBased = matchIP(re.total, re.mode, ip, re.dport)
		} else {
			// dest is hostname
			if re.host != re.dest {
				matchedRoutes, re.ruleBased = matchHost(re.total, re.mode, re.dest, re.dport)
			}

			// resolve hostname to IP if no host rules matched
			if len(matchedRoutes) == 0 {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(dnsTimeout))
				network := "ip"
				if servers[0].force4 {
					network = "ip4"
				}

				ips, err := net.DefaultResolver.LookupIP(ctx, network, re.dest)
				cancel()

				if err != nil || len(ips) == 0 {
					if *verbose {
						logger.Printf("%s %5d: NXD           DNS resolution failed for %s", re.mode, re.total, re.dest)
					}
					return false
				}

				if *verbose {
					logger.Printf("%s %5d:  *            IP address resolved to %v", re.mode, re.total, ips[0])
				}

				matchedRoutes, re.ruleBased = matchIP(re.total, re.mode, ips[0], re.dport)
				re.resolvedIP = ips[0].String()
			}
		}
	}

	// Validate all routes exist
	for _, r := range matchedRoutes {
		if r < 0 || (r != 0 && routes[r] == nil) {
			if *verbose {
				logger.Printf("%s %5d:  *            Route to %s is invalid or blocked", re.mode, re.total, key)
			}
			return false
		}
	}

	// Get existing route or a locked route
	var entry *routeEntry
	var existSrv *server
	if !*fastSwitch {
		// We match the first route only, or blocked route may fail to work.
		// For example, blocked route [2 1] always matches route 1.
		route := 0
		if len(matchedRoutes) > 0 {
			route = matchedRoutes[0]
		}
		if r, s, e, n := rt.addOrLock(key, route); e {
			// When existing, r can't be 0
			matchedRoutes = []int{r}
			existSrv = servers[s]
			if *verbose {
				logger.Printf("%s %5d: EXT           Connections to %s exist. Select route %d server %d", re.mode, re.total, key, r, s)
			}
			entry = n
		} else {
			entry = n
		}
	}

	// Build worker groups (flat slice)
	var groups []workerGroup
	var priority *workerInfo
	totalWorkers := 0

	if len(matchedRoutes) == 0 {
		// Race mode
		primary := routes[autoCfg.Primary]
		secondary := routes[autoCfg.Secondary]
		directSrv := primary.tiers[0][0]

		if !re.successive {
			// Parallel: merge direct + secondary tier 0 into one group, direct prioritized
			g0 := workerGroup{start: make(chan bool, 1)}
			g0.workers = append(g0.workers, workerInfo{directSrv})

			for _, srv := range secondary.tiers[0] {
				g0.workers = append(g0.workers, workerInfo{srv})
			}
			priority = &g0.workers[0] // must be after appending
			groups = append(groups, g0)
			totalWorkers += len(g0.workers)

			// Remaining secondary tiers
			for ti := 1; ti < len(secondary.tiers); ti++ {
				g := workerGroup{start: make(chan bool, 1)}
				for _, srv := range secondary.tiers[ti] {
					g.workers = append(g.workers, workerInfo{srv})
				}
				groups = append(groups, g)
				totalWorkers += len(g.workers)
			}
		} else {
			// Successive: separate groups, no priority
			groups = append(groups, workerGroup{
				workers: []workerInfo{{directSrv}},
				start:   make(chan bool, 1),
			})
			totalWorkers++

			for _, tier := range secondary.tiers {
				for _, srv := range tier {
					groups = append(groups, workerGroup{
						workers: []workerInfo{{srv}},
						start:   make(chan bool, 1),
					})
					totalWorkers++
				}
			}
		}
	} else {
		// Specific matched routes
		if existSrv != nil {
			// Use existing server (addOrLock already validated it)
			groups = append(groups, workerGroup{
				workers: []workerInfo{{existSrv}},
				start:   make(chan bool, 1),
			})
			totalWorkers++
		} else {
			// Build groups for all routes in fallback order
			for _, routeID := range matchedRoutes {
				rc := routes[routeID]
				if rc.direct {
					srv := rc.tiers[0][0]
					groups = append(groups, workerGroup{
						workers: []workerInfo{{srv}},
						start:   make(chan bool, 1),
					})
					totalWorkers++
				} else if re.successive {
					for _, tier := range rc.tiers {
						for _, srv := range tier {
							groups = append(groups, workerGroup{
								workers: []workerInfo{{srv}},
								start:   make(chan bool, 1),
							})
							totalWorkers++
						}
					}
				} else {
					for _, tier := range rc.tiers {
						g := workerGroup{start: make(chan bool, 1)}
						for _, srv := range tier {
							g.workers = append(g.workers, workerInfo{srv})
						}
						groups = append(groups, g)
						totalWorkers += len(g.workers)
					}
				}
			}
		}
	}

	// Create channels
	try := make(chan routeResult, totalWorkers)
	do := make(chan doSignal, 1)

	// Dispatch all workers
	for _, g := range groups {
		for _, w := range g.workers {
			go re.handleRemote(loConn, key, w.srv, g.start, try, do)
		}
	}

	// Start first group
	groups[0].start <- true

	// Wait for first byte from server
	timer1 := time.NewTimer(time.Second * time.Duration(autoCfg.Priority))
	timer2 := time.NewTimer(time.Second * time.Duration(totalTimeout))
	currentGroup := 0
	failedInGroup := 0
	priorityExpired := false
	priorityFailed := false
	var winSrv *server
	var winOut net.Conn

	// Helper to use a winning server
	useWinner := func(srv *server, out net.Conn) bool {
		if !*fastSwitch {
			if existSrv == nil {
				if *verbose {
					logger.Printf("%s %5d:     NEW     %d Save route %d server %d for %s", re.mode, re.total, srv.route, srv.route, srv.id, key)
				}
				entry.save(srv.route, srv.id)
			} else {
				if entry.reset(srv.route, srv.id) {
					if *verbose {
						logger.Printf("%s %5d:      *      %d Reset counter for %s", re.mode, re.total, srv.route, key)
					}
				}
			}
		}
		re.srv = srv
		re.conn = out
		do <- doSignal{srv}
		return true
	}

	// Helper to move to next group
	advanceGroup := func() bool {
		if currentGroup < len(groups)-1 {
			currentGroup++
			failedInGroup = 0
			groups[currentGroup].start <- true
			return true
		}
		return false
	}

	// Helper to abort when no route is available
	abortNoRoute := func() {
		if !*fastSwitch {
			if existSrv == nil {
				if len(re.first) > 0 {
					logger.Printf("%s %5d:     ERR       No available route to %s", re.mode, re.total, key)
				}
				rt.unlock(key, entry)
			} else {
				if len(re.first) > 0 {
					logger.Printf("%s %5d:     ERR     %d Existing route to %s failed", re.mode, re.total, existSrv.route, key)
				}
				rt.del(key, false, existSrv.route, existSrv.id)
			}
		} else {
			if len(re.first) > 0 {
				logger.Printf("%s %5d:     ERR       No available route to %s", re.mode, re.total, key)
			}
		}
	}

	for {
		select {
		case sig := <-try:
			isPriority := priority != nil && sig.srv == priority.srv
			if sig.ok {
				// Worker succeeded
				if isPriority || priority == nil || priorityExpired || priorityFailed {
					// Use immediately
					return useWinner(sig.srv, sig.out)
				} else if winSrv == nil {
					// Store as pending (only first one, unless stopped)
					winSrv = sig.srv
					winOut = sig.out
				}
			} else {
				// Worker failed
				if isPriority {
					priorityFailed = true
					if winSrv != nil {
						return useWinner(winSrv, winOut)
					}

					// Do not count failure if not the first group
					if currentGroup == 0 {
						failedInGroup++
					}
				} else {
					failedInGroup++
				}

				g := groups[currentGroup]

				// Advance to next group even if priority is still pending
				if failedInGroup >= len(g.workers) || currentGroup == 0 && priority != nil && !priorityFailed && failedInGroup >= len(g.workers)-1 {
					if !advanceGroup() && (priority == nil || priorityFailed) {
						// All groups exhausted (including priority if any), abort
						//do <- doSignal{nil} // No need to send signal, all workers are done
						abortNoRoute()
						return false
					}
				}
			}
		case <-timer1.C:
			priorityExpired = true
			if winSrv != nil {
				return useWinner(winSrv, winOut)
			}
		case <-timer2.C:
			do <- doSignal{nil}
			abortNoRoute()
			return false
		}
	}
}

func (re *remoteConn) relayLocalFor(buf io.Reader) {
	totalBytes := int64(len(re.first))
	var err error
	for {
		p := make([]byte, bufferSize)
		var bytes int
		bytes, err = buf.Read(p)
		if err == nil {
			bytes, err = re.conn.Write(p[:bytes])
		} else {
			bytes, _ = re.conn.Write(p[:bytes])
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
			logger.Printf("%s %5d:          *    Local connection closed. Sent %d bytes.", re.mode, re.total, totalBytes)
		}
	} else if strings.Contains(err.Error(), "reset") {
		if *verbose {
			logger.Printf("%s %5d:          *    Local connection reset. Sent %d bytes.", re.mode, re.total, totalBytes)
		}
		if tcp, ok := re.conn.(*net.TCPConn); ok {
			tcp.SetLinger(0)
		}
	} else {
		if *verbose {
			logger.Printf("%s %5d:         ERR   Local connection closed. Sent %d bytes. Error: %s", re.mode, re.total, totalBytes, err)
		}
	}
	mu.Lock()
	sent[re.srv.route] += totalBytes
	mu.Unlock()
	re.conn.Close()
}

func (re *remoteConn) handleRemote(loConn net.Conn, key string, srv *server, start chan bool, try chan routeResult, do chan doSignal) {
	mu.Lock()
	jobs[srv.route]++
	mu.Unlock()

	select {
	case <-start:
		start <- true // put back for next worker
		out, firstResp, firstIn, bufOut, sentTime, ok := re.fetchResponse(loConn, srv)
		try <- routeResult{ok, srv, out}

		if ok {
			mu.Lock()
			open[srv.route]++
			mu.Unlock()

			// Wait for signal to go ahead
			sig := <-do
			do <- sig
			if sig.srv == srv {
				re.lastReq = sentTime
				if *verbose {
					logger.Printf("%s %5d:     CON     %d Continue %s %s -> %s", re.mode, re.total, srv.route, out.LocalAddr().Network(), out.LocalAddr(), out.RemoteAddr())
				}

				re.relayConnection(loConn, srv.route, sentTime, firstResp, firstIn, bufOut)

				if *verbose {
					logger.Printf("%s %5d:          *  %d Relay from %s completed", re.mode, re.total, srv.route, out.RemoteAddr())
				}

				if !*fastSwitch {
					rt.del(key, true, 0, 0)
					if *verbose {
						logger.Printf("%s %5d:          *  %d Deleted route to %s", re.mode, re.total, srv.route, key)
					}
				}
			}

			out.Close()
			mu.Lock()
			open[srv.route]--
			mu.Unlock()
		} else {
			if out != nil {
				out.Close()
			}
		}
	case sig := <-do:
		do <- sig
	}

	mu.Lock()
	jobs[srv.route]--
	mu.Unlock()
}

func (re *remoteConn) fetchResponse(loConn net.Conn, srv *server) (out net.Conn, firstResp *http.Response, firstIn []byte, bufOut *bufio.Reader, sentTime time.Time, ok bool) {
	var dest string
	var err error
	if srv.addr == nil {
		// Direct route
		network := re.network
		if srv.force4 {
			network = "tcp4"
		}
		if re.resolvedIP != "" {
			dest = net.JoinHostPort(re.resolvedIP, re.dport)
		} else {
			dest = net.JoinHostPort(re.dest, re.dport)
		}
		if *verbose {
			logger.Printf("%s %5d:  *          %d Dialing to %s %s", re.mode, re.total, srv.route, network, dest)
		}
		// it's possible to use client's address as source but we need to fix the return route
		// useful when turnout is sitting between client and upstream
		dialer := &net.Dialer{
			Timeout: time.Second * time.Duration(srv.timeout),
			//LocalAddr: lo.source,
			//Control:   transparentControl,
		}
		out, err = dialer.Dial(network, dest)
	} else if srv.addr.Scheme == "socks5" {
		// SOCKS5
		addr := srv.addr.Host
		var dialer proxy.Dialer
		var auth *proxy.Auth
		if srv.addr.User != nil {
			auth = new(proxy.Auth)
			auth.User = srv.addr.User.Username()
			// replace username with client IP if it's "CLIENT_IP"
			if auth.User == "CLIENT_IP" {
				switch addr := loConn.RemoteAddr().(type) {
				case *net.TCPAddr:
					auth.User = addr.IP.String()
				case *net.UDPAddr:
					auth.User = addr.IP.String()
				}
			}
			if p, ok := srv.addr.User.Password(); ok {
				auth.Password = p
			}
		}
		dialer, err = proxy.SOCKS5("tcp", addr, auth, &net.Dialer{Timeout: time.Second * time.Duration(srv.timeout)})
		if err != nil {
			logger.Printf("%s %5d: ERR         %d Failed to dial server %s. Error: %s", re.mode, re.total, srv.route, addr, err)
			return
		}
		if re.host != "" {
			dest = net.JoinHostPort(re.host, re.dport)
		} else {
			dest = net.JoinHostPort(re.dest, re.dport)
		}
		if *verbose {
			logger.Printf("%s %5d:  *          %d Dialing to %s via %s", re.mode, re.total, srv.route, dest, addr)
		}
		out, err = dialer.Dial("tcp", dest)
	} else {
		// HTTP or HTTPS
		addr := srv.addr.Host
		var auth http_dialer.ProxyAuthorization
		if srv.addr.User != nil {
			user := srv.addr.User.Username()
			password, _ := srv.addr.User.Password()
			auth = http_dialer.AuthBasic(user, password)
		}
		// Optional TLS configuration
		tlsConfig := tls.Config{
			//			MinVersion: tls.VersionTLS10,
			//			NextProtos: []string{"http/1.1"},
		}
		dialer := http_dialer.New(srv.addr,
			http_dialer.WithProxyAuth(auth),
			http_dialer.WithTls(&tlsConfig),
			http_dialer.WithConnectionTimeout(time.Second*time.Duration(srv.timeout)))
		if re.host != "" {
			dest = net.JoinHostPort(re.host, re.dport)
		} else {
			dest = net.JoinHostPort(re.dest, re.dport)
		}
		if *verbose {
			logger.Printf("%s %5d:  *          %d Dialing to %s via %s", re.mode, re.total, srv.route, dest, addr)
		}
		// HTTP dialer only accepts tcp as network
		out, err = dialer.Dial("tcp", dest)
	}
	if err != nil {
		if strings.Contains(err.Error(), "time") || strings.Contains(err.Error(), "host unreachable") {
			if *verbose {
				logger.Printf("%s %5d: SYN         %d Initial connection timeout", re.mode, re.total, srv.route)
			}
		} else if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "EOF") {
			// Linux: "connect: connection refused"
			// Windows: "connectex: No connection could be made because the target machine actively refused it."
			if *verbose {
				logger.Printf("%s %5d: FIN         %d Initial connection refused", re.mode, re.total, srv.route)
			}
		} else if strings.Contains(err.Error(), "no such host") {
			if *verbose {
				logger.Printf("%s %5d: NXD         %d DNS resolution failed", re.mode, re.total, srv.route)
			}
		} else {
			if *verbose {
				logger.Printf("%s %5d: ERR         %d Failed to dial server. Error: %s", re.mode, re.total, srv.route, err)
			}
		}
		return
	}
	if *verbose {
		logger.Printf("%s %5d:  *          %d TCP connection established", re.mode, re.total, srv.route)
	}

	// Send first byte to server
	if len(re.first) > 0 {
		out.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(srv.timeout)))
		if _, err := out.Write(re.first); err != nil {
			if *verbose {
				logger.Printf("%s %5d: ERR         %d Failed to send first byte to server. Error: %s", re.mode, re.total, srv.route, err)
			}
			return
		}
		out.SetWriteDeadline(time.Time{})
	}
	sentTime = time.Now()

	// Wait for response from server
	firstIn = make([]byte, initialSize)
	bufOut = bufio.NewReader(out)
	n := 0
	if re.firstIsFull {
		out.SetReadDeadline(time.Now().Add(time.Millisecond * 300))
	} else {
		out.SetReadDeadline(time.Now().Add(time.Second * time.Duration(srv.timeout)))
	}
	var ttfb time.Duration
	if re.mode == "H" && re.firstReq != nil {
		firstResp, err = http.ReadResponse(bufOut, re.firstReq)
		ttfb = time.Since(sentTime)
	} else {
		n, err = bufOut.Read(firstIn)
		ttfb = time.Since(sentTime)
		if n > 0 && *verbose {
			logger.Printf("%s %5d:      *      %d First %d bytes from server. TTFB %d ms.", re.mode, re.total, srv.route, n, ttfb.Milliseconds())
		}
		// Continue reading for a short period of time to detect delayed reset
		if err == nil && srv.route == 1 && !re.ruleBased && n > 0 && n < initialSize {
			out.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(*firstByteDelay)))
			var n1 int
			n1, err = io.ReadFull(bufOut, firstIn[n:])
			n += n1
			if err != nil && strings.Contains(err.Error(), "time") {
				err = nil
			}
		}
	}
	out.SetReadDeadline(time.Time{})

	if err != nil {
		// If request is only partially sent, timeout is normal
		if !re.firstIsFull || !strings.Contains(err.Error(), "time") {
			if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
				if *verbose {
					logger.Printf("%s %5d:     RST     %d First byte reset", re.mode, re.total, srv.route)
				}
				/*if srv.route == 1 && !re.ruleBased {
					if tcpAddr := out.RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
						if re.host == "" || *dnsOK {
							logger.Printf("%s %5d:     ADD     %d TCP reset detected, %s %s port %s added to blocked list", re.mode, re.total, srv.route, re.host, tcpAddr.IP, re.dport)
							blockedIPSet.add(tcpAddr.IP, re.dport)
						} else {
							logger.Printf("%s %5d:     ADD     %d TCP reset detected, %s port %s added to blocked list", re.mode, re.total, srv.route, re.host, re.dport)
						}
						blockedHostSet.add(re.host, re.dport)
					}
				}*/
			} else if strings.Contains(err.Error(), "time") {
				if *verbose {
					logger.Printf("%s %5d:     PSH     %d First byte timeout", re.mode, re.total, srv.route)
				}
			} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if *verbose {
					logger.Printf("%s %5d:     FIN     %d First byte from server is EOF", re.mode, re.total, srv.route)
				}
			} else if !strings.Contains(err.Error(), "closed") {
				if *verbose {
					logger.Printf("%s %5d:     ERR     %d Connection closed before receiving first byte. Error: %s", re.mode, re.total, srv.route, err)
				}
			} else {
				if *verbose {
					logger.Printf("%s %5d:     ERR     %d Error in receiving first byte. Error: %s", re.mode, re.total, srv.route, err)
				}
			}
			return
		}
	} else {
		// If there is response, remove full flag
		re.firstIsFull = false
		if re.mode == "H" && re.firstReq != nil {
			if *verbose {
				logger.Printf("H %5d:      *      %d HTTP Status %s Content-length %d. TTFB %d ms.", re.total, srv.route, firstResp.Status, firstResp.ContentLength, ttfb.Milliseconds())
			}
			if srv.route == 1 && !re.ruleBased && len(httpRules.findRouteForText(firstResp.Status, false)) > 0 {
				if *verbose {
					logger.Printf("%s %5d:      *      %d HTTP status in blocklist", re.mode, re.total, srv.route)
				}
				return
			}
		} else {
			if re.http {
				if resp, err := readResponseStatus(bufio.NewReader(bytes.NewReader(firstIn[:n]))); err == nil {
					if *verbose {
						logger.Printf("%s %5d:      *      %d HTTP Status %s", re.mode, re.total, srv.route, resp.Status)
					}
					if srv.route == 1 && !re.ruleBased && len(httpRules.findRouteForText(resp.Status, false)) > 0 {
						if *verbose {
							logger.Printf("%s %5d:      *      %d HTTP status in blocklist", re.mode, re.total, srv.route)
						}
						return
					}
				} else {
					if *verbose {
						logger.Printf("%s %5d:     ERR     %d Bad HTTP response from %s. Error: %s", re.mode, re.total, srv.route, dest, err)
					}
					if srv.route == 1 && !re.ruleBased {
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
							logger.Printf("%s %5d:      *      %d %s Server Hello", re.mode, re.total, srv.route, m.verString)
						}
					}
				} else if n > recordHeaderLen+1 && recordType(firstIn[0]) == recordTypeAlert {
					if *verbose {
						logger.Printf("%s %5d:     ERR     %d TLS Alert from %s: %s", re.mode, re.total, srv.route, dest, alertText[alert(firstIn[recordHeaderLen+1])])
					}
				} else {
					if *verbose {
						logger.Printf("%s %5d:     ERR     %d Bad TLS handshake from %s", re.mode, re.total, srv.route, dest)
					}
					if srv.route == 1 && !re.ruleBased {
						return
					}
				}
			}
		}
	}

	firstIn = firstIn[:n]
	ok = true
	return
}

func (re *remoteConn) relayConnection(loConn net.Conn, route int, sentTime time.Time, firstResp *http.Response, firstIn []byte, bufOut *bufio.Reader) {
	if re.mode == "H" && re.firstReq != nil {
		defer func() {
			for range re.reqs {
				// Drain channel so that sender will not block
			}
			// notify client
			close(re.done)
		}()

		// Proxy responses need to be parsed one by one
		var totalBytes, accum int64
		accumStart := re.lastReq
		for {
			var resp *http.Response
			if firstResp != nil {
				resp = firstResp
				firstResp = nil
			} else {
				// We must have a request before reading response
				var req *http.Request
				if re.firstIsFull {
					req = re.firstReq
					re.firstIsFull = false
				} else {
					r, ok := <-re.reqs
					if !ok {
						// client is waiting for our close (switching host)
						re.conn.Close()
						bufOut.Discard(bufOut.Buffered())
					} else {
						req = r
					}
				}

				var err error
				resp, err = http.ReadResponse(bufOut, req)
				if err != nil {
					totalTime := time.Since(sentTime)
					if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "closed") {
						if *verbose {
							logger.Printf("H %5d:          *  %d Remote connection closed. Received %d bytes in %.1f s.", re.total, route, totalBytes, totalTime.Seconds())
						}
						/*t := time.Since(re.lastReq).Seconds()
						if route == 1 && !re.ruleBased && t > 30 && totalBytes > 0 && totalBytes < 1000 {
							if tcpAddr := out.RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
								logger.Printf("H %5d:         ERR %d Connection to %s %s likely cut off, %.1f s since last request", re.total, route, re.host, tcpAddr, t)
								/*logger.Printf("H %5d:         ADD %d Connection likely cut off, %.1f s since last request, %s %s added to blocked list", total, route, t, host, tcpAddr.IP)
								blockedIPSet.add(tcpAddr.IP)
								blockedHostSet.add(host)
							}
						}*/
					} else if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
						if *verbose {
							logger.Printf("H %5d:         RST %d Remote connection reset. Received %d bytes in %.1f s, %.1f s since last request. Error: %s", re.total, route, totalBytes, totalTime.Seconds(), time.Since(re.lastReq).Seconds(), err)
						}
						if route == 1 && !re.ruleBased && totalTime.Seconds() < blockSafeTime {
							if tcpAddr := re.conn.RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
								if re.host == "" {
									logger.Printf("H %5d:         ADD %d TCP reset detected, %s port %s added to blocked list", re.total, route, tcpAddr.IP, re.dport)
									blockedIPSet.add(tcpAddr.IP, re.dport)
								} else {
									logger.Printf("H %5d:         ADD %d TCP reset detected, %s port %s added to blocked list", re.total, route, re.host, re.dport)
									blockedHostSet.add(re.host, re.dport)
								}
							}
						}
						if tcp, ok := loConn.(*net.TCPConn); ok {
							tcp.SetLinger(0)
						}
					} else {
						if *verbose {
							logger.Printf("H %5d:         ERR %d Remote connection closed. Received %d bytes in %.1f s. Error: %s", re.total, route, totalBytes, totalTime.Seconds(), err)
						}
					}

					mu.Lock()
					received[route] += totalBytes
					mu.Unlock()

					// Remote connection no longer usable
					re.conn.Close()
					// Do nothing on normal close (could have been closed by client)
					// or we must notify client by closing loConn
					if req != nil {
						loConn.Close()
					}
					return
				}

				if *verbose {
					logger.Printf("H %5d:      *      %d HTTP Status %s Content-length %d", re.total, route, resp.Status, resp.ContentLength)
				}
			}

			// It's not safe to close connection at this stage (body has not been read),
			// but we need to inform client as soon as possible
			if resp.Close {
				re.close = true
			}

			// Do not change connection header to proxy-connection as they have different scopes.
			// Client requests are directly forwarded to the server without any delay.
			// We can't strip connection header for those servers that don't support pipelines,
			// until we are able to hold the pipelined requests and send according to server capability.
			resp.Header.Del("Proxy-Connection") // unlikely, just in case
			header, _ := httputil.DumpResponse(resp, false)

			_, err := loConn.Write(header)
			totalBytes += int64(len(header))
			if err != nil {
				if *verbose {
					logger.Printf("H %5d:     ERR     %d Failed to write HTTP header to client. Error: %s", re.total, route, err)
				}
				totalBytes += int64(bufOut.Buffered())

				// Unexpected error, close both ends
				re.conn.Close()
				loConn.Close()
				// Continue so that in next loop we can return with empty == true and update counter
				bufOut.Discard(bufOut.Buffered())
				continue
			}

			if accumStart.Before(re.lastReq) {
				accumStart = re.lastReq
				accum = 0
			}

			// Write body to client
			if resp.ContentLength == -1 && len(resp.TransferEncoding) > 0 && resp.TransferEncoding[0] == "chunked" {
				cr := newChunkedReader(bufOut)
				n, bytes, err := cr.copyTo(loConn, re, re.conn.RemoteAddr(), route, accum)
				accum += bytes
				totalBytes += bytes
				if err == nil || errors.Is(err, io.EOF) {
					if *verbose {
						logger.Printf("H %5d:      *      %d Parsed %d chunks and %d bytes", re.total, route, n, bytes)
					}
				} else {
					if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") ||
						strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") || errors.Is(err, io.ErrUnexpectedEOF) {
						if *verbose {
							logger.Printf("H %5d:     RST     %d Chunks parsing reset by server, %.1f s since last request. Error: %s", re.total, route, time.Since(re.lastReq).Seconds(), err)
						}
						if route == 1 && !re.ruleBased {
							if tcpAddr := re.conn.RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
								if re.host == "" {
									logger.Printf("H %5d:     ADD     %d TCP reset detected, %s port %s added to blocked list", re.total, route, tcpAddr.IP, re.dport)
									blockedIPSet.add(tcpAddr.IP, re.dport)
								} else {
									logger.Printf("H %5d:     ADD     %d TCP reset detected, %s port %s added to blocked list", re.total, route, re.host, re.dport)
									blockedHostSet.add(re.host, re.dport)
								}
							}
						}
						if tcp, ok := loConn.(*net.TCPConn); ok {
							tcp.SetLinger(0)
						}
					} else {
						if *verbose {
							logger.Printf("H %5d:     ERR     %d Parsed %d chunks and %d bytes but failed to write to client. Error: %s", re.total, route, n, bytes, err)
						}
					}
					totalBytes += int64(bufOut.Buffered())

					// Unexpected error, close both ends
					re.conn.Close()
					loConn.Close()
					// Continue so that in next loop we can return with empty == true and update counter
					bufOut.Discard(bufOut.Buffered())
					continue
				}

				// Write trailer
				var trailer []byte
				for {
					line, err := bufOut.ReadSlice('\n')
					trailer = append(trailer, line...)
					totalBytes += int64(len(line))
					if len(line) == 2 || err != nil {
						loConn.Write(trailer)
						break
					}
				}
			} else if resp.ContentLength != 0 && resp.Request.Method != "HEAD" {
				bytes, err := re.writeTo(loConn, resp.Body, true, re.conn.RemoteAddr(), route, accum)
				accum += bytes
				totalBytes += bytes
				resp.Body.Close()
				if err != nil && !errors.Is(err, io.EOF) {
					// Linux: "read: connection reset by peer"
					// Windows: "wsarecv: An existing connection was forcibly closed by the remote host."
					if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") ||
						strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") || errors.Is(err, io.ErrUnexpectedEOF) {
						if *verbose {
							logger.Printf("H %5d:     RST     %d HTTP body fetching reset by server, %.1f s since last request. Error: %s", re.total, route, time.Since(re.lastReq).Seconds(), err)
						}
						if route == 1 && !re.ruleBased {
							if tcpAddr := re.conn.RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
								if re.host == "" {
									logger.Printf("H %5d:     ADD     %d TCP reset detected, %s port %s added to blocked list", re.total, route, tcpAddr.IP, re.dport)
									blockedIPSet.add(tcpAddr.IP, re.dport)
								} else {
									logger.Printf("H %5d:     ADD     %d TCP reset detected, %s port %s added to blocked list", re.total, route, re.host, re.dport)
									blockedHostSet.add(re.host, re.dport)
								}
							}
						}
						if tcp, ok := loConn.(*net.TCPConn); ok {
							tcp.SetLinger(0)
						}
					} else {
						if *verbose {
							logger.Printf("H %5d:     ERR     %d Failed to write HTTP body to client. Error: %s", re.total, route, err)
						}
					}
					totalBytes += int64(bufOut.Buffered())

					// Unexpected error, close both ends
					re.conn.Close()
					loConn.Close()
					// Continue so that in next loop we can return with empty == true and update counter
					bufOut.Discard(bufOut.Buffered())
					continue
				}
			}

			// We close remote connection per server instruction and continue to update counter in the next loop
			// client can choose whether to close or reuse connection
			if resp.Close {
				re.conn.Close()
				bufOut.Discard(bufOut.Buffered())
				continue
			}
		}
	} else {
		// Non-proxy responses
		loConn.Write(firstIn)
		bytes, err := re.writeTo(loConn, bufOut, false, re.conn.RemoteAddr(), route, int64(len(firstIn)))
		totalBytes := int64(len(firstIn)) + bytes + int64(bufOut.Buffered())
		totalTime := time.Since(sentTime)
		if err == nil || errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "time") {
			if *verbose {
				logger.Printf("%s %5d:          *  %d Remote connection closed. Received %d bytes in %.1f s.", re.mode, re.total, route, totalBytes, totalTime.Seconds())
			}
			//t := time.Since(re.lastReq).Seconds()
			/*if route == 1 && !re.ruleBased && re.tls && totalBytes == int64(n) && totalTime.Seconds() > 30 && !re.lastReq.Equal(sentTime) {
				if tcpAddr := out.RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
					if re.host == "" || *dnsOK {
						logger.Printf("%s %5d:         ADD %d TLS handshake cut off, %s %s port %s added to blocked list", re.mode, re.total, route, re.host, tcpAddr.IP, re.dport)
						blockedIPSet.add(tcpAddr.IP, re.dport)
					} else {
						logger.Printf("%s %5d:         ADD %d TLS handshake cut off, %s port %s added to blocked list", re.mode, re.total, route, re.host, re.dport)
					}
					blockedHostSet.add(re.host, re.dport)
				}
			} else if route == 1 && !re.ruleBased && t > 30 && totalBytes > 0 && totalBytes < 1000 {
				if tcpAddr := out.RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
					logger.Printf("%s %5d:         ERR %d Connection to %s %s likely cut off, %.1f s since last request", re.mode, re.total, route, re.host, tcpAddr, t)
					/*logger.Printf("%s %5d:         ADD %d Connection likely cut off, %.1f s since last request, %s %s added to blocked list", mode, total, route, t, host, tcpAddr.IP)
					blockedIPSet.add(tcpAddr.IP)
					blockedHostSet.add(host)
				}
			}*/
		} else if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
			if *verbose {
				logger.Printf("%s %5d:         RST %d Remote connection reset. Received %d bytes in %.1f s, %.1f s since last request. Error: %s", re.mode, re.total, route, totalBytes, totalTime.Seconds(), time.Since(re.lastReq).Seconds(), err)
			}
			if route == 1 && !re.ruleBased && totalTime.Seconds() < blockSafeTime {
				if tcpAddr := re.conn.RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
					if re.host == "" {
						logger.Printf("%s %5d:         ADD %d TCP reset detected, %s port %s added to blocked list", re.mode, re.total, route, tcpAddr.IP, re.dport)
						blockedIPSet.add(tcpAddr.IP, re.dport)
					} else {
						logger.Printf("%s %5d:         ADD %d TCP reset detected, %s port %s added to blocked list", re.mode, re.total, route, re.host, re.dport)
						blockedHostSet.add(re.host, re.dport)
					}
				}
			}
			if tcp, ok := loConn.(*net.TCPConn); ok {
				tcp.SetLinger(0)
			}
		} else {
			if *verbose {
				logger.Printf("%s %5d:         ERR %d Remote connection closed. Received %d bytes in %.1f s. Error: %s", re.mode, re.total, route, totalBytes, totalTime.Seconds(), err)
			}
		}

		mu.Lock()
		received[route] += totalBytes
		mu.Unlock()

		loConn.Close()
	}
}

func matchHost(total int, mode, host, port string) (routes []int, ruleBased bool) {
	routes = hostRules.findRouteForText(host, true)
	if len(routes) > 0 {
		if *verbose {
			logger.Printf("%s %5d: RUL           Host rule matched for %s. Select routes %v", mode, total, host, routes)
		}
		ruleBased = true
		return
	}
	if blockedHostSet.find(host, port, false) {
		routes = blockedRoutes
		if *verbose {
			logger.Printf("%s %5d: SET           Host %s port %s found in blocked list. Select routes %v", mode, total, host, port, blockedRoutes)
		}
		return
	}
	if slowHostSet.find(host, port, false) {
		routes = blockedRoutes
		if *verbose {
			logger.Printf("%s %5d: SET           Host %s port %s found in slow list. Select routes %v", mode, total, host, port, blockedRoutes)
		}
		return
	}
	return
}

func matchIP(total int, mode string, ip net.IP, port string) (routes []int, ruleBased bool) {
	routes = ipRules.findRouteForIP(ip)
	if len(routes) > 0 {
		if *verbose {
			logger.Printf("%s %5d: RUL           IP rule matched for %s. Select routes %v", mode, total, ip, routes)
		}
		ruleBased = true
		return
	}
	if blockedIPSet.find(ip, port, false) {
		routes = blockedRoutes
		if *verbose {
			logger.Printf("%s %5d: SET           IP %s port %s found in blocked list. Select routes %v", mode, total, ip, port, blockedRoutes)
		}
		return
	}
	if slowIPSet.find(ip, port, false) {
		routes = blockedRoutes
		if *verbose {
			logger.Printf("%s %5d: SET           IP %s port %s found in slow list. Select routes %v", mode, total, ip, port, blockedRoutes)
		}
		return
	}
	return
}

func (re *remoteConn) writeTo(loConn net.Conn, out io.Reader, single bool, addr net.Addr, route int, lastBytes int64) (bytes int64, err error) {
	if route == 1 && *slowSpeed > 0 && !re.ruleBased && contain(chkPorts, re.dport) {
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
				_, err = loConn.Write(p[:n])
			} else if bytes > 0 {
				loConn.Write(p[:n])
			}
			d = time.Since(t)
			sampleStart = sampleStart.Add(d)
			reqStart = reqStart.Add(d)
			if err != nil {
				break
			}
			if !added && slow {
				logger.Printf("%s %5d:     SLO     %d Slow connection to %s %s at %.1f kB/s, %.1f kB/s since last request, %.1f kB/s overall", re.mode, re.total, route, re.host, addr, speed, aveSpeed, totalSpeed)
				if tcpAddr := addr.(*net.TCPAddr); tcpAddr != nil && !*slowDry {
					slowIPSet.add(tcpAddr.IP, "")
					slowHostSet.add(re.host, "")
					if *slowClose {
						loConn.Close()
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
							logger.Printf("%s %5d:     SLO     %d Speed to %s %s recovered to %.1f kB/s, %.1f kB/s since last request, %.1f kB/s overall", re.mode, re.total, route, re.host, addr, speed, aveSpeed, totalSpeed)
							slow = false
							added = false
							if tcpAddr := addr.(*net.TCPAddr); tcpAddr != nil && !*slowDry {
								slowIPSet.find(tcpAddr.IP, "", true)
								slowHostSet.find(re.host, "", true)
							}
						}
					}
				}
			}
		}
	} else {
		bytes, err = io.Copy(loConn, out)
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
