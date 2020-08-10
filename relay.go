// Released under MIT License
// Copyright (c) 2020 domosekai

// Relay functions for both modes

package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	initialSize       = 5000
	bufferSize        = 10000 // Not effective if speed detection is disabled (system default buffer size will be used)
	minSampleInterval = 5     // Due to slow start, this seconds are needed for meaningful speed detection
	maxSampleInterval = 20
	minSpeed          = 3 // Speed below this kB/s is likely to have special purpose
	blockSafeTime     = 5 // After this many seconds it is less likely to be blocked by firewall
)

var (
	blockedIPSet   ipSet
	blockedHostSet hostSet
	slowIPSet      ipSet
	slowHostSet    hostSet
)

// Wait for first byte from client, should come immediately with ACK in the 3-way handshake
// Otherwise it may never come (like FTP)
func handleFirstByte(bufIn *bufio.Reader, conn *net.Conn, mode, network, dest, port string, sniff bool, total int) {
	// git sometimes sends first byte with more than 200ms delay
	(*conn).SetReadDeadline(time.Now().Add(time.Millisecond * 300))
	first := make([]byte, initialSize)
	n, err := bufIn.Read(first)
	if err == nil {
		if *verbose {
			logger.Printf("%s %5d:  *            First %d bytes from client", mode, total, n)
		}
	} else if !strings.Contains(err.Error(), "time") {
		if *verbose {
			logger.Printf("%s %5d:  *            Failed to read first byte from client. Error: %s", mode, total, err)
		}
		return
	}
	(*conn).SetReadDeadline(time.Time{})
	var lastReq time.Time

	// TLS Client Hello
	if n > recordHeaderLen && recordType(first[0]) == recordTypeHandshake && first[recordHeaderLen] == typeClientHello {
		if m := new(clientHelloMsg); m.unmarshal(first[recordHeaderLen:n]) {
			host := ""
			if m.serverName != "" {
				if *verbose {
					logger.Printf("%s %5d:  *            TLS SNI %s", mode, total, m.serverName)
				}
				if sniff {
					host, _ = normalizeHostname(m.serverName, port)
				}
			} else if m.esni {
				if *verbose {
					logger.Printf("%s %5d:  *            TLS ESNI", mode, total)
				}
			} else {
				if *verbose {
					logger.Printf("%s %5d:  *            TLS Client Hello", mode, total)
				}
			}
			if out, route := getRoute(bufIn, conn, first[:n], n == initialSize, nil, nil, mode, network, dest, host, port, false, total, false, true, &lastReq); out != nil {
				relayLocal(bufIn, out, mode, total, route, n, &lastReq)
			}
			return
		}
	}

	// HTTP
	if n > 0 {
		if req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(first[:n]))); err == nil {
			if *verbose {
				logger.Printf("%s %5d:  *            HTTP %s Host %s Content-length %d", mode, total, req.Method, req.Host, req.ContentLength)
			}
			host := ""
			if sniff {
				host, _ = normalizeHostname(req.Host, port)
			}
			if out, route := getRoute(bufIn, conn, first[:n], n == initialSize, req, nil, mode, network, dest, host, port, true, total, false, false, &lastReq); out != nil {
				relayLocal(bufIn, out, mode, total, route, n, &lastReq)
			}
			return
		}
	}

	// Unknown protocol
	if out, route := getRoute(bufIn, conn, first[:n], n == initialSize, nil, nil, mode, network, dest, "", port, true, total, false, false, &lastReq); out != nil {
		relayLocal(bufIn, out, mode, total, route, n, &lastReq)
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

func getRoute(bufIn *bufio.Reader, conn *net.Conn, first []byte, firstFull bool, firstReq *http.Request, reqs chan *http.Request, mode, network, dest, host, port string,
	successive bool, total int, connection, tls bool, lastReq *time.Time) (*net.Conn, int) {
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
	try2 := make(chan int, len(socks))
	stop2 := make(chan bool, 1)
	do1 := make(chan int, 1)
	do2 := make(chan int, 1)
	var out1 net.Conn
	out2 := make([]net.Conn, len(socks))
	ok1, ok2 := -1, -1
	var available1, available2 int

	// Match rules
	route := 0
	ruleBased := false
	if host != "" {
		route, ruleBased = matchHost(total, mode, host)
	}
	if route == 0 {
		if ip := net.ParseIP(dest); ip != nil {
			// dest is IP
			if *dnsOK {
				route, ruleBased = matchIP(total, mode, ip)
			}
		} else {
			// dest is hostname
			route, ruleBased = matchHost(total, mode, dest)
		}
	}

	// Dispatch workers
	net1 := network
	net2 := network
	if *force4 {
		net1 = "tcp4"
	}
	totalTimeout := 1
	if route == 0 || route == 1 {
		go handleRemote(bufIn, conn, &out1, first, firstFull, ruleBased, firstReq, reqs, mode, net1, dest, host, port, int(*r1Timeout), total, 1, 1, start[0], try1, do1, stop2, connection, tls, lastReq)
		totalTimeout += int(*r1Timeout)
	}
	if route == 0 || route == 2 {
		for i, v := range socks {
			go handleRemote(bufIn, conn, &out2[i], first, firstFull, ruleBased, firstReq, reqs, mode, net2, dest, host, port, int(*r2Timeout), total, 2, i+1, start[v.pri], try2, do2, stop2, connection, tls, lastReq)
			totalTimeout += int(*r2Timeout)
		}
	}

	// Send signal to workers
	switch route {
	case 0:
		start[0] <- true
		if !successive {
			for range priority[1] {
				start[1] <- true
			}
		}
		available1 = 1
		available2 = len(socks)
	case 1:
		start[0] <- true
		available1 = 1
		available2 = 0
	case 2:
		if !successive {
			for range priority[1] {
				start[1] <- true
			}
		} else {
			start[1] <- true
		}
		available1 = 0
		available2 = len(socks)
	default:
		return nil, 0
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
				do1 <- 1
				if available2 > 0 {
					do2 <- 0
				}
				return &out1, 1
			}
			available1--
			if available2 > 0 {
				if successive {
					start[1] <- true
				}
				if server2 > 0 {
					do2 <- server2
					return &out2[server2-1], 2
				}
			} else {
				return nil, 0
			}
		// Route 2 sends status from any server
		case ok2 = <-try2:
			count2++
			if ok2 > 0 && available2 > 0 && server2 == 0 {
				server2 = ok2
				if available1 == 0 {
					do2 <- server2
					return &out2[server2-1], 2
				} else if !wait {
					do2 <- server2
					do1 <- 0
					return &out2[server2-1], 2
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
					return nil, 0
				}
			}
		// Priority period for route 1 ends
		case <-timer1.C:
			wait = false
			if server2 > 0 && available2 > 0 {
				do2 <- server2
				if available1 > 0 {
					do1 <- 0
				}
				return &out2[server2-1], 2
			}
		case <-timer2.C:
			if available1 > 0 {
				do1 <- 0
			}
			if available2 > 0 {
				do2 <- 0
			}
			return nil, 0
		}
	}
}

func relayLocal(bufIn *bufio.Reader, out *net.Conn, mode string, total, route, n int, lastReq *time.Time) {
	totalBytes := int64(n)
	var err error
	if route == 1 && *slowSpeed > 0 {
		for {
			p := make([]byte, bufferSize)
			var bytes int
			bytes, err = bufIn.Read(p)
			if err == nil {
				bytes, err = (*out).Write(p[:bytes])
			} else {
				bytes, _ = (*out).Write(p[:bytes])
			}
			totalBytes += int64(bytes)
			if err != nil {
				break
			}
			// Only set time if successfully sent
			*lastReq = time.Now()
		}
	} else {
		var bytes int64
		bytes, err = bufIn.WriteTo(*out)
		totalBytes += bytes
	}
	if err == nil || errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "time") {
		if *verbose {
			logger.Printf("%s %5d:          *    Local connection closed, %d bytes sent", mode, total, totalBytes)
		}
	} else if strings.Contains(err.Error(), "reset") {
		if *verbose {
			logger.Printf("%s %5d:          *    Local connection reset, %d bytes sent", mode, total, totalBytes)
		}
	} else {
		if *verbose {
			logger.Printf("%s %5d:         ERR   Local connection closed, %d bytes sent. Error: %s", mode, total, totalBytes, err)
		}
	}
	mu.Lock()
	sent[route] += totalBytes
	mu.Unlock()
	(*out).Close()
}

func handleRemote(bufIn *bufio.Reader, conn, out *net.Conn, firstOut []byte, firstFull, ruleBased bool, firstReq *http.Request, reqs chan *http.Request, mode, network, dest, host, port string,
	timeout, total, route, server int, start chan bool, try, do chan int, stop2 chan bool, connection, tls bool, lastReq *time.Time) {
	mu.Lock()
	jobs[route]++
	mu.Unlock()
	select {
	case <-start:
		doRemote(bufIn, conn, out, firstOut, firstFull, ruleBased, firstReq, reqs, mode, network, dest, host, port, timeout, total, route, server, try, do, stop2, connection, tls, lastReq)
	case s := <-do:
		do <- s
	}
	mu.Lock()
	jobs[route]--
	mu.Unlock()
}

func doRemote(bufIn *bufio.Reader, conn, out *net.Conn, firstOut []byte, firstFull, ruleBased bool, firstReq *http.Request, reqs chan *http.Request, mode, network, dest, host, port string,
	timeout, total, route, server int, try, do chan int, stop2 chan bool, connection, tls bool, lastReq *time.Time) {
	var dp string
	var err error
	if route == 1 {
		dp = net.JoinHostPort(dest, port)
		if *verbose {
			logger.Printf("%s %5d:  *          %d Dialing to %s %s", mode, total, route, network, dp)
		}
		*out, err = net.DialTimeout(network, dp, time.Second*time.Duration(timeout))
	} else {
		dialer, err1 := proxy.SOCKS5("tcp", socks[server-1].addr, nil, &net.Dialer{Timeout: time.Second * time.Duration(timeout)})
		if err1 != nil {
			logger.Printf("%s %5d: ERR         %d Failed to dial SOCKS server %s. Error: %s", mode, total, route, socks[server-1].addr, err)
			try <- 0
			return
		}
		if host != "" {
			dp = net.JoinHostPort(host, port)
		} else {
			dp = net.JoinHostPort(dest, port)
		}
		if *verbose {
			logger.Printf("%s %5d:  *          %d Dialing to %s %s via %s", mode, total, route, network, dp, socks[server-1].addr)
		}
		*out, err = dialer.Dial(network, dp)
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
				logger.Printf("%s %5d: SYN         %d Initial connection timeout", mode, total, route)
			}
		} else if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "reset") {
			if *verbose {
				logger.Printf("%s %5d: RST         %d Initial connection reset", mode, total, route)
			}
		} else if strings.Contains(err.Error(), "no such host") {
			if *verbose {
				logger.Printf("%s %5d: NXD         %d Domain lookup failed", mode, total, route)
			}
		} else {
			if *verbose {
				logger.Printf("%s %5d: ERR         %d Failed to dial server. Error: %s", mode, total, route, err)
			}
		}
		try <- 0
		return
	}
	/*if tcp, ok := (*out).(*net.TCPConn); ok {
		tcp.SetLinger(0)
	}*/
	if *verbose {
		logger.Printf("%s %5d:  *          %d TCP connection established", mode, total, route)
	}
	mu.Lock()
	open[route]++
	mu.Unlock()
	defer func() {
		(*out).Close()
		mu.Lock()
		open[route]--
		mu.Unlock()
	}()

	destIsIP := net.ParseIP(dest) != nil
	if host == "" && !destIsIP {
		host = dest
	}

	// Match IP rules in HTTP proxy mode if DNS is trusted
	if route == 1 && !ruleBased && *dnsOK && !destIsIP {
		// dest is hostname
		if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
			var newRoute int
			newRoute, ruleBased = matchIP(total, mode, tcpAddr.IP)
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
	if len(firstOut) > 0 {
		(*out).SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		if _, err := (*out).Write(firstOut); err != nil {
			if *verbose {
				logger.Printf("%s %5d: ERR         %d Failed to send first byte to server. Error: %s", mode, total, route, err)
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
	if firstFull {
		(*out).SetReadDeadline(time.Now().Add(time.Millisecond * 100))
	} else {
		(*out).SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
	}
	if mode == "H" && firstReq != nil {
		firstResp, err = http.ReadResponse(bufOut, firstReq)
	} else {
		n, err = bufOut.Read(firstIn)
	}
	(*out).SetReadDeadline(time.Time{})
	ttfb := time.Since(sentTime)

	if err != nil {
		// If request is only partially sent, timeout is normal
		if !firstFull || !strings.Contains(err.Error(), "time") {
			if strings.Contains(err.Error(), "reset") {
				if *verbose {
					logger.Printf("%s %5d:     RST     %d First byte reset", mode, total, route)
				}
			} else if strings.Contains(err.Error(), "time") {
				if *verbose {
					logger.Printf("%s %5d:     PSH     %d First byte timeout", mode, total, route)
				}
			} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if *verbose {
					logger.Printf("%s %5d:     FIN     %d First byte from server is EOF", mode, total, route)
				}
			} else if !strings.Contains(err.Error(), "closed") {
				if *verbose {
					logger.Printf("%s %5d:     ERR     %d Connection closed before receiving first byte. Error: %s", mode, total, route, err)
				}
			}
			try <- 0
			return
		}
	} else {
		// If there is response, remove full flag
		firstFull = false
		// Check response validity
		if mode == "H" && firstReq != nil {
			if *verbose {
				logger.Printf("H %5d:      *      %d HTTP Status %s Content-length %d. TTFB %d ms", total, route, firstResp.Status, firstResp.ContentLength, ttfb.Milliseconds())
			}
			if route == 1 && !ruleBased && findRouteForText(firstResp.Status, httpRules, false) == 2 {
				if *verbose {
					logger.Printf("%s %5d:      *      %d HTTP Status in blocklist", mode, total, route)
				}
				try <- 0
				return
			}
		} else {
			if *verbose {
				logger.Printf("%s %5d:      *      %d First %d bytes from server. TTFB %d ms", mode, total, route, n, ttfb.Milliseconds())
			}
			if firstReq != nil {
				if resp, err := readResponseStatus(bufio.NewReader(bytes.NewReader(firstIn[:n]))); err == nil {
					if *verbose {
						logger.Printf("%s %5d:      *      %d HTTP Status %s", mode, total, route, resp.Status)
					}
					if route == 1 && !ruleBased && findRouteForText(resp.Status, httpRules, false) == 2 {
						if *verbose {
							logger.Printf("%s %5d:      *      %d HTTP Status in blocklist", mode, total, route)
						}
						try <- 0
						return
					}
				} else {
					logger.Printf("%s %5d:     ERR     %d Bad HTTP response. Error: %s", mode, total, route, err)
					if route == 1 && !ruleBased {
						try <- 0
						return
					}
				}
			}
			if tls && n > recordHeaderLen {
				if !(recordType(firstIn[0]) == recordTypeHandshake && firstIn[recordHeaderLen] == typeServerHello) {
					logger.Printf("%s %5d:     ERR     %d Bad TLS Handshake", mode, total, route)
					if route == 1 && !ruleBased {
						try <- 0
						return
					}
				}
			}
		}
	}

	// Match IP rules in both modes after TLS and HTTP check if DNS is not trusted
	if route == 1 && !ruleBased && !*dnsOK {
		if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
			var newRoute int
			newRoute, ruleBased = matchIP(total, mode, tcpAddr.IP)
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
			for len(reqs) > 0 {
				<-reqs
			}
		}()
		// Set last request time to sent time before writeing response to client
		// Do not set initially at client side as it's racy
		*lastReq = sentTime
		if *verbose {
			logger.Printf("%s %5d:      *      %d Continue %s %s -> %s", mode, total, route, (*out).LocalAddr().Network(), (*out).LocalAddr(), (*out).RemoteAddr())
		}
		if mode == "H" && firstReq != nil {
			var totalBytes, accum int64
			accumStart := *lastReq
			for {
				var resp *http.Response
				if firstResp != nil {
					resp = firstResp
					firstResp = nil
				} else {
					var err error
					if _, err = bufOut.ReadByte(); err == nil {
						if firstFull {
							bufOut.UnreadByte()
							resp, err = http.ReadResponse(bufOut, firstReq)
							firstFull = false
						} else if len(reqs) > 0 {
							bufOut.UnreadByte()
							resp, err = http.ReadResponse(bufOut, <-reqs)
						} else {
							err = errors.New("HTTP response received with no matching request")
						}
					}
					if err != nil {
						totalTime := time.Since(sentTime)
						if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "closed") {
							if *verbose {
								logger.Printf("H %5d:          *  %d Remote connection closed, %d bytes received in %.1f s", total, route, totalBytes, totalTime.Seconds())
							}
							t := time.Since(*lastReq).Seconds()
							if route == 1 && !ruleBased && t > 30 && totalBytes < 1000 {
								//logger.Printf("H %5d:         ERR %d Suspiciously blocked connection to %s %s, %.1f s since last request", total, route, host, (*out).RemoteAddr(), time.Since(*lastReq).Seconds())
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:         BLK %d Traffic likely cut off, %.1f s since last request, %s %s added to blocked list", total, route, t, host, tcpAddr.IP)
									blockedIPSet.add(tcpAddr.IP)
									blockedHostSet.add(host)
								}
							}
						} else if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
							if *verbose {
								logger.Printf("H %5d:         RST %d Remote connection reset, %d bytes received in %.1f s, %.1f s since last request. Error: %s", total, route, totalBytes, totalTime.Seconds(), time.Since(*lastReq).Seconds(), err)
							}
							if route == 1 && !ruleBased && totalTime.Seconds() < blockSafeTime {
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:         BLK %d TCP reset detected, %s %s added to blocked list", total, route, host, tcpAddr.IP)
									blockedIPSet.add(tcpAddr.IP)
									blockedHostSet.add(host)
								}
							}
						} else {
							logger.Printf("H %5d:         ERR %d Remote connection closed, %d bytes received in %.1f s. Error: %s", total, route, totalBytes, totalTime.Seconds(), err)
						}
						mu.Lock()
						received[route] += totalBytes
						mu.Unlock()
						(*out).Close()
						if len(reqs) > 0 {
							(*conn).Close()
						}
						return
					}
					if *verbose {
						logger.Printf("H %5d:      *      %d HTTP Status %s Content-length %d", total, route, resp.Status, resp.ContentLength)
					}
				}
				header, _ := httputil.DumpResponse(resp, false)
				if !connection {
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
				_, err := (*conn).Write(header)
				totalBytes += int64(len(header))
				if err != nil {
					if *verbose {
						logger.Printf("H %5d:     ERR     %d Failed to write HTTP header to client. Error: %s", total, route, err)
					}
					totalBytes += int64(bufOut.Buffered())
					bufOut.Discard(bufOut.Buffered())
					(*out).Close()
					(*conn).Close()
					continue
				}
				if resp.ContentLength == -1 && len(resp.TransferEncoding) > 0 && resp.TransferEncoding[0] == "chunked" {
					cr := newChunkedReader(bufOut)
					n, bytes, err := cr.copy(conn)
					totalBytes += bytes
					if errors.Is(err, io.EOF) {
						if *verbose {
							logger.Printf("H %5d:      *      %d Parsed %d chunks and %d bytes", total, route, n, bytes)
						}
					} else {
						if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
							if *verbose {
								logger.Printf("H %5d:     RST     %d Chunks parsing reset by server, %.1f s since last request. Error: %s", total, route, time.Since(*lastReq).Seconds(), err)
							}
							if route == 1 && !ruleBased && time.Since(*lastReq).Seconds() < blockSafeTime {
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:     BLK     %d TCP reset detected, %s %s added to blocked list", total, route, host, tcpAddr.IP)
									blockedIPSet.add(tcpAddr.IP)
									blockedHostSet.add(host)
								}
							}
						} else {
							if *verbose {
								logger.Printf("H %5d:     ERR     %d Parsed %d chunks and %d bytes but failed to write to client. Error: %s", total, route, n, bytes, err)
							}
						}
						totalBytes += int64(bufOut.Buffered())
						bufOut.Discard(bufOut.Buffered())
						(*out).Close()
						(*conn).Close()
						continue
					}
					// Write trailer
					var trailer []byte
					for {
						line, err := bufOut.ReadSlice('\n')
						trailer = append(trailer, line...)
						totalBytes += int64(len(line))
						if len(line) == 2 || err != nil {
							(*conn).Write(trailer)
							break
						}
					}
				} else if resp.ContentLength != 0 && resp.Request.Method != "HEAD" {
					if accumStart.Before(*lastReq) {
						accumStart = *lastReq
						accum = 0
					}
					bytes, err := receiveSend(conn, resp.Body, ruleBased, true, mode, dest, host, port, (*out).RemoteAddr(), total, route, lastReq, accum)
					accum += bytes
					totalBytes += bytes
					resp.Body.Close()
					if err != nil && !errors.Is(err, io.EOF) {
						// Linux: "read: connection reset by peer"
						// Windows: "wsarecv: An existing connection was forcibly closed by the remote host."
						if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
							if *verbose {
								logger.Printf("H %5d:     RST     %d HTTP body fetching reset by server, %.1f s since last request. Error: %s", total, route, time.Since(*lastReq).Seconds(), err)
							}
							if route == 1 && !ruleBased && time.Since(*lastReq).Seconds() < blockSafeTime {
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:     BLK     %d TCP reset detected, %s %s added to blocked list", total, route, host, tcpAddr.IP)
									blockedIPSet.add(tcpAddr.IP)
									blockedHostSet.add(host)
								}
							}
						} else {
							if *verbose {
								logger.Printf("H %5d:     ERR     %d Failed to write HTTP body to client. Error: %s", total, route, err)
							}
						}
						totalBytes += int64(bufOut.Buffered())
						bufOut.Discard(bufOut.Buffered())
						(*out).Close()
						(*conn).Close()
						continue
					}
				}
				if resp.Close {
					defer (*conn).Close()
				}
			}
		} else {
			(*conn).Write(firstIn[:n])
			bytes, err := receiveSend(conn, bufOut, ruleBased, false, mode, dest, host, port, (*out).RemoteAddr(), total, route, lastReq, int64(n))
			totalBytes := int64(n) + bytes + int64(bufOut.Buffered())
			totalTime := time.Since(sentTime)
			if err == nil || errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "time") {
				if *verbose {
					logger.Printf("%s %5d:          *  %d Remote connection closed, %d bytes received in %.1f s", mode, total, route, totalBytes, totalTime.Seconds())
				}
				t := time.Since(*lastReq).Seconds()
				if route == 1 && !ruleBased && tls && totalBytes == int64(n) && totalTime.Seconds() > 5 && !(*lastReq).Equal(sentTime) {
					if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
						logger.Printf("%s %5d:         BLK %d TLS handshake cut off, %s %s added to blocked list", mode, total, route, host, tcpAddr.IP)
						blockedIPSet.add(tcpAddr.IP)
						blockedHostSet.add(host)
					}
				} else if route == 1 && !ruleBased && t > 30 && totalBytes < 1000 {
					//logger.Printf("%s %5d:         ERR %d Suspiciously blocked connection to %s %s, %.1f s since last request", mode, total, route, host, (*out).RemoteAddr(), time.Since(*lastReq).Seconds())
					if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
						logger.Printf("%s %5d:         BLK %d Traffic likely cut off, %.1f s since last request, %s %s added to blocked list", mode, total, route, t, host, tcpAddr.IP)
						blockedIPSet.add(tcpAddr.IP)
						blockedHostSet.add(host)
					}
				}
			} else if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
				if *verbose {
					logger.Printf("%s %5d:         RST %d Remote connection reset, %d bytes received in %.1f s, %.1f s since last request. Error: %s", mode, total, route, totalBytes, totalTime.Seconds(), time.Since(*lastReq).Seconds(), err)
				}
				if route == 1 && !ruleBased && totalTime.Seconds() < blockSafeTime {
					if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
						logger.Printf("%s %5d:         BLK %d TCP reset detected, %s %s added to blocked list", mode, total, route, host, tcpAddr.IP)
						blockedIPSet.add(tcpAddr.IP)
						blockedHostSet.add(host)
					}
				}
			} else {
				if *verbose {
					logger.Printf("%s %5d:         ERR %d Remote connection closed, %d bytes received in %.1f s. Error: %s", mode, total, route, totalBytes, totalTime.Seconds(), err)
				}
			}
			mu.Lock()
			received[route] += totalBytes
			mu.Unlock()
			(*conn).Close()
		}
	}
}

func matchHost(total int, mode, host string) (route int, ruleBased bool) {
	if hostRules != nil {
		route = findRouteForText(host, hostRules, true)
		if route != 0 {
			if *verbose {
				logger.Printf("%s %5d:  *            Host rule matched for %s. Select route %d", mode, total, host, route)
			}
			ruleBased = true
			return
		}
	}
	if blockedHostSet.contain(host) {
		route = 2
		if *verbose {
			logger.Printf("%s %5d:  *            Host %s found in blocked list. Select route %d", mode, total, host, route)
		}
		return
	}
	if slowHostSet.contain(host) {
		route = 2
		if *verbose {
			logger.Printf("%s %5d:  *            Host %s found in slow list. Select route %d", mode, total, host, route)
		}
		return
	}
	return
}

func matchIP(total int, mode string, ip net.IP) (route int, ruleBased bool) {
	if ipRules != nil {
		route = findRouteForIP(ip, ipRules)
		if route == 0 && elseRoute != 0 {
			route = elseRoute
		}
		if route != 0 {
			if *verbose {
				logger.Printf("%s %5d:  *            IP rule matched for %s. Select route %d", mode, total, ip, route)
			}
			ruleBased = true
			return
		}
	}
	if blockedIPSet.contain(ip) {
		route = 2
		if *verbose {
			logger.Printf("%s %5d:  *            IP %s found in blocked list. Select route %d", mode, total, ip, route)
		}
		return
	}
	if slowIPSet.contain(ip) {
		route = 2
		if *verbose {
			logger.Printf("%s %5d:  *            IP %s found in slow list. Select route %d", mode, total, ip, route)
		}
		return
	}
	return
}

func receiveSend(conn *net.Conn, out io.Reader, ruleBased, single bool, mode, dest, host, port string, addr net.Addr, total, route int, lastReq *time.Time, lastBytes int64) (bytes int64, err error) {
	if route == 1 && *slowSpeed > 0 && !ruleBased && (port == "80" || port == "443") {
		var sample int64
		accum := lastBytes
		sampleStart := time.Now()
		accumStart := *lastReq
		var slow, added bool
		for {
			p := make([]byte, bufferSize)
			var n int
			n, err = out.Read(p)
			bytes += int64(n)
			if sampleStart.Before(*lastReq) {
				sampleStart = *lastReq
				sample = 0
			}
			if !single && accumStart.Before(*lastReq) {
				accumStart = *lastReq
				accum = 0
			}
			if err == nil {
				_, err = (*conn).Write(p[:n])
			} else if bytes > 0 {
				(*conn).Write(p[:n])
			}
			if err != nil {
				break
			}
			if !added && slow {
				if tcpAddr := addr.(*net.TCPAddr); tcpAddr != nil {
					logger.Printf("%s %5d:     SLO     %d %s %s added to slow list", mode, total, route, host, tcpAddr.IP)
					slowIPSet.add(tcpAddr.IP)
					slowHostSet.add(host)
					if *slowClose {
						(*conn).Close()
					}
				}
				added = true
			}
			sample += int64(n)
			accum += int64(n)
			t := time.Since(sampleStart).Seconds()
			// If n = bufferSize, either connection is too fast or client is slow
			if !slow && t > minSampleInterval && n < bufferSize {
				speed := float64(sample) / 1000 / t
				t0 := time.Since(accumStart).Seconds()
				aveSpeed := float64(accum) / 1000 / t0
				if t < maxSampleInterval && (aveSpeed < float64(*slowSpeed) || speed < float64(*slowSpeed)*0.3) && aveSpeed > minSpeed && speed > minSpeed {
					if *verbose {
						logger.Printf("%s %5d:      *      %d Slow connection to %s %s at %.1f kB/s, average %.1f kB/s since last request %.1f s ago", mode, total, route, host, addr, speed, aveSpeed, t0)
					}
					// Set flag to add to list only if this read is not the final one
					slow = true
				}
				sampleStart = time.Now()
				sample = 0
			}
		}
	} else {
		bytes, err = io.Copy(*conn, out)
	}
	return
}
