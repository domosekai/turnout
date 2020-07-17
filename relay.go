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
	initialSize   = 5000
	bufferSize    = 5000
	sampleSize    = 100000 // Download size for slowness detection, smaller size may be inaccurate
	sampleTime    = 10     // Due to slow start, assessing the speed too early can be inaccurate, at least wait for this many seconds
	blockSafeTime = 15     // After this many seconds it is less likely to be blocked by TCP RESET
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
		logger.Printf("%s %5d:  *            First %d bytes from client", mode, total, n)
	} else if !strings.Contains(err.Error(), "time") {
		logger.Printf("%s %5d:  *            Failed to read first byte from client. Error: %s", mode, total, err)
		return
	}
	(*conn).SetReadDeadline(time.Time{})
	var lastReq time.Time

	// TLS Client Hello
	if n > recordHeaderLen && recordType(first[0]) == recordTypeHandshake && first[recordHeaderLen] == typeClientHello {
		if m := new(clientHelloMsg); m.unmarshal(first[recordHeaderLen:n]) {
			logger.Printf("%s %5d:  *            TLS SNI %s", mode, total, m.serverName)
			host := ""
			if sniff {
				host, _ = normalizeHostname(m.serverName, port)
			}
			if out, route := getRoute(bufIn, conn, first[:n], n == initialSize, nil, mode, network, dest, host, port, false, total, false, &lastReq); out != nil {
				relayLocal(bufIn, out, mode, total, route, n, &lastReq)
			}
			return
		}
	}

	// HTTP
	if n > 0 {
		if req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(first[:n]))); err == nil {
			logger.Printf("%s %5d:  *            HTTP %s Host %s Content-length %d", mode, total, req.Method, req.Host, req.ContentLength)
			host := ""
			if sniff {
				host, _ = normalizeHostname(req.Host, port)
			}
			if out, route := getRoute(bufIn, conn, first[:n], n == initialSize, req, mode, network, dest, host, port, true, total, false, &lastReq); out != nil {
				relayLocal(bufIn, out, mode, total, route, n, &lastReq)
			}
			return
		}
	}

	// Unknown protocol
	if out, route := getRoute(bufIn, conn, first[:n], n == initialSize, nil, mode, network, dest, "", port, true, total, false, &lastReq); out != nil {
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

func getRoute(bufIn *bufio.Reader, conn *net.Conn, first []byte, full bool, req *http.Request, mode, network, dest, host, port string,
	successive bool, total int, connection bool, lastReq *time.Time) (*net.Conn, int) {
	// Dial each route and send first byte out
	start1 := make(chan bool, 1)
	start2 := make(chan bool, 1)
	try1 := make(chan int, 1)
	try2 := make(chan int, len(socks))
	stop2 := make(chan bool, 1)
	do1 := make(chan int, 1)
	do2 := make(chan int, 1)
	var out1, out2 net.Conn
	ok1, ok2 := -1, -1
	var available int

	// Match rules
	route := 0
	ruleBased := false
	if host != "" {
		route, ruleBased = matchHost(total, mode, host)
	}
	if route == 0 {
		if ip := net.ParseIP(dest); ip != nil {
			// dest is IP
			route, ruleBased = matchIP(total, mode, ip)
		} else {
			// dest is hostname
			route, ruleBased = matchHost(total, mode, dest)
		}
	}

	switch route {
	case -1:
		return nil, 0
	case 0:
		start1 <- true
		if !successive {
			start2 <- true
		}
		available = len(socks) + 1
	case 1:
		start1 <- true
		start2 <- false
		available = 1
	case 2:
		start1 <- false
		start2 <- true
		available = len(socks)
	}

	net1 := network
	net2 := network
	if *force4 {
		net1 = "tcp4"
	}
	totalTimeout := 1
	if route != 2 {
		go handleRemote(bufIn, conn, &out1, first, full, ruleBased, req, mode, net1, dest, host, port, int(*r1Timeout), total, 1, 1, start1, stop2, try1, do1, connection, lastReq)
		totalTimeout += int(*r1Timeout)
	}
	if route != 1 {
		for i := range socks {
			go handleRemote(bufIn, conn, &out2, first, full, ruleBased, req, mode, net2, dest, host, port, int(*r2Timeout), total, 2, i+1, start2, stop2, try2, do2, connection, lastReq)
			totalTimeout += int(*r2Timeout)
		}
	}

	// Wait for first byte from server
	timer1 := time.NewTimer(time.Second * time.Duration(*r1Priority)) // during which route 1 is prioritized, or in successive mode start of route 2 is deferred
	timer2 := time.NewTimer(time.Second * time.Duration(totalTimeout))
	wait := true
	bad2 := false
	for {
		// Make sure no channel is written twice without return
		// and no goroutine will wait forever
		select {
		// This is before route 1 sends first byte, when it found the IP matches some rule
		case bad2 = <-stop2:
			if bad2 && available > 1 {
				if successive {
					start2 <- false
				} else {
					do2 <- 0
				}
			}
		// Route 1 sends status, bad2 is set by this time
		case ok1 = <-try1:
			if ok1 > 0 {
				do1 <- 1
				if available > 1 && !bad2 {
					if successive {
						start2 <- false
					} else {
						do2 <- 0
					}
				}
				return &out1, 1
			}
			available--
			if available > 0 && !bad2 {
				if successive {
					start2 <- true
				}
				if ok2 > 0 {
					do2 <- ok2
					return &out2, 2
				}
			} else {
				return nil, 0
			}
		// Route 2 sends status from any server
		case ok2 = <-try2:
			if ok2 > 0 && !bad2 {
				if ok1 == 0 {
					do2 <- ok2
					return &out2, 2
				} else if !wait {
					do2 <- ok2
					do1 <- 0
					return &out2, 2
				}
			} else {
				available--
				if successive && !bad2 && (available > 1 || ok1 == 0 && available > 0) {
					start2 <- true
				}
				if available == 0 {
					return nil, 0
				}
			}
		// Priority period for route 1 ends
		case <-timer1.C:
			wait = false
			if ok2 > 0 && !bad2 {
				do2 <- ok2
				if ok1 == -1 {
					do1 <- 0
				}
				return &out2, 2
			}
		case <-timer2.C:
			if ok1 == -1 {
				do1 <- 0
				if available > 1 && !bad2 {
					if successive {
						start2 <- false
					} else {
						do2 <- 0
					}
				}
			} else if !bad2 {
				do2 <- 0
			}
			return nil, 0
		}
	}
}

func relayLocal(bufIn *bufio.Reader, out *net.Conn, mode string, total, route, n int, lastReq *time.Time) {
	totalBytes := int64(n)
	var err error
	if *slowSpeed > 0 {
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
			*lastReq = time.Now()
		}
	} else {
		var bytes int64
		bytes, err = bufIn.WriteTo(*out)
		totalBytes += bytes
	}
	if err == nil || errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "time") {
		logger.Printf("%s %5d:          *    Local connection closed. Sent %d bytes", mode, total, totalBytes)
	} else if strings.Contains(err.Error(), "reset") {
		logger.Printf("%s %5d:          *    Local connection reset. Sent %d bytes", mode, total, totalBytes)
	} else {
		logger.Printf("%s %5d:         ERR   Local connection closed. Sent %d bytes. Error: %s", mode, total, totalBytes, err)
	}
	mu.Lock()
	sent[route] += totalBytes
	mu.Unlock()
	(*out).Close()
}

func handleRemote(bufIn *bufio.Reader, conn, out *net.Conn, firstOut []byte, full, ruleBased bool, req *http.Request, mode, network, dest, host, port string,
	timeout, total, route, server int, start, stop2 chan bool, try, do chan int, connection bool, lastReq *time.Time) {
	var err error
	if !<-start {
		start <- false
		return
	}
	var dp string
	if route == 1 {
		dp = net.JoinHostPort(dest, port)
		logger.Printf("%s %5d:  *          %d Dialing to %s %s", mode, total, route, network, dp)
		*out, err = net.DialTimeout(network, dp, time.Second*time.Duration(timeout))
	} else {
		dialer, err1 := proxy.SOCKS5("tcp", socks[server-1], nil, &net.Dialer{Timeout: time.Second * time.Duration(timeout)})
		if err1 != nil {
			logger.Printf("%s %5d: ERR         %d Failed to dial SOCKS server %s. Error: %s", mode, total, route, socks[server-1], err)
			try <- 0
			return
		}
		if host != "" {
			dp = net.JoinHostPort(host, port)
		} else {
			dp = net.JoinHostPort(dest, port)
		}
		logger.Printf("%s %5d:  *          %d Dialing to %s %s via %s", mode, total, route, network, dp, socks[server-1])
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
			logger.Printf("%s %5d: SYN         %d Initial connection timeout", mode, total, route)
		} else if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "reset") {
			logger.Printf("%s %5d: RST         %d Initial connection was reset", mode, total, route)
		} else if strings.Contains(err.Error(), "no such host") {
			logger.Printf("%s %5d: NXD         %d Domain lookup failed", mode, total, route)
		} else {
			logger.Printf("%s %5d: ERR         %d Failed to dial server. Error: %s", mode, total, route, err)
		}
		try <- 0
		return
	}
	/*if tcp, ok := (*out).(*net.TCPConn); ok {
		tcp.SetLinger(0)
	}*/
	mu.Lock()
	open[route]++
	mu.Unlock()
	defer func() {
		(*out).Close()
		mu.Lock()
		open[route]--
		mu.Unlock()
	}()

	// Match IP rules
	destIsIP := net.ParseIP(dest) != nil
	if host == "" && !destIsIP {
		host = dest
	}
	if route == 1 && !ruleBased && !destIsIP {
		// dest is hostname
		if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
			var newRoute int
			newRoute, ruleBased = matchIP(total, mode, tcpAddr.IP)
			switch newRoute {
			case -1:
				stop2 <- true
				try <- 0
				return
			case 1:
				stop2 <- true
			case 2:
				try <- 0
				return
			}
		}
	}

	// Send first byte to server
	if len(firstOut) > 0 {
		(*out).SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		if _, err := (*out).Write(firstOut); err != nil {
			logger.Printf("%s %5d: ERR         %d Failed to send first byte to server. Error: %s", mode, total, route, err)
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
	if full {
		(*out).SetReadDeadline(time.Now().Add(time.Millisecond * 100))
	} else {
		(*out).SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
	}
	if mode == "H" && req != nil {
		firstResp, err = http.ReadResponse(bufOut, req)
	} else {
		n, err = bufOut.Read(firstIn)
	}
	if err != nil {
		// If request is only partially sent, timeout is normal
		if !full || !strings.Contains(err.Error(), "time") {
			if strings.Contains(err.Error(), "reset") {
				logger.Printf("%s %5d:     RST     %d First byte was reset", mode, total, route)
			} else if strings.Contains(err.Error(), "time") {
				logger.Printf("%s %5d:     PSH     %d First byte timeout", mode, total, route)
			} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				logger.Printf("%s %5d:     FIN     %d First byte from server is EOF", mode, total, route)
			} else if !strings.Contains(err.Error(), "closed") {
				logger.Printf("%s %5d:     ERR     %d Connection closed before receiving first byte. Error: %s", mode, total, route, err)
			}
			try <- 0
			return
		}
	}
	(*out).SetReadDeadline(time.Time{})
	ttfb := time.Since(sentTime)
	if n > 0 {
		logger.Printf("%s %5d:      *      %d First %d bytes from server. TTFB %d ms", mode, total, route, n, ttfb.Milliseconds())
		if req != nil {
			if resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(firstIn[:n])), req); err == nil {
				logger.Printf("%s %5d:      *      %d HTTP Status %s Content-length %d", mode, total, route, resp.Status, resp.ContentLength)
			} else {
				logger.Printf("%s %5d:     ERR     %d Failed to parse HTTP response. Error: %s", mode, total, route, err)
			}
		}
	}
	try <- server

	// Wait for signal to go ahead
	doServer := <-do
	do <- doServer
	if doServer == server {
		*lastReq = time.Now()
		logger.Printf("%s %5d:      *      %d Continue %s %s -> %s", mode, total, route, (*out).LocalAddr().Network(), (*out).LocalAddr(), (*out).RemoteAddr())
		if mode == "H" && req != nil {
			var totalBytes int64
			for {
				var resp *http.Response
				if firstResp != nil {
					resp = firstResp
					firstResp = nil
					logger.Printf("H %5d:      *      %d HTTP Status %s Content-length %d. TTFB %d ms", total, route, resp.Status, resp.ContentLength, ttfb.Milliseconds())
				} else {
					var err error
					resp, err = http.ReadResponse(bufOut, req)
					totalTime := time.Since(sentTime)
					if err != nil {
						if errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "closed") {
							logger.Printf("H %5d:          *  %d Remote connection closed. Received %d bytes in %.1f s", total, route, totalBytes, totalTime.Seconds())
							if route == 1 && !ruleBased && totalTime.Seconds() > 30 && totalBytes < 1000 {
								logger.Printf("H %5d:         ERR %d Suspiciously blocked connection to %s %s. %.1f s since last request", total, route, host, (*out).RemoteAddr(), time.Since(*lastReq).Seconds())
								/*if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:         SET %d %s added to blocked list", total, route, tcpAddr.IP)
									blocked.add(tcpAddr.IP)
								}*/
							}
						} else if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
							logger.Printf("H %5d:         RST %d Remote connection reset. Received %d bytes in %.1f s, %.1f s since last request. Error: %s", total, route, totalBytes, totalTime.Seconds(), time.Since(*lastReq).Seconds(), err)
							if route == 1 && !ruleBased && totalTime.Seconds() < blockSafeTime {
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:         SET %d %s %s added to blocked list", total, route, host, tcpAddr.IP)
									blockedIPSet.add(tcpAddr.IP)
									blockedHostSet.add(host)
								}
							}
						} else {
							logger.Printf("H %5d:         ERR %d Remote connection closed. Received %d bytes in %.1f s. Error: %s", total, route, totalBytes, totalTime.Seconds(), err)
						}
						mu.Lock()
						received[route] += totalBytes
						mu.Unlock()
						break
					}
					logger.Printf("H %5d:      *      %d HTTP Status %s Content-length %d", total, route, resp.Status, resp.ContentLength)
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
					logger.Printf("H %5d:     ERR     %d Failed to write HTTP header to client. Error: %s", total, route, err)
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
						logger.Printf("H %5d:      *      %d Parsed %d chunks and %d bytes", total, route, n, bytes)
					} else {
						if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
							logger.Printf("H %5d:     RST     %d Chunks parsing is reset by server. %.1f s since last request. Error: %s", total, route, time.Since(*lastReq).Seconds(), err)
							if route == 1 && !ruleBased && time.Since(*lastReq).Seconds() < blockSafeTime {
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:     SET     %d %s %s added to blocked list", total, route, host, tcpAddr.IP)
									blockedIPSet.add(tcpAddr.IP)
									blockedHostSet.add(host)
								}
							}
						} else {
							logger.Printf("H %5d:     ERR     %d Parsed %d chunks and %d bytes but failed to write to client. Error: %s", total, route, n, bytes, err)
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
				} else if resp.ContentLength != 0 && req.Method != "HEAD" {
					bytes, err := receiveSend(conn, resp.Body, ruleBased, mode, dest, host, (*out).RemoteAddr(), total, route, lastReq)
					totalBytes += bytes
					resp.Body.Close()
					if err != nil && !errors.Is(err, io.EOF) {
						// Linux: "read: connection reset by peer"
						// Windows: "wsarecv: An existing connection was forcibly closed by the remote host."
						if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
							logger.Printf("H %5d:     RST     %d Reading HTTP body gets reset by server. %.1f s since last request. Error: %s", total, route, time.Since(*lastReq).Seconds(), err)
							if route == 1 && !ruleBased && time.Since(*lastReq).Seconds() < blockSafeTime {
								if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
									logger.Printf("H %5d:     SET     %d %s %s added to blocked list", total, route, host, tcpAddr.IP)
									blockedIPSet.add(tcpAddr.IP)
									blockedHostSet.add(host)
								}
							}
						} else {
							logger.Printf("H %5d:     ERR     %d Failed to write HTTP body to client. Error: %s", total, route, err)
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
			totalBytes := int64(n)
			bytes, err := receiveSend(conn, bufOut, ruleBased, mode, dest, host, (*out).RemoteAddr(), total, route, lastReq)
			totalBytes += bytes + int64(bufOut.Buffered())
			totalTime := time.Since(sentTime)
			if err == nil || errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "time") {
				logger.Printf("%s %5d:          *  %d Remote connection closed. Received %d bytes in %.1f s", mode, total, route, totalBytes, totalTime.Seconds())
				if route == 1 && !ruleBased && totalTime.Seconds() > 30 && totalBytes < 1000 {
					logger.Printf("%s %5d:         ERR %d Suspiciously blocked connection to %s %s, %.1f s since last request", mode, total, route, host, (*out).RemoteAddr(), time.Since(*lastReq).Seconds())
					/*if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
						logger.Printf("%s %5d:         SET %d %s added to blocked list", mode, total, route, tcpAddr.IP)
						blocked.add(tcpAddr.IP)
					}*/
				}
			} else if strings.Contains(err.Error(), "read") && strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "forcibly") && strings.Contains(err.Error(), "remote") {
				logger.Printf("%s %5d:         RST %d Remote connection reset. Received %d bytes in %.1f s, %.1f s since last request. Error: %s", mode, total, route, totalBytes, totalTime.Seconds(), time.Since(*lastReq).Seconds(), err)
				if route == 1 && !ruleBased && totalTime.Seconds() < blockSafeTime {
					if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
						logger.Printf("%s %5d:         SET %d %s %s added to blocked list", mode, total, route, host, tcpAddr.IP)
						blockedIPSet.add(tcpAddr.IP)
						blockedHostSet.add(host)
					}
				}
			} else {
				logger.Printf("%s %5d:         ERR %d Remote connection closed. Received %d bytes in %.1f s. Error: %s", mode, total, route, totalBytes, totalTime.Seconds(), err)
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
		route = findRouteForHost(host, hostRules)
		if route != 0 {
			logger.Printf("%s %5d:  *            Host rule matched for %s. Select route %d", mode, total, host, route)
			ruleBased = true
		}
	}
	if route == 0 && (blockedHostSet.contain(host) || slowHostSet.contain(host)) {
		route = 2
		logger.Printf("%s %5d: SET           %s found in blocked or slow list. Select route %d", mode, total, host, route)
	}
	return
}

func matchIP(total int, mode string, ip net.IP) (route int, ruleBased bool) {
	if ipRules != nil {
		route = findRouteForIP(ip, ipRules)
		if route != 0 {
			logger.Printf("%s %5d:  *            IP rule matched for %s. Select route %d", mode, total, ip, route)
			ruleBased = true
		}
	}
	if route == 0 && (blockedIPSet.contain(ip) || slowIPSet.contain(ip)) {
		route = 2
		logger.Printf("%s %5d: SET           %s found in blocked or slow list. Select route %d", mode, total, ip, route)
	}
	return
}

func receiveSend(conn *net.Conn, out io.Reader, ruleBased bool, mode, dest, host string, addr net.Addr, total, route int, lastReq *time.Time) (bytes int64, err error) {
	if route == 1 && *slowSpeed > 0 && !ruleBased {
		var sample, accum int64
		var sampleStart, accumStart time.Time
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
			if accumStart.Before(*lastReq) {
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
					logger.Printf("%s %5d:     SET     %d %s %s added to slow list", mode, total, route, host, tcpAddr.IP)
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
			// If n = bufferSize, either connection is too fast or client is slow
			if time.Since(accumStart).Seconds() > sampleTime && sample >= sampleSize && n < bufferSize {
				speed := float64(sample) / 1000 / time.Since(sampleStart).Seconds()
				aveSpeed := float64(accum) / 1000 / time.Since(accumStart).Seconds()
				if !slow && (aveSpeed < float64(*slowSpeed) || speed < float64(*slowSpeed)*0.3) {
					logger.Printf("%s %5d:      *      %d Slow connection to %s %s at %.1f kB/s, average %.1f kB/s, %.1f s since last request", mode, total, route, host, addr, speed, aveSpeed, time.Since(accumStart).Seconds())
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
