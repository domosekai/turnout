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

const initialBlock = 5000

// Wait for first byte from client, should come immediately with ACK in the 3-way handshake
// Otherwise it may never come (like FTP)
func handleFirstByte(bufIn *bufio.Reader, conn *net.Conn, mode, network, dest, port string, sniff bool, total int) {
	(*conn).SetReadDeadline(time.Now().Add(time.Millisecond * 100))
	first := make([]byte, initialBlock)
	n, err := bufIn.Read(first)
	if err == nil {
		logger.Printf("%s %5d:  *            First %d bytes from client", mode, total, n)
	} else if !strings.Contains(err.Error(), "time") {
		logger.Printf("%s %5d:  *            Failed to read first byte from client. Error: %s", mode, total, err)
		return
	}
	(*conn).SetReadDeadline(time.Time{})

	// TLS Client Hello
	if n > recordHeaderLen && recordType(first[0]) == recordTypeHandshake && first[recordHeaderLen] == typeClientHello {
		if m := new(clientHelloMsg); m.unmarshal(first[recordHeaderLen:n]) {
			logger.Printf("%s %5d:  *            TLS SNI %s", mode, total, m.serverName)
			host := ""
			if sniff {
				host, _ = normalizeHostname(m.serverName, port)
			}
			if out, route := getRoute(bufIn, conn, first[:n], n == initialBlock, nil, mode, network, dest, host, port, false, total, false); out != nil {
				relayLocal(bufIn, out, mode, total, route, n)
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
			if out, route := getRoute(bufIn, conn, first[:n], n == initialBlock, req, mode, network, dest, host, port, true, total, false); out != nil {
				relayLocal(bufIn, out, mode, total, route, n)
			}
			return
		}
	}

	// Unknown protocol
	if out, route := getRoute(bufIn, conn, first[:n], n == initialBlock, nil, mode, network, dest, "", port, true, total, false); out != nil {
		relayLocal(bufIn, out, mode, total, route, n)
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
	successive bool, total int, connection bool) (*net.Conn, int) {
	// Dial each route and send first byte out
	start1 := make(chan bool, 1)
	start2 := make(chan bool, 1)
	try1 := make(chan bool, 1)
	try2 := make(chan bool, 1)
	stop2 := make(chan bool, 1)
	do1 := make(chan bool, 1)
	do2 := make(chan bool, 1)
	var out1, out2 net.Conn
	var ok1, ok2 bool
	var available int

	// Match rules
	route := 0
	if host != "" && hostRules != nil {
		route = findRouteForHost(host, hostRules)
		if route != 0 {
			logger.Printf("%s %5d:  *            Host rule matched. Select route %d", mode, total, route)
		}
	}
	if route == 0 {
		if ip := net.ParseIP(dest); ip != nil {
			// dest is IP
			if ipRules != nil {
				route = findRouteForIP(ip, ipRules)
				if route != 0 {
					logger.Printf("%s %5d:  *            IP rule matched for %s. Select route %d", mode, total, ip, route)
				}
			}
		} else {
			// dest is hostname
			if hostRules != nil {
				route = findRouteForHost(dest, hostRules)
				if route != 0 {
					logger.Printf("%s %5d:  *            Host rule matched. Select route %d", mode, total, route)
				}
			}
		}
	}
	switch route {
	case 0:
		start1 <- true
		if !successive {
			start2 <- true
		}
		available = 2
	case 1:
		start1 <- true
		start2 <- false
		available = 1
	case 2:
		start1 <- false
		start2 <- true
		available = 1
	}

	net1 := network
	net2 := network
	if *force4 {
		net1 = "tcp4"
	}
	if route != 2 {
		go handleRemote(bufIn, conn, &out1, first, full, req, mode, net1, dest, host, port, int(*r1Timeout), total, 1, start1, try1, stop2, do1, connection)
	}
	if route != 1 {
		go handleRemote(bufIn, conn, &out2, first, full, req, mode, net2, dest, host, port, int(*r2Timeout), total, 2, start2, try2, stop2, do2, connection)
	}

	// Wait for first byte from server
	timer1 := time.NewTimer(time.Second * time.Duration(*r1Priority)) // during which route 1 is prioritized, or in successive mode start of route 2 is deferred
	timer2 := time.NewTimer(time.Second * time.Duration(*r1Timeout+*r2Timeout))
	wait := true
	bad2 := false
	for {
		// Make sure no channel is written twice without return
		// and no goroutine will wait forever
		select {
		case bad2 = <-stop2:
			// This is before ok1 returns either true or false
			if bad2 && available == 2 {
				if successive {
					start2 <- false
				} else {
					do2 <- false
				}
			}
		case ok1 = <-try1:
			if ok1 {
				do1 <- true
				if available == 2 && !bad2 {
					if successive {
						start2 <- false
					} else {
						do2 <- false
					}
				}
				return &out1, 1
			}
			available--
			if available > 0 && !bad2 {
				if successive {
					start2 <- true
				}
				if ok2 {
					do2 <- true
					return &out2, 2
				}
			} else {
				return nil, 0
			}
		case ok2 = <-try2:
			if ok2 && !bad2 {
				if available == 1 {
					do2 <- true
					return &out2, 2
				} else if !wait {
					do2 <- true
					do1 <- false
					return &out2, 2
				}
			} else {
				available--
				if available == 0 {
					return nil, 0
				}
			}
		case <-timer1.C:
			wait = false
			if ok2 && !bad2 {
				do2 <- true
				if available == 2 {
					do1 <- false
				}
				return &out2, 2
			}
		case <-timer2.C:
			do1 <- false
			if !bad2 {
				start2 <- false
				do2 <- false
			}
			return nil, 0
		}
	}
}

func relayLocal(bufIn *bufio.Reader, out *net.Conn, mode string, total, route, n int) {
	bytes, err := bufIn.WriteTo(*out)
	totalBytes := bytes + int64(n)
	if err == nil || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "time") {
		logger.Printf("%s %5d:          *    Local connection closed. Sent %d bytes.", mode, total, totalBytes)
	} else if strings.Contains(err.Error(), "reset") {
		logger.Printf("%s %5d:          *    Local connection reset. Sent %d bytes.", mode, total, totalBytes)
	} else {
		logger.Printf("%s %5d:         ERR   Local connection closed. Sent %d bytes. Error: %s", mode, total, totalBytes, err)
	}
	mu.Lock()
	sent[route] += totalBytes
	mu.Unlock()
	(*out).Close()
}

func handleRemote(bufIn *bufio.Reader, conn, out *net.Conn, firstOut []byte, full bool, req *http.Request, mode, network, dest, host, port string,
	timeout, total int, route int, start, try, stop2, do chan bool, connection bool) {
	var err error
	if !<-start {
		return
	}
	var dp string
	if route == 1 {
		dp = net.JoinHostPort(dest, port)
		logger.Printf("%s %5d:  *          %d Dialing to %s %s", mode, total, route, network, dp)
		*out, err = net.DialTimeout(network, dp, time.Second*time.Duration(timeout))
	} else if *socksAddr != "" {
		dialer, err1 := proxy.SOCKS5("tcp", *socksAddr, nil, &net.Dialer{Timeout: time.Second * time.Duration(timeout)})
		if err1 != nil {
			logger.Printf("%s %5d: ERR         %d Failed to dial SOCKS server. Error: %s", mode, total, route, err)
			try <- false
			return
		}
		if host != "" {
			dp = net.JoinHostPort(host, port)
		} else {
			dp = net.JoinHostPort(dest, port)
		}
		logger.Printf("%s %5d:  *          %d Dialing to %s %s", mode, total, route, network, dp)
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
		try <- false
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
	if route == 1 && ipRules != nil {
		if ip := net.ParseIP(dest); ip == nil {
			if tcpAddr := (*out).RemoteAddr().(*net.TCPAddr); tcpAddr != nil {
				if route := findRouteForIP(tcpAddr.IP, ipRules); route != 0 {
					logger.Printf("%s %5d:  *            IP rule matched for %s. Select route %d", mode, total, tcpAddr.IP, route)
					if route == 1 {
						stop2 <- true
					}
					if route == 2 {
						try <- false
						return
					}
				}
			}
		}
	}

	// Send first byte to server
	if len(firstOut) > 0 {
		(*out).SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		if _, err := (*out).Write(firstOut); err != nil {
			logger.Printf("%s %5d: ERR         %d Failed to send first byte to server. Error: %s", mode, total, route, err)
			try <- false
			return
		}
		(*out).SetWriteDeadline(time.Time{})
	}

	// Wait for response from server
	firstIn := make([]byte, initialBlock)
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
			try <- false
			return
		}
	}
	(*out).SetReadDeadline(time.Time{})
	if n > 0 {
		logger.Printf("%s %5d:      *      %d First %d bytes from server", mode, total, route, n)
		if req != nil {
			if resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(firstIn[:n])), req); err == nil {
				logger.Printf("%s %5d:      *      %d HTTP Status %s Content-length %d", mode, total, route, resp.Status, resp.ContentLength)
			} else {
				logger.Printf("%s %5d:     ERR     %d Failed to parse HTTP response. Error: %s", mode, total, route, err)
			}
		}
	}
	try <- true

	// Wait for signal to go ahead
	if <-do {
		logger.Printf("%s %5d:      *      %d Continue %s %s -> %s", mode, total, route, (*out).LocalAddr().Network(), (*out).LocalAddr().String(), (*out).RemoteAddr().String())
		var totalBytes int64
		if mode == "H" && req != nil {
			for {
				var resp *http.Response
				if firstResp != nil {
					resp = firstResp
					firstResp = nil
				} else {
					resp, err = http.ReadResponse(bufOut, req)
					if err != nil {
						if errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "closed") {
							logger.Printf("H %5d:          *  %d Remote connection closed. Received %d bytes.", total, route, totalBytes)
						} else {
							logger.Printf("H %5d:         ERR %d Remote connection closed due to bad HTTP response. Received %d bytes. Error: %s", total, route, totalBytes, err)
						}
						mu.Lock()
						received[route] += totalBytes
						mu.Unlock()
						break
					}
				}
				logger.Printf("H %5d:      *      %d HTTP Status %s Content-length %d", total, route, resp.Status, resp.ContentLength)
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
						logger.Printf("H %5d:     ERR     %d Parsed %d chunks and %d bytes but failed to write to client. Error: %s", total, route, n, bytes, err)
						totalBytes += int64(bufOut.Buffered())
						bufOut.Discard(bufOut.Buffered())
						(*out).Close()
						(*conn).Close()
						continue
					}
					// Write trailer
					for {
						line, err := bufOut.ReadSlice('\n')
						(*conn).Write(line)
						totalBytes += int64(len(line))
						if len(line) == 2 || err != nil {
							break
						}
					}
				} else if resp.ContentLength != 0 && req.Method != "HEAD" {
					bytes, err := io.Copy(*conn, resp.Body)
					totalBytes += bytes
					resp.Body.Close()
					if err != nil {
						logger.Printf("H %5d:     ERR     %d Failed to write HTTP body to client. Error: %s", total, route, err)
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
			totalBytes += int64(n)
			bytes, err := bufOut.WriteTo(*conn)
			totalBytes += bytes + int64(bufOut.Buffered())
			if err == nil || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "time") {
				logger.Printf("%s %5d:          *  %d Remote connection closed. Received %d bytes.", mode, total, route, totalBytes)
			} else if strings.Contains(err.Error(), "reset") {
				logger.Printf("%s %5d:         RST %d Remote connection reset. Received %d bytes.", mode, total, route, totalBytes)
			} else {
				logger.Printf("%s %5d:         ERR %d Remote connection closed. Received %d bytes. Error: %s", mode, total, route, totalBytes, err)
			}
			mu.Lock()
			received[route] += totalBytes
			mu.Unlock()
			(*conn).Close()
		}
	}
}
