// Released under MIT License
// Copyright (c) 2020 domosekai

// HTTP proxy

package main

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

const httpPipeline = 20

func doHTTP(total *int) {
	defer wg.Done()
	addr, err := net.ResolveTCPAddr("tcp", *httpAddr)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	logger.Printf("HTTP proxy started on TCP %s", addr)
	for {
		var lo localConn
		var err error
		lo.conn, err = listener.Accept()
		if err != nil {
			logger.Printf("Failed to accept new connection. Error: %s", err)
			continue
		}
		lo.buf = bufio.NewReader(lo.conn)
		mu.Lock()
		*total++
		open[0]++
		lo.total = *total
		mu.Unlock()
		go lo.handleHTTP()
	}
}

func (lo *localConn) handleHTTP() {
	defer func() {
		lo.conn.Close()
		mu.Lock()
		open[0]--
		mu.Unlock()
	}()

	newConn := true
	var totalBytes int64
	if *verbose {
		logger.Printf("H %5d:  *            New %s %s -> %s", lo.total, lo.conn.LocalAddr().Network(), lo.conn.RemoteAddr(), lo.conn.LocalAddr())
	}
	lo.mode = "H"
	lo.network = "tcp"
	re := new(remoteConn)

	for {
		req, err := http.ReadRequest(lo.buf)
		if err != nil {
			if re.sent > 0 {
				mu.Lock()
				sent[re.route] += re.sent
				mu.Unlock()
				totalBytes += re.sent
			}
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") {
				if *verbose {
					logger.Printf("H %5d:          *    Local connection closed. Sent %d bytes.", lo.total, totalBytes)
				}
			} else if strings.Contains(err.Error(), "reset") {
				if *verbose {
					logger.Printf("H %5d:          *    Local connection reset. Sent %d bytes.", lo.total, totalBytes)
				}
				if tcp, ok := (*re.conn).(*net.TCPConn); ok {
					tcp.SetLinger(0)
				}
			} else if strings.Contains(err.Error(), "malformed") {
				if *verbose {
					logger.Printf("H %5d:         ERR   Local connection closed due to bad HTTP request. Sent %d bytes. Error: %s", lo.total, totalBytes, err)
				} else {
					logger.Printf("H %5d:         ERR   Bad HTTP request from client. Error: %s", lo.total, err)
				}
			} else {
				if *verbose {
					logger.Printf("H %5d:          *    Local connection closed. Sent %d bytes. Error: %s", lo.total, totalBytes, err)
				}
			}
			break
		}
		if *verbose {
			logger.Printf("H %5d:  *            HTTP %s Host %s Content-length %d", lo.total, req.Method, req.Host, req.ContentLength)
		}
		host, port := normalizeHostname(req.Host, "80")
		if host == "" {
			logger.Printf("H %5d: ERR           Invalid HTTP host: %s", lo.total, req.Host)
			rejectHTTP(lo.conn)
			break
		}
		if host != lo.dest || port != lo.dport {
			lo.dest = host
			lo.key = net.JoinHostPort(host, port)
			if net.ParseIP(host) == nil {
				lo.host = host
			} else {
				lo.host = ""
			}
			lo.dport = port
			newConn = true
		}

		if req.Method == "CONNECT" {
			if re.conn != nil {
				(*re.conn).Close()
			}
			resp := &http.Response{
				Status:     "200 Connection established",
				StatusCode: 200,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
			}
			respBytes, _ := httputil.DumpResponse(resp, false)
			if _, err := lo.conn.Write(respBytes); err != nil {
				break
			}
			lo.getFirstByte()
			break
		} else {
			req.RequestURI = strings.TrimPrefix(req.RequestURI, "http://")
			req.RequestURI = strings.TrimPrefix(req.RequestURI, net.JoinHostPort(host, port))
			req.RequestURI = strings.TrimPrefix(req.RequestURI, req.Host)
			req.RequestURI = strings.TrimPrefix(req.RequestURI, host)
			var connection bool
			if req.Header.Get("Connection") == "" {
				if value := req.Header.Get("Proxy-Connection"); value != "" {
					req.Header.Add("Connection", value)
					req.Close = shouldClose(req.ProtoMajor, req.ProtoMinor, req.Header)
				}
				connection = false
			} else {
				connection = true
			}
			req.Header.Del("Proxy-Connection")
			header, _ := httputil.DumpRequest(req, false)
			if !newConn && re.conn != nil {
				re.hasConnection = connection
				re.reqs <- req
				if n, err := (*re.conn).Write(header); err == nil {
					re.sent += int64(n)
				} else {
					newConn = true
				}
			} else {
				newConn = true
			}
			if newConn {
				if re.conn != nil {
					(*re.conn).Close()
				}
				if re.sent > 0 {
					mu.Lock()
					sent[re.route] += re.sent
					mu.Unlock()
					totalBytes += re.sent
				}
				re = &remoteConn{
					hasConnection: connection,
					reqs:          make(chan *http.Request, httpPipeline),
					firstReq:      req,
					first:         header,
					firstIsFull:   req.ContentLength != 0,
				}
				if re.getRouteFor(*lo) {
					newConn = false
					re.sent += int64(len(header))
				} else {
					lo.buf.Discard(lo.buf.Buffered())
					rejectHTTP(lo.conn)
					continue
				}
			} else {
				re.lastReq = time.Now()
			}
			if req.ContentLength == -1 && len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked" {
				cr := newChunkedReader(lo.buf)
				n, bytes, err := cr.copy(*re.conn)
				re.sent += bytes
				if errors.Is(err, io.EOF) {
					if *verbose {
						logger.Printf("H %5d:  *            Parsed %d chunks and %d bytes", lo.total, n, bytes)
					}
				} else {
					if *verbose {
						logger.Printf("H %5d: ERR           Parsed %d chunks and %d bytes but failed to sent to server. Error: %s", lo.total, n, bytes, err)
					}
					lo.buf.Discard(lo.buf.Buffered())
					continue
				}
				// Write trailer
				var trailer []byte
				for {
					line, err := lo.buf.ReadSlice('\n')
					trailer = append(trailer, line...)
					if len(line) == 2 || err != nil {
						n, _ := (*re.conn).Write(trailer)
						re.sent += int64(n)
						break
					}
				}
				re.lastReq = time.Now()
			} else if req.ContentLength != 0 {
				bytes, err := io.Copy(*re.conn, req.Body)
				re.sent += bytes
				req.Body.Close()
				if err != nil {
					if *verbose {
						logger.Printf("H %5d: ERR           Failed to send HTTP body to server. Error: %s", lo.total, err)
					}
					lo.buf.Discard(lo.buf.Buffered())
					continue
				}
				re.lastReq = time.Now()
			}
		}
	}
	if re.conn != nil {
		(*re.conn).Close()
	}
}

func rejectHTTP(conn net.Conn) {
	resp := &http.Response{
		Status:     "502 Bad Gateway", // Squid sends 502 on unreachable hosts, 503 on failed DNS, 200 on CONNECT method
		StatusCode: 502,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	respBytes, _ := httputil.DumpResponse(resp, false)
	conn.Write(respBytes)
}
