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
		var conn connection
		var err error
		conn.in, err = listener.Accept()
		if err != nil {
			logger.Printf("Failed to accept new connection. Error: %s", err)
			continue
		}
		conn.bufIn = bufio.NewReader(conn.in)
		mu.Lock()
		*total++
		open[0]++
		conn.total = *total
		mu.Unlock()
		go conn.handleHTTP()
	}
}

func (c *connection) handleHTTP() {
	defer func() {
		c.in.Close()
		mu.Lock()
		open[0]--
		mu.Unlock()
	}()

	new := true
	var totalBytes int64
	if *verbose {
		logger.Printf("H %5d:  *            New %s %s -> %s", c.total, c.in.LocalAddr().Network(), c.in.RemoteAddr(), c.in.LocalAddr())
	}
	c.mode = "H"
	c.network = "tcp"

	for {
		req, err := http.ReadRequest(c.bufIn)
		if err != nil {
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") {
				if *verbose {
					logger.Printf("H %5d:          *    Local connection closed. Sent %d bytes.", c.total, totalBytes)
				}
			} else if strings.Contains(err.Error(), "reset") {
				if *verbose {
					logger.Printf("H %5d:          *    Local connection reset. Sent %d bytes.", c.total, totalBytes)
				}
			} else if strings.Contains(err.Error(), "malformed") {
				if *verbose {
					logger.Printf("H %5d:         ERR   Local connection closed due to bad HTTP request. Sent %d bytes. Error: %s", c.total, totalBytes, err)
				} else {
					logger.Printf("H %5d:         ERR   Bad HTTP request from client. Error: %s", c.total, err)
				}
			} else {
				if *verbose {
					logger.Printf("H %5d:          *    Local connection closed. Sent %d bytes. Error: %s", c.total, totalBytes, err)
				}
			}
			mu.Lock()
			sent[c.route] += totalBytes
			mu.Unlock()
			break
		}
		if *verbose {
			logger.Printf("H %5d:  *            HTTP %s Host %s Content-length %d", c.total, req.Method, req.Host, req.ContentLength)
		}
		host, port := normalizeHostname(req.Host, "80")
		if host == "" {
			logger.Printf("H %5d: ERR           Invalid HTTP host: %s", c.total, req.Host)
			rejectHTTP(c.in)
			break
		}

		if req.Method == "CONNECT" {
			if c.out != nil {
				(*c.out).Close()
			}
			resp := &http.Response{
				Status:     "200 Connection established",
				StatusCode: 200,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
			}
			respBytes, _ := httputil.DumpResponse(resp, false)
			if _, err := c.in.Write(respBytes); err != nil {
				break
			}
			c.dest = host
			c.host = ""
			c.dport = port
			c.first = nil
			c.currentReq = nil
			c.tls = false
			c.hasConnection = false
			c.getFirstByte()
			break
		} else {
			req.RequestURI = strings.TrimPrefix(req.RequestURI, "http://")
			req.RequestURI = strings.TrimPrefix(req.RequestURI, net.JoinHostPort(host, port))
			req.RequestURI = strings.TrimPrefix(req.RequestURI, req.Host)
			req.RequestURI = strings.TrimPrefix(req.RequestURI, host)
			if req.Header.Get("Connection") == "" {
				if value := req.Header.Get("Proxy-Connection"); value != "" {
					req.Header.Add("Connection", value)
					req.Close = shouldClose(req.ProtoMajor, req.ProtoMinor, req.Header)
				}
				c.hasConnection = false
			} else {
				c.hasConnection = true
			}
			req.Header.Del("Proxy-Connection")
			header, _ := httputil.DumpRequest(req, false)
			totalBytes += int64(len(header))
			if host != c.dest || port != c.dport {
				c.dest = host
				c.host = ""
				c.dport = port
				new = true
			}
			if new {
				if c.out != nil {
					(*c.out).Close()
				}
				c.reqs = make(chan *http.Request, httpPipeline)
				c.currentReq = req
				c.first = header
				c.firstIsFull = req.ContentLength != 0
				c.tls = false
				if c.getRoute() {
					new = false
				} else {
					logger.Printf("H %5d: ERR           No route found for %s:%s", c.total, host, port)
					c.bufIn.Discard(c.bufIn.Buffered())
					rejectHTTP(c.in)
					continue
				}
			} else {
				var err error
				if c.out != nil {
					c.reqs <- req
					_, err = (*c.out).Write(header)
				}
				if c.out == nil || err != nil {
					c.reqs = make(chan *http.Request, httpPipeline)
					c.currentReq = req
					c.first = header
					c.firstIsFull = req.ContentLength != 0
					c.tls = false
					if c.getRoute() {
						logger.Printf("H %5d: ERR           No route found for %s:%s", c.total, host, port)
						c.bufIn.Discard(c.bufIn.Buffered())
						rejectHTTP(c.in)
						continue
					}
				} else {
					c.lastReq = time.Now()
				}
			}
			if req.ContentLength == -1 && len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked" {
				cr := newChunkedReader(c.bufIn)
				n, bytes, err := cr.copy(*c.out)
				totalBytes += bytes
				if errors.Is(err, io.EOF) {
					if *verbose {
						logger.Printf("H %5d:  *            Parsed %d chunks and %d bytes", c.total, n, bytes)
					}
				} else {
					if *verbose {
						logger.Printf("H %5d: ERR           Parsed %d chunks and %d bytes but failed to sent to server. Error: %s", c.total, n, bytes, err)
					}
					c.bufIn.Discard(c.bufIn.Buffered())
					continue
				}
				// Write trailer
				var trailer []byte
				for {
					line, err := c.bufIn.ReadSlice('\n')
					trailer = append(trailer, line...)
					if len(line) == 2 || err != nil {
						n, _ := (*c.out).Write(trailer)
						totalBytes += int64(n)
						break
					}
				}
				c.lastReq = time.Now()
			} else if req.ContentLength != 0 {
				bytes, err := io.Copy(*c.out, req.Body)
				totalBytes += bytes
				req.Body.Close()
				if err != nil {
					if *verbose {
						logger.Printf("H %5d: ERR           Failed to send HTTP body to server. Error: %s", c.total, err)
					}
					c.bufIn.Discard(c.bufIn.Buffered())
					continue
				}
				c.lastReq = time.Now()
			}
		}
	}
	if c.out != nil {
		(*c.out).Close()
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
