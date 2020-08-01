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
		conn, err := listener.Accept()
		if err != nil {
			logger.Printf("Failed to accept new connection. Error: %s", err)
			continue
		}
		mu.Lock()
		*total++
		open[0]++
		mu.Unlock()
		go handleHTTP(conn, *total)
	}
}

func handleHTTP(conn net.Conn, total int) {
	defer func() {
		conn.Close()
		mu.Lock()
		open[0]--
		mu.Unlock()
	}()

	new := true
	var currentHost, currentPort string
	var totalBytes int64
	var out *net.Conn
	var route int
	logger.Printf("H %5d:  *            New %s %s -> %s", total, conn.LocalAddr().Network(), conn.RemoteAddr(), conn.LocalAddr())
	bufIn := bufio.NewReader(conn)
	var lastReq time.Time
	var ch chan *http.Request

	for {
		req, err := http.ReadRequest(bufIn)
		if err != nil {
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") {
				logger.Printf("H %5d:          *    Local connection closed. Sent %d bytes", total, totalBytes)
			} else if strings.Contains(err.Error(), "reset") {
				logger.Printf("H %5d:          *    Local connection reset. Sent %d bytes", total, totalBytes)
			} else if strings.Contains(err.Error(), "malformed") {
				logger.Printf("H %5d:         ERR   Local connection closed due to bad HTTP request. Sent %d bytes. Error: %s", total, totalBytes, err)
			} else {
				logger.Printf("H %5d:          *    Local connection closed. Sent %d bytes. Error: %s", total, totalBytes, err)
			}
			mu.Lock()
			sent[route] += totalBytes
			mu.Unlock()
			break
		}
		logger.Printf("H %5d:  *            HTTP %s Host %s Content-length %d", total, req.Method, req.Host, req.ContentLength)
		host, port := normalizeHostname(req.Host, "80")
		if host == "" {
			logger.Printf("H %5d: ERR           Invalid hostname: %s", total, req.Host)
			rejectHTTP(&conn)
			break
		}

		if req.Method == "CONNECT" {
			if out != nil {
				(*out).Close()
			}
			resp := &http.Response{
				Status:     "200 Connection established",
				StatusCode: 200,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
			}
			respBytes, _ := httputil.DumpResponse(resp, false)
			if _, err := conn.Write(respBytes); err != nil {
				break
			}
			handleFirstByte(bufIn, &conn, "H", "tcp", host, port, false, total)
			break
		} else {
			req.RequestURI = strings.TrimPrefix(req.RequestURI, "http://")
			req.RequestURI = strings.TrimPrefix(req.RequestURI, net.JoinHostPort(host, port))
			req.RequestURI = strings.TrimPrefix(req.RequestURI, req.Host)
			req.RequestURI = strings.TrimPrefix(req.RequestURI, host)
			connection := false
			if req.Header.Get("Connection") == "" {
				if value := req.Header.Get("Proxy-Connection"); value != "" {
					req.Header.Add("Connection", value)
					req.Close = shouldClose(req.ProtoMajor, req.ProtoMinor, req.Header)
				}
			} else {
				connection = true
			}
			req.Header.Del("Proxy-Connection")
			header, _ := httputil.DumpRequest(req, false)
			totalBytes += int64(len(header))
			if host != currentHost || port != currentPort {
				currentHost = host
				currentPort = port
				new = true
			}
			if new {
				if out != nil {
					(*out).Close()
				}
				ch = make(chan *http.Request, httpPipeline)
				if out, route = getRoute(bufIn, &conn, header, req.ContentLength != 0, req, ch, "H", "tcp", host, "", port, true, total, connection, false, &lastReq); out != nil {
					new = false
				} else {
					bufIn.Discard(bufIn.Buffered())
					rejectHTTP(&conn)
					continue
				}
			} else {
				var err error
				if out != nil {
					ch <- req
					_, err = (*out).Write(header)
				}
				if out == nil || err != nil {
					ch = make(chan *http.Request, httpPipeline)
					if out, route = getRoute(bufIn, &conn, header, req.ContentLength != 0, req, ch, "H", "tcp", host, "", port, true, total, connection, false, &lastReq); out == nil {
						logger.Printf("H %5d: ERR           Failed to send HTTP header to server. Error: %s", total, err)
						bufIn.Discard(bufIn.Buffered())
						rejectHTTP(&conn)
						continue
					}
				}
			}
			if req.ContentLength == -1 && len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked" {
				cr := newChunkedReader(bufIn)
				n, bytes, err := cr.copy(out)
				totalBytes += bytes
				if errors.Is(err, io.EOF) {
					logger.Printf("H %5d:  *            Parsed %d chunks and %d bytes", total, n, bytes)
				} else {
					logger.Printf("H %5d: ERR           Parsed %d chunks and %d bytes but failed to sent to server. Error: %s", total, n, bytes, err)
					bufIn.Discard(bufIn.Buffered())
					continue
				}
				// Write trailer
				var trailer []byte
				for {
					line, err := bufIn.ReadSlice('\n')
					trailer = append(trailer, line...)
					if len(line) == 2 || err != nil {
						n, _ := (*out).Write(trailer)
						totalBytes += int64(n)
						break
					}
				}
			} else if req.ContentLength != 0 {
				bytes, err := io.Copy(*out, req.Body)
				totalBytes += bytes
				req.Body.Close()
				if err != nil {
					logger.Printf("H %5d: ERR           Failed to send HTTP body to server. Error: %s", total, err)
					bufIn.Discard(bufIn.Buffered())
					continue
				}
			}
			lastReq = time.Now()
		}
	}
	if out != nil {
		(*out).Close()
	}
}

func rejectHTTP(conn *net.Conn) {
	resp := &http.Response{
		Status:     "502 Bad Gateway", // Squid sends 502 on unreachable hosts, 503 on failed DNS, 200 on CONNECT method
		StatusCode: 502,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	respBytes, _ := httputil.DumpResponse(resp, false)
	(*conn).Write(respBytes)
}
