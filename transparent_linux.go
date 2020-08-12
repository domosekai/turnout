// Released under MIT License
// Copyright (c) 2020 domosekai

// Transparent proxy (Linux only)

package main

import (
	"bufio"
	"log"
	"net"
	"strings"
	"syscall"
)

var localAddrs []net.Addr
var tranPort string

func doTransparent(total *int) {
	defer wg.Done()
	addr, err := net.ResolveTCPAddr("tcp", *tranAddr)
	if err != nil {
		log.Fatal(err)
	}
	_, tranPort, _ = net.SplitHostPort(*tranAddr)
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	if *tproxy {
		fd, err := listener.File()
		if err != nil {
			log.Fatal(err)
		}
		defer fd.Close()
		if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
			log.Fatal(err)
		}
	}
	logger.Printf("Transparent proxy started on TCP %s", addr)
	localAddrs, err = net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}
	for {
		var conn connection
		var err error
		conn.in, err = listener.Accept()
		if err != nil {
			logger.Printf("Listener failed to accept new connection. Error: %s", err)
			continue
		}
		mu.Lock()
		*total++
		open[0]++
		conn.total = *total
		mu.Unlock()
		go conn.handleLocal()
	}
}

func isLocalAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	for _, localAddr := range localAddrs {
		if strings.HasPrefix(localAddr.String(), host) && port == tranPort {
			return true
		}
	}
	return false
}

func (c *connection) handleLocal() {
	defer func() {
		c.in.Close()
		mu.Lock()
		open[0]--
		mu.Unlock()
	}()

	// Get original destination
	var dest string
	c.network = c.in.LocalAddr().Network()
	if *tproxy {
		dest = c.in.LocalAddr().String()
	}
	if dest == "" || isLocalAddr(dest) {
		if tcp, ok := c.in.(*net.TCPConn); ok {
			var err error
			if dest, err = getOriginalDst(tcp); err != nil {
				logger.Printf("Failed to get original destination in redirect mode. Error: %s", err)
				return
			}
			if dest == "" || isLocalAddr(dest) {
				logger.Print("Error: Destination is a local address. Check your configuration.")
				return
			}
		} else {
			return
		}
	}
	if *verbose {
		logger.Printf("T %5d:  *            New %s %s -> %s", c.total, c.network, c.in.RemoteAddr(), dest)
	}
	c.dest, c.dport, _ = net.SplitHostPort(dest)
	c.bufIn = bufio.NewReader(c.in)
	c.mode = "T"
	c.getFirstByte()
}
