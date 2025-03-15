// Released under MIT License
// Copyright (c) 2020 domosekai

// Transparent proxy (Linux only)

package main

import (
	"bufio"
	"fmt"
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
		var lo localConn
		var err error
		lo.conn, err = listener.Accept()
		if err != nil {
			logger.Printf("Listener failed to accept new connection. Error: %s", err)
			continue
		}
		mu.Lock()
		*total++
		open[0]++
		lo.total = *total
		mu.Unlock()
		go lo.handleLocal()
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

func (lo *localConn) handleLocal() {
	defer func() {
		lo.conn.Close()
		mu.Lock()
		open[0]--
		mu.Unlock()
	}()

	// Get original destination
	var dest string
	lo.network = lo.conn.LocalAddr().Network()
	if *tproxy {
		dest = lo.conn.LocalAddr().String()
	}
	if dest == "" || isLocalAddr(dest) {
		if tcp, ok := lo.conn.(*net.TCPConn); ok {
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
		logger.Printf("T %5d:  *            New %s %s -> %s", lo.total, lo.network, lo.conn.RemoteAddr(), dest)
	}
	lo.dest, lo.dport, _ = net.SplitHostPort(dest)
	lo.source = lo.conn.RemoteAddr().(*net.TCPAddr)
	lo.buf = bufio.NewReader(lo.conn)
	lo.mode = "T"
	lo.getFirstByte()
}

func transparentControl(network, address string, c syscall.RawConn) error {
	var err1, err2 error
	err := c.Control(func(fd uintptr) {
		err1 = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
		err2 = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if err1 != nil {
		return fmt.Errorf("failed to set socket option IP_TRANSPARENT: %v", err1)
	}
	if err2 != nil {
		return fmt.Errorf("failed to set socket option SO_REUSEADDR: %v", err2)
	}
	return err
}
