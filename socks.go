// Released under MIT License
// Copyright (c) 2020 domosekai

// SOCKS5 proxy

package main

import (
	"bufio"
	"log"
	"net"

	"turnout/socks5"
)

func doSocks(total *int) {
	defer wg.Done()

	addr, err := net.ResolveTCPAddr("tcp", *socksListenAddr)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	logger.Printf("SOCKS5 proxy started on TCP %s", addr)

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

		go lo.handleSocks()
	}
}

func (lo *localConn) handleSocks() {
	defer func() {
		lo.conn.Close()
		mu.Lock()
		open[0]--
		mu.Unlock()
	}()

	lo.network = lo.conn.LocalAddr().Network()

	err := socks5.PerformHandshake(lo.conn)
	if err != nil {
		return
	}

	host, port, err := socks5.ReadRequest(lo.conn)
	if err != nil {
		return
	}

	socks5.ReplySuccess(lo.conn)

	dest := net.JoinHostPort(host, port)
	lo.dest = host
	if net.ParseIP(host) == nil {
		lo.host = host
	}
	lo.dport = port

	if *verbose {
		logger.Printf("S %5d:  *            New %s %s -> %s", lo.total, lo.network, lo.conn.RemoteAddr(), dest)
	}

	lo.source = lo.conn.RemoteAddr().(*net.TCPAddr)
	lo.buf = bufio.NewReader(lo.conn)
	lo.mode = "S"
	lo.getFirstByte()
}
