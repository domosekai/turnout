// Released under MIT License
// Copyright (c) 2024 domosekai

// DNS reverse lookup tools

package main

import (
	"net"
	"time"
)

const (
	shdnsTimeout = 1
)

func getHostnameFromIP(ip net.IP) string {
	if shdns != nil {
		return getHostnameFromShdns(ip, shdns)
	}
	return ""
}

func getHostnameFromShdns(ip net.IP, server *net.UDPAddr) string {
	conn, err := net.DialUDP("udp", nil, server)
	if err != nil {
		return ""
	}
	defer conn.Close()
	op := []byte{1}
	_, err = conn.Write(append(op, ip...))
	if err != nil {
		return ""
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(shdnsTimeout) * time.Second))
	if err != nil {
		return ""
	}
	var answer [1500]byte
	len, _, err := conn.ReadFrom(answer[:])
	if err != nil {
		return ""
	}
	if len <= 1 || answer[0] != 2 {
		return ""
	}
	return string(answer[1:len])
}
