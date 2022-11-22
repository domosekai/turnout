// Released under MIT License
// Copyright (c) 2022 domosekai

// Reacts on system signals

//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func listenSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGUSR2)
	for sig := range sigs {
		switch sig {
		case syscall.SIGHUP:
			logger.Println("Received signal to reload files and clear cache")
			if *ipFile != "" {
				readIPRules(&ipRules, *ipFile)
			}
			if *hostFile != "" {
				readHostRules(&hostRules, *hostFile)
			}
			slowIPSet.clear()
			slowHostSet.clear()
			blockedIPSet.clear()
			blockedHostSet.clear()
			logger.Println("Slow and blocked lists flushed")
		case syscall.SIGUSR2:
			if *logFile == "" {
				break
			}
			logger.Println("Received signal to reopen log file")
			logger.Open(*logFile, *logAppend)
		}
	}
}
