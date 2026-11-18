package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var sc serverConfig

func init() {
	sc.flags(flag.CommandLine)
}

func main() {
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s := sc.newServer(ctx)
	if err := s.serve(); err != nil {
		log.Printf("Server error:\n%v", err)
	}
}
