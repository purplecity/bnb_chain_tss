package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	sign "github.com/purplecity/bnb_chain_tss/task2-sign"
)

func main() {
	configPath := flag.String("config", "gateway.json", "gateway configuration JSON")
	flag.Parse()
	var cfg sign.GatewayConfig
	if err := sign.LoadJSON(*configPath, &cfg); err != nil {
		fatal("load config: %v", err)
	}
	gateway, err := sign.NewGateway(cfg)
	if err != nil {
		fatal("create signing gateway: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := gateway.Connect(ctx); err != nil {
		fatal("connect signer nodes: %v", err)
	}
	if err := gateway.ServeHTTP(ctx); err != nil {
		fatal("gateway stopped: %v", err)
	}
}

func fatal(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
