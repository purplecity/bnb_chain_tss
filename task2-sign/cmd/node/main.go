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
	configPath := flag.String("config", "node.json", "node configuration JSON")
	flag.Parse()
	var cfg sign.NodeConfig
	if err := sign.LoadJSON(*configPath, &cfg); err != nil {
		fatal("load config: %v", err)
	}
	node, err := sign.NewNode(cfg)
	if err != nil {
		fatal("create signer node: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := node.Serve(ctx); err != nil {
		fatal("signer node stopped: %v", err)
	}
}

func fatal(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
