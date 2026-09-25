package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	modeFlag := flag.String("mode", "", "Execution mode: 'server' or 'client'")
	configFlag := flag.String("config", "config.json", "Path to config file")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("Fatal: Elevated privileges (root) are required to control TUN devices.")
	}

	cfg, err := LoadConfig(*configFlag)
	if err != nil {
		log.Fatalf("Fatal configuration error: %v", err)
	}

	if *modeFlag != "" {
		cfg.Mode = *modeFlag
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	switch cfg.Mode {
	case "server":
		srv, err := NewServer(cfg)
		if err != nil {
			log.Fatalf("Server bootstrap failed: %v", err)
		}

		go func() {
			<-sigChan
			log.Println("\nReceived shutdown signal, terminating server...")
			srv.Shutdown()
			os.Exit(0)
		}()

		srv.Start()

	case "client":
		cli, err := NewClient(cfg)
		if err != nil {
			log.Fatalf("Client bootstrap failed: %v", err)
		}

		go func() {
			<-sigChan
			log.Println("\nReceived shutdown signal, terminating client...")
			cli.Shutdown()
			os.Exit(0)
		}()

		cli.Start()

	default:
		log.Fatalf("Unsupported execution mode: %s", cfg.Mode)
	}
}
