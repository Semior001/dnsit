// Package main is an application entrypoint.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/Semior001/dnsit/app/config"
	"github.com/Semior001/dnsit/app/ns"
	"github.com/hashicorp/logutils"
	"github.com/jessevdk/go-flags"
)

var opts struct {
	Addr     string        `long:"addr"     env:"ADDR"     description:"Address to listen on"           default:":53"`
	Upstream string        `long:"upstream" env:"UPSTREAM" description:"Upstream DNS server address"`
	TTL      time.Duration `long:"ttl"      env:"TTL"      description:"TTL for DNS records"            default:"5m"`
	Config   string        `long:"config"   env:"CONFIG"   description:"Path to the configuration file" required:"true"`
	Debug    bool          `long:"debug"    env:"DEBUG"    description:"Enable debug mode"`
}

var version = "unknown"

func getVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && version == "unknown" {
		return bi.Main.Version
	}
	return version
}

func main() {
	_, _ = fmt.Fprintf(os.Stderr, "dnsit %s\n", getVersion())

	ctx, cancel := context.WithCancelCause(context.Background())
	go func() { // catch signal and invoke graceful termination
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		sig := <-stop
		log.Printf("[INFO] caught signal: %s", sig)
		cancel(fmt.Errorf("received shutdown signal: %s", sig))
	}()

	if _, err := flags.Parse(&opts); err != nil {
		fe := &flags.Error{}
		if errors.As(err, &fe) && errors.Is(fe.Type, flags.ErrHelp) {
			os.Exit(0)
		}
		log.Fatalf("failed to parse flags: %v", err)
	}

	setupLog(opts.Debug)

	if err := run(ctx); err != nil {
		log.Fatalf("failed to run: %v", err)
	}
}

func run(ctx context.Context) error {
	f, err := os.Open(opts.Config)
	if err != nil {
		return fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()

	cfg, err := config.Parse(f)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	log.Printf("[INFO] parsed config with %d sections", len(cfg.Sections))

	srv := &ns.Server{
		Addr:     opts.Addr,
		Upstream: opts.Upstream,
		TTL:      opts.TTL,
		Config:   cfg,
	}

	if err = srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("run server: %w", err)
	}

	return nil
}

func setupLog(debug bool) {
	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN", "ERROR"},
		MinLevel: "INFO",
		Writer:   os.Stderr,
	}

	logFlags := log.Ldate | log.Ltime

	if debug {
		logFlags = log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile
		filter.MinLevel = "DEBUG"
	}

	log.SetFlags(logFlags)
	log.SetOutput(filter)

	log.Printf("[DEBUG] debug mode enabled")
}
