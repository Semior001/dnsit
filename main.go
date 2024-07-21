// Package main is an application entrypoint.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/Semior001/dnsit/app/config"
	"github.com/Semior001/dnsit/app/ns"
	"github.com/hashicorp/logutils"
	"github.com/jessevdk/go-flags"
	"golang.org/x/sync/errgroup"
	"gopkg.in/natefinch/lumberjack.v2"
)

var opts struct {
	Addr     string        `long:"addr"           env:"ADDR"           description:"Address to listen on"                 default:":53"`
	Upstream string        `long:"upstream"       env:"UPSTREAM"       description:"Upstream DNS server address"`
	TTL      time.Duration `long:"ttl"            env:"TTL"            description:"TTL for DNS records"                  default:"5m"`
	Config   struct {
		Path          string        `long:"path"           env:"PATH"           description:"path to the configuration file"       required:"true"`
		Delay         time.Duration `long:"delay"          env:"DELAY"          description:"Delay before applying changes"        default:"10s"`
		CheckInterval time.Duration `long:"check-interval" env:"CHECK_INTERVAL" description:"Interval to check for config changes" default:"3s"`
	} `group:"config" namespace:"config" env-namespace:"CONFIG"`

	Log struct {
		File  string `long:"log-file"       env:"LOG_FILE"       description:"Log file path, empty for stdout"`
		Debug bool   `long:"debug"          env:"DEBUG"          description:"Enable debug mode"`
	} `group:"log" namespace:"log" env-namespace:"LOG"`
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

	setupLog()

	if err := run(ctx); err != nil {
		log.Fatalf("failed to run: %v", err)
	}
}

func run(ctx context.Context) error {
	srv := ns.NewServer(opts.Addr, opts.TTL, opts.Upstream)

	checker := &config.Checker{
		FileName:      opts.Config.Path,
		CheckInterval: opts.Config.CheckInterval,
		Delay:         opts.Config.Delay,
		Decoder:       config.DecoderFunc(config.Parse),
		UpdateFn:      srv.SetConfig,
	}

	ewg, ctx := errgroup.WithContext(ctx)
	ewg.Go(func() error {
		if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("run server: %w", err)
		}
		return nil
	})
	ewg.Go(func() error {
		if err := checker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("run checker: %w", err)
		}
		return nil
	})
	return ewg.Wait()
}

func setupLog() {
	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN", "ERROR"},
		MinLevel: "INFO",
		Writer:   os.Stderr,
	}

	logFlags := log.Ldate | log.Ltime

	if opts.Log.Debug {
		logFlags = log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile
		filter.MinLevel = "DEBUG"
	}

	if opts.Log.File != "" {
		lj := &lumberjack.Logger{
			Filename:   filepath.Clean(opts.Log.File),
			MaxSize:    100, // 100 MB
			MaxAge:     28,  // 28 days
			MaxBackups: 3,
			LocalTime:  true,
		}
		filter.Writer = io.MultiWriter(os.Stderr, lj)
	}

	log.SetFlags(logFlags)
	log.SetOutput(filter)

	log.Printf("[DEBUG] debug mode enabled")
}
