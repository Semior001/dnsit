package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
)

// Checker is a configuration checker.
type Checker struct {
	FileName      string
	CheckInterval time.Duration
	Delay         time.Duration
	UpdateFn      func(Config)
}

// Run runs the configuration checker.
// Blocks until the context is canceled.
func (d *Checker) Run(ctx context.Context) error {
	ticker := time.NewTicker(d.CheckInterval)
	defer ticker.Stop()

	modif, ok := d.getModifTime()
	if !ok {
		return fmt.Errorf("first get of modification time of %q", d.FileName)
	}

	cfg, err := d.parse()
	if err != nil {
		return fmt.Errorf("parse file for the first time: %w", err)
	}

	const logTimeFmt = "2006-01-02 15:04:05.000"
	log.Printf("[INFO] parsed config file for the first time, modif: %s, file: %q",
		modif.Format(logTimeFmt), d.FileName)

	d.UpdateFn(cfg)
	lastModif := modif

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if modif, ok = d.getModifTime(); !ok {
				continue
			}

			// don't react on modification right away
			if modif == lastModif || modif.Sub(lastModif) < d.Delay {
				continue
			}

			log.Printf("[DEBUG] file changed: %s -> %s",
				lastModif.Format(logTimeFmt), modif.Format(logTimeFmt))
			lastModif = modif

			if cfg, err = d.parse(); err != nil {
				log.Printf("[ERROR] failed to parse file %q: %v", d.FileName, err)
				continue
			}

			d.UpdateFn(cfg)
		}
	}
}

func (d *Checker) parse() (Config, error) {
	f, err := os.Open(d.FileName)
	if err != nil {
		return Config{}, fmt.Errorf("open file: %w", err)
	}
	defer func() {
		if cErr := f.Close(); cErr != nil {
			log.Printf("[WARN] failed to close file %q: %v", d.FileName, cErr)
		}
	}()

	cfg, err := Parse(f)
	if err != nil {
		return Config{}, fmt.Errorf("decode file: %w", err)
	}

	return cfg, nil
}

func (d *Checker) getModifTime() (modif time.Time, ok bool) {
	fi, err := os.Stat(d.FileName)
	if err != nil {
		log.Printf("[WARN] failed to read file %q: %v", d.FileName, err)
		return time.Time{}, false
	}

	if fi.IsDir() {
		log.Printf("[WARN] expected file, but found a directory: %q", d.FileName)
		return time.Time{}, false
	}

	return fi.ModTime(), true
}
