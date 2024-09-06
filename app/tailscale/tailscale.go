package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Interface is an interface that provides the information about the IP address
// from the TSTag service.
type Interface interface {
	// Run starts the client and refreshes the data from the TSTag service.
	Run(ctx context.Context, refreshInterval time.Duration)
	// Refresh refreshes the data from the tailscale.
	Refresh(ctx context.Context) error
	// GetTags returns the tags for the given device that is identified by the IP address.
	GetTags(ip net.IP) (tags []string, err error)
}

// Device represents a device in the TSTag network.
type Device struct {
	Addresses []net.IP
	Tags      []string
}

// Client is a client that interacts with the TSTag service.
type Client struct {
	Client  *http.Client
	Tailnet string
	Token   string

	devices  []Device
	deviceMu sync.RWMutex

	lastRefresh time.Time
	refreshMu   sync.RWMutex
}

// Run starts the client and refreshes the data from the TSTag service.
func (c *Client) Run(ctx context.Context, refreshInterval time.Duration) {
	log.Printf("[INFO][tailscale] starting refresher, interval: %s", refreshInterval)

	if err := c.Refresh(ctx); err != nil {
		log.Printf("[WARN][tailscale] failed to refresh devices for the first time: %v", err)
	}

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Refresh(ctx); err != nil {
				log.Printf("[ERROR][tailscale] failed to refresh devices: %v", err)
			}
		}
	}
}

// GetTags returns the tags for the given device that is identified by the IP address.
func (c *Client) GetTags(ip net.IP) (tags []string, err error) {
	c.deviceMu.RLock()
	defer c.deviceMu.RUnlock()

	for _, d := range c.devices {
		for _, a := range d.Addresses {
			if a.Equal(ip) {
				return d.Tags, nil
			}
		}
	}

	return nil, errors.New("device not found")
}

// Refresh refreshes the data from the tailscale.
func (c *Client) Refresh(ctx context.Context) error {
	c.refreshMu.RLock()
	if time.Since(c.lastRefresh) < 5*time.Second {
		// do not refresh too often
		c.refreshMu.RUnlock()
		return nil
	}
	c.refreshMu.RUnlock()
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.lastRefresh = time.Now()

	log.Printf("[DEBUG][tailscale] refreshing devices")

	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/devices", c.Tailnet)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("get devices: %w", err)
	}

	defer resp.Body.Close()

	var body struct {
		Devices []struct {
			Addresses []string `json:"addresses"`
			Tags      []string `json:"tags"`
		} `json:"devices"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	devices := make([]Device, 0, len(body.Devices))
	for _, d := range body.Devices {
		addresses := make([]net.IP, 0, len(d.Addresses))
		for _, a := range d.Addresses {
			ip := net.ParseIP(a)
			if ip == nil {
				log.Printf("[WARN][tailscale] failed to parse IP address: %s", a)
				continue
			}
			addresses = append(addresses, ip)
		}
		devices = append(devices, Device{
			Addresses: addresses,
			Tags:      d.Tags,
		})
	}

	c.deviceMu.RLock()
	if !equal(c.devices, devices) {
		log.Printf("[DEBUG][tailscale] updating devices, old: %d, new: %d", len(c.devices), len(devices))
		c.deviceMu.RUnlock()
		c.deviceMu.Lock()
		c.devices = devices
		c.deviceMu.Unlock()
		return nil
	}
	c.deviceMu.RUnlock()
	return nil
}

func equal(a, b []Device) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if !equalDevice(a[i], b[i]) {
			return false
		}
	}

	return true
}

func equalDevice(a, b Device) bool {
	if len(a.Addresses) != len(b.Addresses) {
		return false
	}

	for i := range a.Addresses {
		if !a.Addresses[i].Equal(b.Addresses[i]) {
			return false
		}
	}

	if len(a.Tags) != len(b.Tags) {
		return false
	}

	for i := range a.Tags {
		if a.Tags[i] != b.Tags[i] {
			return false
		}
	}

	return true
}
