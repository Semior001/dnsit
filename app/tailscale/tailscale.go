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

	devices []Device
	mu      sync.RWMutex
}

// Run starts the client and refreshes the data from the TSTag service.
func (c *Client) Run(ctx context.Context, refreshInterval time.Duration) {
	log.Printf("[INFO][tailscale] starting refresher, interval: %s", refreshInterval)

	c.refresh(ctx)

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refresh(ctx)
		}
	}
}

// GetTags returns the tags for the given device that is identified by the IP address.
func (c *Client) GetTags(ip net.IP) (tags []string, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, d := range c.devices {
		for _, a := range d.Addresses {
			if a.Equal(ip) {
				return d.Tags, nil
			}
		}
	}

	return nil, errors.New("device not found")
}

func (c *Client) refresh(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	log.Printf("[DEBUG][tailscale] refreshing devices")

	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/devices", c.Tailnet)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		log.Printf("[WARN][tailscale] failed to create request: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.Client.Do(req)
	if err != nil {
		log.Printf("[WARN][tailscale] failed to get devices: %v", err)
		return
	}

	defer resp.Body.Close()

	var body struct {
		Devices []struct {
			Addresses []string `json:"addresses"`
			Tags      []string `json:"tags"`
		} `json:"devices"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.Printf("[WARN][tailscale] failed to decode response: %v", err)
		return
	}

	devices := make([]Device, 0, len(body.Devices))
	for _, d := range body.Devices {
		addresses := make([]net.IP, 0, len(d.Addresses))
		for _, a := range d.Addresses {
			ip := net.ParseIP(a)
			if ip == nil {
				log.Printf("[WARN][tailscale] failed to parse IP address: %s", a[0])
				continue
			}
			addresses = append(addresses, ip)
		}
		devices = append(devices, Device{
			Addresses: addresses,
			Tags:      d.Tags,
		})
	}

	c.mu.RLock()
	if !equal(c.devices, devices) {
		log.Printf("[DEBUG][tailscale] updating devices, old: %d, new: %d", len(c.devices), len(devices))
		c.mu.RUnlock()
		c.mu.Lock()
		c.devices = devices
		c.mu.Unlock()
		return
	}
	c.mu.RUnlock()
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
