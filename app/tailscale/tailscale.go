// Package tailscale provides the interface and client
// to interact with the tailscale API.
package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
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
	Name      string
	Addresses []net.IP
	Tags      []string
}

// Client is a client that interacts with the TSTag service.
type Client struct {
	Client  *http.Client
	Tailnet string
	Token   string

	ts  time.Time
	val State
	mu  sync.RWMutex
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
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, d := range c.val.Devices {
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
	if last := c.lastModified(); time.Since(last) < 5*time.Second {
		// do not refresh too often 
		log.Printf("[DEBUG] suppressed refresh, when the last one was less than 5 sec ago: %s", last)
		return nil
	}

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
			Name      string   `json:"name"`
			Addresses []string `json:"addresses"`
			Tags      []string `json:"tags"`
		} `json:"devices"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	st := State{Devices: make([]Device, 0, len(body.Devices))}
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
		st.Devices = append(st.Devices, Device{
			Name:      d.Name,
			Addresses: addresses,
			Tags:      d.Tags,
		})
	}

	if !c.state().Equal(st) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.val = st
	}

	return nil
}

func (c *Client) lastModified() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ts
}

func (c *Client) state() State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.val
}

// State specifies the current state of the tailnet.
type State struct {
	Devices []Device
}

// Equal returns true if two states are equal.
func (s State) Equal(other State) bool {
	sort.Slice(s.Devices, func(i, j int) bool {
		return s.Devices[i].Name > s.Devices[j].Name
	})
	sort.Slice(other.Devices, func(i, j int) bool {
		return other.Devices[i].Name > other.Devices[j].Name
	})

	if len(other.Devices) != len(s.Devices) {
		return false
	}

	for i := range s.Devices {
		if !s.Devices[i].Equal(other.Devices[i]) {
			return false
		}
	}

	return true
}

// Equal returns true if two devices are identical.
func (d Device) Equal(other Device) bool {
	if d.Name != other.Name {
		return false
	}

	sort.Strings(d.Tags)
	sort.Strings(other.Tags)
	sort.Slice(d.Addresses, func(i, j int) bool {
		return d.Addresses[i].String() > d.Addresses[j].String()
	})
	sort.Slice(other.Addresses, func(i, j int) bool {
		return other.Addresses[i].String() > other.Addresses[j].String()
	})

	if len(d.Addresses) != len(other.Addresses) || len(d.Tags) != len(other.Tags) {
		return false
	}

	for i := range d.Addresses {
		if !d.Addresses[i].Equal(other.Addresses[i]) {
			return false
		}
	}

	for i := range d.Tags {
		if d.Tags[i] != other.Tags[i] {
			return false
		}
	}

	return true
}
