// Package config provides structures and methods to parse /etc/hosts-like configuration files.
package config

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the DNS server configuration.
type Config struct {
	Sections []Section
}

// String returns the string representation of the configuration.
func (c Config) String() string {
	result := &strings.Builder{}
	_, _ = result.WriteString("{")
	for idx, s := range c.Sections {
		_, _ = fmt.Fprintf(result, "%s|%d: %d",
			s.SectionConfig.From,
			len(s.SectionConfig.TSTag),
			len(s.Aliases),
		)
		if idx < len(c.Sections)-1 {
			_, _ = result.WriteString(", ")
		}
	}
	_, _ = result.WriteString("}")
	return result.String()
}

// Section represents a section of the configuration.
type Section struct {
	Aliases []Alias
	SectionConfig
}

// Alias represents an alias for an IP address.
type Alias struct {
	IP        net.IP
	Hostnames []string
}

// SectionConfig represents the configuration of a section.
type SectionConfig struct {
	From  *net.IPNet
	TSTag map[string]struct{}
}

// UnmarshalYAML unmarshals a YAML node into a SectionConfig.
func (s *SectionConfig) UnmarshalYAML(v *yaml.Node) error {
	var raw struct {
		From  string   `yaml:"from"`
		TSTag []string `yaml:"tstag"`
	}

	if err := v.Decode(&raw); err != nil {
		return fmt.Errorf("decode raw: %w", err)
	}

	if raw.From != "" {
		_, ipNet, err := net.ParseCIDR(raw.From)
		if err != nil {
			return fmt.Errorf("parse CIDR: %w", err)
		}

		ipNet.IP = ipNet.IP.To4()
		s.From = ipNet
	}

	if len(raw.TSTag) > 0 {
		s.TSTag = make(map[string]struct{}, len(raw.TSTag))
		for _, tag := range raw.TSTag {
			s.TSTag[tag] = struct{}{}
		}
	}

	return nil
}

// Parse parses a configuration file.
func Parse(file io.Reader) (result Config, err error) {
	scanner := bufio.NewScanner(file)
	yamlSectionBuf := &strings.Builder{}
	var current Section
	idx := 0

	for scanner.Scan() {
		idx++
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "#!!"): // section config
			if len(current.Aliases) > 0 {
				result.Sections = append(result.Sections, current)
				current = Section{}
			}

			line = strings.TrimPrefix(line, "#!!")
			yamlSectionBuf.WriteString(line)
			yamlSectionBuf.WriteRune('\n')
		case strings.HasPrefix(line, "#"): // comment
			continue
		case strings.TrimSpace(line) == "": // empty line
			continue
		default:
			if yamlSectionBuf.Len() > 0 {
				s := yamlSectionBuf.String()
				if err = yaml.Unmarshal([]byte(s), &current.SectionConfig); err != nil {
					return Config{}, fmt.Errorf("unmarshal section config at line %d: %w", idx, err)
				}
				yamlSectionBuf.Reset()
			}

			fields := strings.Fields(line)
			if len(fields) < 2 {
				return Config{}, fmt.Errorf("invalid line %d: %s", idx, line)
			}

			ip := net.ParseIP(fields[0])
			if ip == nil {
				return Config{}, fmt.Errorf("invalid IP address at line %d: %s", idx, fields[0])
			}

			alias := Alias{IP: ip.To4(), Hostnames: filterOutComment(fields[1:])}

			for hostIdx, hostname := range alias.Hostnames {
				if !strings.HasSuffix(hostname, ".") {
					alias.Hostnames[hostIdx] = hostname + "." // ensure FQDN
				}
			}

			current.Aliases = append(current.Aliases, alias)
		}
	}

	if err = scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("scan: %w", err)
	}

	if len(current.Aliases) > 0 {
		result.Sections = append(result.Sections, current)
	}

	return result, nil
}

func filterOutComment(ls []string) []string {
	var result []string
	for _, l := range ls {
		if strings.HasPrefix(l, "#") {
			break
		}
		result = append(result, l)
	}
	return result
}

// Decoder is a configuration decoder.
type Decoder interface {
	Decode(io.Reader) (Config, error)
}

// DecoderFunc is an adapter to use an ordinary function as a Decoder.
type DecoderFunc func(io.Reader) (Config, error)

// Decode calls f(r).
func (f DecoderFunc) Decode(r io.Reader) (Config, error) { return f(r) }
