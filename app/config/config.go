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
	From *net.IPNet
}

// UnmarshalYAML unmarshals a YAML node into a SectionConfig.
func (s *SectionConfig) UnmarshalYAML(v *yaml.Node) error {
	var raw struct {
		From string `yaml:"from"`
	}

	if err := v.Decode(&raw); err != nil {
		return fmt.Errorf("decode raw: %w", err)
	}

	_, ipNet, err := net.ParseCIDR(raw.From)
	if err != nil {
		return fmt.Errorf("parse CIDR: %w", err)
	}

	s.From = ipNet
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

			alias := Alias{IP: ip, Hostnames: filterOutComment(fields[1:])}

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
