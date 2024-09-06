package config

import (
	"bytes"
	_ "embed"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/simple.cfg
var simpleCfg []byte

func TestParse(t *testing.T) {
	cfg, err := Parse(bytes.NewReader(simpleCfg))
	require.NoError(t, err)

	expected := Config{Sections: []Section{
		{
			Aliases: []Alias{
				{IP: net.IPv4(192, 168, 174, 1).To4(), Hostnames: []string{"some.domain.com.", "some.domain."}},
				{IP: net.IPv4(192, 168, 174, 2).To4(), Hostnames: []string{"some.other.domain.com.", "some.other.domain.", "some.other."}},
			},
			SectionConfig: SectionConfig{From: cidr(t, "192.168.174.0/24")},
		},
		{
			Aliases: []Alias{
				{IP: net.IPv4(100, 10, 10, 3).To4(), Hostnames: []string{"foo.bar."}},
				{IP: net.IPv4(100, 8, 1, 1).To4(), Hostnames: []string{"bar.foo."}},
			},
			SectionConfig: SectionConfig{
				From:  cidr(t, "100.10.10.1/32"),
				TSTag: map[string]struct{}{"foo": {}, "bar": {}},
			},
		},
	}}

	assert.Equal(t, expected, cfg)
}

func cidr(t *testing.T, s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	require.NoError(t, err)
	ipNet.IP = ipNet.IP.To4()
	return ipNet
}
