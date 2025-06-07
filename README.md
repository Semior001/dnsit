# project status
This project is unmaintained and archived.

# dnsit
simple as that dns server, accepts /etc/hosts like config for resolving A records

## installation
```bash
go install github.com/Semior001/dnsit@latest
```

```bash
docker run --rm -it -p 53:53/udp -v ./my-config-file.conf:/srv/config ghcr.io/semior001/dnsit:latest
```

## usage
```
Usage:
  dsnit [OPTIONS]

Application Options:
      --addr=                  Address to listen on (default: :53) [$ADDR]
      --upstream=              Upstream DNS server address [$UPSTREAM]
      --ttl=                   TTL for DNS records (default: 5m) [$TTL]

config:
      --config.path=           Path to the configuration file [$CONFIG_PATH]
      --config.delay=          Delay before applying changes (default: 10s) [$CONFIG_DELAY]
      --config.check-interval= Interval to check for config changes (default: 3s) [$CONFIG_CHECK_INTERVAL]

tailscale:
      --tailscale.tailnet=     Tailscale tailnet [$TAILSCALE_TAILNET]
      --tailscale.token=       Tailscale API token [$TAILSCALE_TOKEN]

log:
      --log.path=              Log file path, empty for stdout [$LOG_PATH]
      --log.debug              Enable debug mode [$LOG_DEBUG]

Help Options:
  -h, --help                   Show this help message

```

### configuration
Config is just like a `/etc/hosts` file, but with some additional options in comments. 

In comment, you can provide a `#!!from: cidr` directive, which will make the next set of records (until the next `!!from` 
directive) record only available for the specified CIDR.

Example:
```
#!!from: 192.168.174.0/24
192.168.174.2   example.com   deeper.example.com
192.168.174.3   foo.bar.com

#!!from: 100.10.10.1/32
100.10.10.2     example.com
100.10.10.5     blah.abacaba.com

#!!tstag:
#!!  - 'tag:foo'
#!!  - 'tag:bar'
127.0.0.1      example.com
```

This will make `example.com` and `deeper.example.com` resolve to `192.168.174.2` only for clients from `192.168.174.0/24` subnet,
and `example.com` and `blah.abacaba.com` resolve to `100.10.10.2` and `100.10.10.5` respectively only for clients from `100.10.10.1/32` subnet.

The third section with `#!!tstag` directive will make `example.com` resolve to the localhost IP address only for clients with `foo` or `bar` tag, tags are received from the Tailscale API.

You can invoke a special query `nslookup semior001.dnsit.refresh-tailscale` to force the server to refresh the tags from the Tailscale API.
