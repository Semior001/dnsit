# dnsit
simple as that dns server, accepts /etc/hosts like config for resolving A records

## installation
```bash
go install github.com/Semior001/dnsit@latest
```

## usage
```
Usage:
  dnsit [OPTIONS]

Application Options:
      --addr=     Address to listen on (default: :53) [$ADDR]
      --upstream= Upstream DNS server address [$UPSTREAM]
      --ttl=      TTL for DNS records (default: 5m) [$TTL]
      --config=   Path to the configuration file [$CONFIG]
      --debug     Enable debug mode [$DEBUG]

Help Options:
  -h, --help      Show this help message
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
```

This will make `example.com` and `deeper.example.com` resolve to `192.168.174.2` only for clients from `192.168.174.0/24` subnet,
and `example.com` and `blah.abacaba.com` resolve to `100.10.10.2` and `100.10.10.5` respectively only for clients from `100.10.10.1/32` subnet.

## project status
This project is in a very early stage of development, so it may not work as expected. Until v1 is released, the API may change at any time.
