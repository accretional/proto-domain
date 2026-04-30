// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE_GO file.
//
// Adapted from $GOROOT/src/net/hosts.go (see ./README.md). Material
// changes vs upstream are listed in dns/README.md and marked inline
// with "// fork:" comments.

package dns

import (
	"bufio"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const cacheMaxAge = 5 * time.Second

// fork: upstream defines hostsFilePath in a build-tagged file
// (hook.go for unix, hook_windows.go for Windows). We only support
// unix-like systems here, so we hardcode the path.
var hostsFilePath = "/etc/hosts"

func parseLiteralIP(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	return ip.String()
}

type byName struct {
	addrs         []string
	canonicalName string
}

// hosts contains known host entries.
var hosts struct {
	sync.Mutex

	// Key for the list of literal IP addresses must be a host
	// name. It would be part of DNS labels, a FQDN or an absolute
	// FQDN.
	// For now the key is converted to lower case for convenience.
	byName map[string]byName

	// Key for the list of host names must be a literal IP address
	// including IPv6 address with zone identifier.
	// We don't support old-classful IP address notation.
	byAddr map[string][]string

	expire time.Time
	path   string
	mtime  time.Time
	size   int64
}

// fork: upstream's stat() helper lives in parse.go; os.Stat returns
// the same fields we need.
func statFile(p string) (time.Time, int64, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return time.Time{}, 0, err
	}
	return fi.ModTime(), fi.Size(), nil
}

func readHosts() {
	now := time.Now()
	hp := hostsFilePath

	if now.Before(hosts.expire) && hosts.path == hp && len(hosts.byName) > 0 {
		return
	}
	mtime, size, err := statFile(hp)
	if err == nil && hosts.path == hp && hosts.mtime.Equal(mtime) && hosts.size == size {
		hosts.expire = now.Add(cacheMaxAge)
		return
	}

	hs := make(map[string]byName)
	is := make(map[string][]string)

	// fork: upstream uses parse.go's open() helper; bufio.Scanner is
	// 1-to-1 for our line-iteration use.
	file, err := os.Open(hp)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
			return
		}
	}

	if file != nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			// fork: bytealg.IndexByteString → strings.IndexByte.
			if i := strings.IndexByte(line, '#'); i >= 0 {
				// Discard comments.
				line = line[0:i]
			}
			// fork: getFields → strings.Fields.
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			addr := parseLiteralIP(f[0])
			if addr == "" {
				continue
			}

			var canonical string
			for i := 1; i < len(f); i++ {
				name := absDomainName(f[i])
				// fork: lowerASCIIBytes (in-place) → strings.ToLower.
				key := absDomainName(strings.ToLower(f[i]))

				if i == 1 {
					canonical = key
				}

				is[addr] = append(is[addr], name)

				if v, ok := hs[key]; ok {
					hs[key] = byName{
						addrs:         append(v.addrs, addr),
						canonicalName: v.canonicalName,
					}
					continue
				}

				hs[key] = byName{
					addrs:         []string{addr},
					canonicalName: canonical,
				}
			}
		}
	}
	// Update the data cache.
	hosts.expire = now.Add(cacheMaxAge)
	hosts.path = hp
	hosts.byName = hs
	hosts.byAddr = is
	hosts.mtime = mtime
	hosts.size = size
}

// lookupStaticHost looks up the addresses and the canonical name for the given host from /etc/hosts.
func lookupStaticHost(host string) ([]string, string) {
	hosts.Lock()
	defer hosts.Unlock()
	readHosts()
	if len(hosts.byName) != 0 {
		// fork: hasUpperCase + in-place lowerASCIIBytes → strings.ToLower.
		host = strings.ToLower(host)
		if byName, ok := hosts.byName[absDomainName(host)]; ok {
			ipsCp := make([]string, len(byName.addrs))
			copy(ipsCp, byName.addrs)
			return ipsCp, byName.canonicalName
		}
	}
	return nil, ""
}

// lookupStaticAddr looks up the hosts for the given address from /etc/hosts.
func lookupStaticAddr(addr string) []string {
	hosts.Lock()
	defer hosts.Unlock()
	readHosts()
	addr = parseLiteralIP(addr)
	if addr == "" {
		return nil
	}
	if len(hosts.byAddr) != 0 {
		if hosts, ok := hosts.byAddr[addr]; ok {
			hostsCp := make([]string, len(hosts))
			copy(hostsCp, hosts)
			return hostsCp
		}
	}
	return nil
}
