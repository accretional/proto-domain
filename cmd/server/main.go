// Command server runs the proto-domain Resolver gRPC service backed by
// the host's DNS resolver.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/accretional/proto-domain/internal/resolver"
	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

func main() {
	addr := flag.String("addr", "", "listen address (host:port). overrides -port if set")
	port := flag.Int("port", 50098, "listen port (used when -addr is empty)")
	upstream := flag.String("upstream", "", "comma-separated upstream resolver addrs (host:port). Empty = use /etc/resolv.conf. Multiple addrs round-robin per RPC.")
	statsInterval := flag.Duration("upstream-stats-interval", 60*time.Second, "interval for per-upstream RPC stats log line; 0 disables")
	flag.Parse()

	// Container-platform conventions (Cloud Run et al): PORT overrides the
	// default port, UPSTREAM supplies -upstream, when the flags are unset.
	bind := *addr
	if bind == "" {
		if p := os.Getenv("PORT"); p != "" {
			bind = ":" + p
		} else {
			bind = ":" + itoa(*port)
		}
	}
	if *upstream == "" {
		*upstream = os.Getenv("UPSTREAM")
	}

	lis, err := net.Listen("tcp", bind)
	if err != nil {
		log.Fatalf("listen %s: %v", bind, err)
	}

	srv := grpc.NewServer()
	var svc *resolver.Service
	var upstreams []string
	if *upstream != "" {
		for _, a := range strings.Split(*upstream, ",") {
			if a = strings.TrimSpace(a); a != "" {
				upstreams = append(upstreams, a)
			}
		}
		svc = resolver.NewWithUpstreams(upstreams)
	} else {
		svc = resolver.New()
	}
	domainpb.RegisterResolverServer(srv, svc)
	// Server reflection: lets grpcurl and other descriptor-less clients
	// discover the service instead of needing the .proto files on hand.
	reflection.Register(srv)

	var stopStats func()
	if *statsInterval > 0 {
		stopStats = svc.LogUpstreamStats(*statsInterval)
	}

	log.Printf("resolver listening on %s (upstreams=%v)", lis.Addr(), upstreams)

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		log.Print("shutting down")
		if stopStats != nil {
			stopStats()
		}
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// itoa is a tiny strconv.Itoa shim to avoid pulling in strconv just for
// one printf-style integer concatenation.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 8)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
