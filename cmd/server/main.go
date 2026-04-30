// Command server runs the proto-domain Resolver gRPC service backed by
// the host's DNS resolver.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"github.com/accretional/proto-domain/internal/resolver"
	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

func main() {
	addr := flag.String("addr", "", "listen address (host:port). overrides -port if set")
	port := flag.Int("port", 50098, "listen port (used when -addr is empty)")
	flag.Parse()

	bind := *addr
	if bind == "" {
		bind = ":" + itoa(*port)
	}

	lis, err := net.Listen("tcp", bind)
	if err != nil {
		log.Fatalf("listen %s: %v", bind, err)
	}

	srv := grpc.NewServer()
	domainpb.RegisterResolverServer(srv, resolver.New())

	log.Printf("resolver listening on %s", lis.Addr())

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		log.Print("shutting down")
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
