// Command rdap-server runs the proto-domain RDAPResolver gRPC service.
// It fetches the IANA DNS bootstrap registry on startup and routes domain
// RDAP queries to the correct registry operator.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/accretional/proto-domain/internal/rdap"
	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

func main() {
	port := flag.Int("port", 50099, "listen port")
	addr := flag.String("addr", "", "listen address (host:port); overrides -port if set")
	bootstrapTimeout := flag.Duration("bootstrap-timeout", 30*time.Second, "timeout for fetching IANA bootstrap")
	flag.Parse()

	bind := *addr
	if bind == "" {
		bind = ":" + itoa(*port)
	}

	log.Print("Fetching IANA RDAP DNS bootstrap registry…")
	bsCtx, bsCancel := context.WithTimeout(context.Background(), *bootstrapTimeout)
	boot, err := rdap.NewBootstrap(bsCtx)
	bsCancel()
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
	log.Print("Bootstrap loaded.")

	client := rdap.NewClient(boot)
	server := rdap.NewServer(client)

	lis, err := net.Listen("tcp", bind)
	if err != nil {
		log.Fatalf("listen %s: %v", bind, err)
	}

	srv := grpc.NewServer()
	domainpb.RegisterRDAPResolverServer(srv, server)
	log.Printf("RDAPResolver listening on %s", lis.Addr())

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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 8)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
