// Package service is the importable entrypoint for composing proto-domain's
// Resolver and RDAPResolver services onto a shared *grpc.Server (the proto-go
// "Register" convention).
package service

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
	"github.com/accretional/proto-domain/internal/rdap"
	"github.com/accretional/proto-domain/internal/resolver"
)

// Register registers the Resolver (DNS records w/ TTLs) and, best-effort, the
// RDAPResolver (domain registration lookups) on s.
//
// RDAPResolver needs the IANA RDAP bootstrap registry, which is fetched over the
// network; if that fails (offline, timeout) the RDAPResolver is simply not
// registered and a warning is logged — the DNS Resolver is always registered.
func Register(s *grpc.Server) {
	domainpb.RegisterResolverServer(s, resolver.New())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	boot, err := rdap.NewBootstrap(ctx)
	cancel()
	if err != nil {
		log.Printf("proto-domain: RDAP bootstrap failed (%v); RDAPResolver not registered", err)
		return
	}
	domainpb.RegisterRDAPResolverServer(s, rdap.NewServer(rdap.NewClient(boot)))
}
