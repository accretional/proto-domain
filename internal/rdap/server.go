package rdap

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

// Server implements the RDAPResolver gRPC service.
type Server struct {
	domainpb.UnimplementedRDAPResolverServer
	client *Client
}

// NewServer returns a Server backed by client.
func NewServer(client *Client) *Server {
	return &Server{client: client}
}

func (s *Server) LookupDomain(ctx context.Context, d *domainpb.Domain) (*domainpb.RDAPDomainResponse, error) {
	if d.GetHostname() == "" {
		return nil, status.Error(codes.InvalidArgument, "Domain.hostname must be set")
	}
	resp, err := s.client.LookupDomain(ctx, d)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "RDAP domain lookup: %v", err)
	}
	return resp, nil
}
