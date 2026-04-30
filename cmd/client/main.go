// Command client is a one-shot CLI that queries the local Resolver gRPC
// service for a domain and prints each streamed DNSRecord on its own
// line. Output format: "<TYPE> <text>" per line, suitable for grep'ing
// in shell scripts. Used by LET_IT_RIP.sh.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/accretional/proto-domain/internal/grammar"
	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

func main() {
	addr := flag.String("addr", "localhost:50098", "Resolver gRPC server address")
	name := flag.String("name", "", "domain name to resolve (e.g. accretional.com)")
	timeout := flag.Duration("timeout", 5*time.Second, "RPC timeout")
	flag.Parse()

	if *name == "" {
		fmt.Fprintln(os.Stderr, "usage: client -name <domain> [-addr host:port]")
		os.Exit(2)
	}

	dom, err := grammar.ParseDomain(*name)
	if err != nil {
		log.Fatalf("parse %q: %v", *name, err)
	}

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial %s: %v", *addr, err)
	}
	defer conn.Close()

	cli := domainpb.NewResolverClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	stream, err := cli.GetDNSRecords(ctx, dom)
	if err != nil {
		log.Fatalf("GetDNSRecords: %v", err)
	}

	count := 0
	for {
		rec, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("stream recv: %v", err)
		}
		fmt.Printf("%s %s\n", rec.GetType(), rec.GetText())
		count++
	}
	fmt.Fprintf(os.Stderr, "(%d records for %s)\n", count, *name)
}
