// Command client is a one-shot CLI that queries the local Resolver gRPC
// service for a domain and prints each streamed DNSRecord on its own
// line. Output format: "<TYPE> <ttl> <rendered body>" per line,
// suitable for grep'ing in shell scripts. Used by LET_IT_RIP.sh.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
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
		fmt.Printf("%-5s ttl=%-6d %s\n", rec.GetType(), rec.GetTtlSeconds(), renderBody(rec))
		count++
	}
	fmt.Fprintf(os.Stderr, "(%d records for %s)\n", count, *name)
}

// renderBody returns a one-line human-readable view of the record's
// typed body. Display only — not a stable wire format.
func renderBody(r *domainpb.DNSRecord) string {
	switch b := r.GetBody().(type) {
	case *domainpb.DNSRecord_A:
		return net.IP(b.A.GetIpv4()).String()
	case *domainpb.DNSRecord_Aaaa:
		return net.IP(b.Aaaa.GetIpv6()).String()
	case *domainpb.DNSRecord_Cname:
		return b.Cname.GetTarget()
	case *domainpb.DNSRecord_Dname:
		return b.Dname.GetTarget()
	case *domainpb.DNSRecord_Ns:
		return b.Ns.GetHost()
	case *domainpb.DNSRecord_Mx:
		return fmt.Sprintf("%d %s", b.Mx.GetPref(), b.Mx.GetHost())
	case *domainpb.DNSRecord_Txt:
		return strings.Join(b.Txt.GetStrings(), "")
	case *domainpb.DNSRecord_Soa:
		s := b.Soa
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			s.GetNs(), s.GetMbox(), s.GetSerial(), s.GetRefresh(),
			s.GetRetry(), s.GetExpire(), s.GetMinTtl())
	case *domainpb.DNSRecord_Loc:
		return renderLOC(b.Loc)
	case *domainpb.DNSRecord_Hinfo:
		return fmt.Sprintf("%q %q", b.Hinfo.GetCpu(), b.Hinfo.GetOs())
	case *domainpb.DNSRecord_Rp:
		return fmt.Sprintf("%s %s", b.Rp.GetMbox(), b.Rp.GetTxt())
	case *domainpb.DNSRecord_Afsdb:
		return fmt.Sprintf("%d %s", b.Afsdb.GetSubtype(), b.Afsdb.GetHostname())
	case *domainpb.DNSRecord_Naptr:
		n := b.Naptr
		return fmt.Sprintf("%d %d %q %q %q %s",
			n.GetOrder(), n.GetPreference(), n.GetFlags(), n.GetService(),
			n.GetRegexp(), n.GetReplacement())
	case *domainpb.DNSRecord_Kx:
		return fmt.Sprintf("%d %s", b.Kx.GetPreference(), b.Kx.GetExchanger())
	case *domainpb.DNSRecord_Sshfp:
		s := b.Sshfp
		return fmt.Sprintf("%d %d %s", s.GetAlgorithm(), s.GetFpType(), hex.EncodeToString(s.GetFingerprint()))
	case *domainpb.DNSRecord_Svcb:
		return renderSVCB(b.Svcb.GetPriority(), b.Svcb.GetTargetName(), b.Svcb.GetParams())
	case *domainpb.DNSRecord_Https:
		return renderSVCB(b.Https.GetPriority(), b.Https.GetTargetName(), b.Https.GetParams())
	case *domainpb.DNSRecord_Caa:
		return fmt.Sprintf("%d %s %q", b.Caa.GetFlags(), b.Caa.GetTag(), b.Caa.GetValue())
	case *domainpb.DNSRecord_Uri:
		return fmt.Sprintf("%d %d %q", b.Uri.GetPriority(), b.Uri.GetWeight(), b.Uri.GetTarget())
	default:
		return "(no body)"
	}
}

func renderLOC(l *domainpb.LOCRecord) string {
	const latLonBias = 1 << 31
	const altBiasCm = 10_000_000
	latDeg := float64(int64(l.GetLatitude())-latLonBias) / 3_600_000.0
	lonDeg := float64(int64(l.GetLongitude())-latLonBias) / 3_600_000.0
	altM := float64(int64(l.GetAltitude())-altBiasCm) / 100.0
	prec := func(b uint32) string {
		mant := float64(b >> 4)
		exp := int(b & 0x0F)
		cm := mant
		for i := 0; i < exp; i++ {
			cm *= 10
		}
		return fmt.Sprintf("%.2fm", cm/100.0)
	}
	return fmt.Sprintf("%.6f %.6f %.2fm size=%s hp=%s vp=%s",
		latDeg, lonDeg, altM,
		prec(l.GetSize()), prec(l.GetHorizPre()), prec(l.GetVertPre()))
}

func renderSVCB(priority uint32, target string, params []*domainpb.SvcbParam) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d %s", priority, target)
	for _, p := range params {
		fmt.Fprintf(&b, " %d=%s", p.GetKey(), hex.EncodeToString(p.GetValue()))
	}
	return b.String()
}
