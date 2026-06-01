// Command rdap-client is a CLI driver for the RDAPResolver gRPC service.
// Used by LET_IT_RIP.sh to verify the server returns RDAP domain data.
//
// Usage:
//
//	rdap-client [-addr HOST:PORT] <domain>   # e.g. example.com
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

func main() {
	addr := flag.String("addr", "localhost:50099", "RDAPResolver server address")
	timeout := flag.Duration("timeout", 15*time.Second, "request timeout")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: rdap-client [-addr HOST:PORT] <domain>")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial %s: %v", *addr, err)
	}
	defer conn.Close()
	client := domainpb.NewRDAPResolverClient(conn)

	resp, err := client.LookupDomain(ctx, &domainpb.Domain{Hostname: args[0]})
	if err != nil {
		log.Fatalf("LookupDomain(%s): %v", args[0], err)
	}
	printResponse(resp)
}

func printResponse(resp *domainpb.RDAPDomainResponse) {
	d := resp.GetDomain()
	fmt.Printf("handle:          %s\n", d.GetHandle())
	fmt.Printf("ldh_name:        %s\n", d.GetLdhName())
	if u := d.GetUnicodeName(); u != "" && u != d.GetLdhName() {
		fmt.Printf("unicode_name:    %s\n", u)
	}
	fmt.Printf("rdap_server:     %s\n", d.GetRdapServer())
	if p := d.GetPort43(); p != "" {
		fmt.Printf("port43:          %s\n", p)
	}

	statuses := make([]string, len(d.GetStatus()))
	for i, s := range d.GetStatus() {
		statuses[i] = shortEnum(s.String(), "RDAP_STATUS_")
	}
	fmt.Printf("status:          %s\n", strings.Join(statuses, ", "))
	fmt.Printf("conformance:     %s\n", strings.Join(d.GetRdapConformance(), ", "))

	for _, ns := range d.GetNameservers() {
		fmt.Printf("nameserver:      %s", ns.GetLdhName())
		if len(ns.GetIpv4Addresses()) > 0 {
			fmt.Printf(" v4=[%s]", strings.Join(ns.GetIpv4Addresses(), ","))
		}
		if len(ns.GetIpv6Addresses()) > 0 {
			fmt.Printf(" v6=[%s]", strings.Join(ns.GetIpv6Addresses(), ","))
		}
		fmt.Println()
	}

	if sd := d.GetSecureDns(); sd != nil && sd.GetDelegationSigned() {
		fmt.Printf("dnssec:          delegation_signed=true ds_records=%d\n", len(sd.GetDsData()))
		for _, ds := range sd.GetDsData() {
			fmt.Printf("  ds:            tag=%d alg=%d digest_type=%d digest=%s\n",
				ds.GetKeyTag(), ds.GetAlgorithm(), ds.GetDigestType(), ds.GetDigest())
		}
	}

	for _, e := range d.GetEntities() {
		// Skip entirely empty entities — some registrars send role stubs with no data.
		if e.GetHandle() == "" && e.GetFn() == "" && e.GetOrg() == "" &&
			len(e.GetEmails()) == 0 && e.GetPhone() == "" {
			continue
		}
		roles := make([]string, len(e.GetRoles()))
		for i, r := range e.GetRoles() {
			roles[i] = shortEnum(r.String(), "RDAP_ROLE_")
		}
		kind := shortEnum(e.GetKind().String(), "RDAP_ENTITY_KIND_")
		fmt.Printf("entity:          handle=%s kind=%s fn=%q org=%q roles=%s\n",
			e.GetHandle(), kind, e.GetFn(), e.GetOrg(), strings.Join(roles, ","))
		if addr := e.GetAddress(); addr != "" {
			fmt.Printf("  address:       %s\n", strings.ReplaceAll(addr, "\n", " | "))
		}
		if phone := e.GetPhone(); phone != "" {
			fmt.Printf("  phone:         %s\n", phone)
		}
		if emails := e.GetEmails(); len(emails) > 0 {
			fmt.Printf("  emails:        %s\n", strings.Join(emails, ", "))
		}
	}

	for _, ev := range d.GetEvents() {
		fmt.Printf("event:           %s @ %s\n",
			shortEnum(ev.GetAction().String(), "RDAP_EVENT_ACTION_"), ev.GetDate())
	}
}

func shortEnum(s, prefix string) string {
	return strings.ToLower(strings.TrimPrefix(s, prefix))
}
