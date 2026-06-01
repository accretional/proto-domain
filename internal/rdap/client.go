package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
	ippb "github.com/accretional/proto-ip/proto/ippb"
)

// Client performs domain RDAP lookups, routing each request through the
// IANA bootstrap registry to the correct registry operator.
type Client struct {
	http *http.Client
	boot *Bootstrap
}

// NewClient returns a Client using boot for RDAP server resolution.
func NewClient(boot *Bootstrap) *Client {
	return &Client{
		http: &http.Client{},
		boot: boot,
	}
}

// LookupDomain queries the RDAP registry for domain. The domain hostname
// field is used; if it is empty the labels+tld are joined to reconstruct it.
func (c *Client) LookupDomain(ctx context.Context, d *domainpb.Domain) (*domainpb.RDAPDomainResponse, error) {
	name := d.GetHostname()
	if name == "" {
		return nil, fmt.Errorf("domain hostname is empty")
	}
	baseURL, err := c.boot.Resolve(name)
	if err != nil {
		return nil, err
	}
	queryURL := baseURL + "domain/" + strings.ToLower(strings.TrimSuffix(name, "."))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RDAP GET %s: %w", queryURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading RDAP response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP server returned HTTP %d for %s: %s",
			resp.StatusCode, queryURL, truncate(string(body), 200))
	}

	domain, err := parseDomain(body, baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing RDAP response: %w", err)
	}

	// Follow the registrar RDAP link (rel=related) if present to collect
	// registrant/admin/tech entities and additional status values that
	// the registry-level response omits.
	if registrarURL := findRelatedRDAPLink(body); registrarURL != "" {
		if r, err := c.fetchRaw(ctx, registrarURL); err == nil {
			mergeRegistrarData(domain, r)
		}
	}

	return &domainpb.RDAPDomainResponse{Domain: domain, RawJson: string(body)}, nil
}

// --- enum conversion maps (JSON string → proto enum) ---

var roleMap = map[string]ippb.RDAPRole{
	"registrant":             ippb.RDAPRole_RDAP_ROLE_REGISTRANT,
	"technical":              ippb.RDAPRole_RDAP_ROLE_TECHNICAL,
	"administrative":         ippb.RDAPRole_RDAP_ROLE_ADMINISTRATIVE,
	"abuse":                  ippb.RDAPRole_RDAP_ROLE_ABUSE,
	"noc":                    ippb.RDAPRole_RDAP_ROLE_NOC,
	"billing":                ippb.RDAPRole_RDAP_ROLE_BILLING,
	"registrar":              ippb.RDAPRole_RDAP_ROLE_REGISTRAR,
	"reseller":               ippb.RDAPRole_RDAP_ROLE_RESELLER,
	"sponsor":                ippb.RDAPRole_RDAP_ROLE_SPONSOR,
	"proxy":                  ippb.RDAPRole_RDAP_ROLE_PROXY,
	"notifications":          ippb.RDAPRole_RDAP_ROLE_NOTIFICATIONS,
	"nocDefaultAbuseContact": ippb.RDAPRole_RDAP_ROLE_NOC_DEFAULT_ABUSE_CONTACT,
	"routing":                ippb.RDAPRole_RDAP_ROLE_ROUTING,
}

var eventActionMap = map[string]ippb.RDAPEventAction{
	"registration":                 ippb.RDAPEventAction_RDAP_EVENT_ACTION_REGISTRATION,
	"reregistration":               ippb.RDAPEventAction_RDAP_EVENT_ACTION_REREGISTRATION,
	"last changed":                 ippb.RDAPEventAction_RDAP_EVENT_ACTION_LAST_CHANGED,
	"expiration":                   ippb.RDAPEventAction_RDAP_EVENT_ACTION_EXPIRATION,
	"deletion":                     ippb.RDAPEventAction_RDAP_EVENT_ACTION_DELETION,
	"reinstantiation":              ippb.RDAPEventAction_RDAP_EVENT_ACTION_REINSTANTIATION,
	"transfer":                     ippb.RDAPEventAction_RDAP_EVENT_ACTION_TRANSFER,
	"locked":                       ippb.RDAPEventAction_RDAP_EVENT_ACTION_LOCKED,
	"unlocked":                     ippb.RDAPEventAction_RDAP_EVENT_ACTION_UNLOCKED,
	"last update of RDAP database": ippb.RDAPEventAction_RDAP_EVENT_ACTION_LAST_UPDATE_OF_RDAP_DATABASE,
	"registrar expiration":         ippb.RDAPEventAction_RDAP_EVENT_ACTION_REGISTRAR_EXPIRATION,
	"enum validation expiration":   ippb.RDAPEventAction_RDAP_EVENT_ACTION_ENUM_VALIDATION_EXPIRATION,
}

var statusMap = map[string]ippb.RDAPStatus{
	// RFC 7483 §10.2.1 space-separated forms
	"active":              ippb.RDAPStatus_RDAP_STATUS_ACTIVE,
	"inactive":            ippb.RDAPStatus_RDAP_STATUS_INACTIVE,
	"validated":           ippb.RDAPStatus_RDAP_STATUS_VALIDATED,
	"renew prohibited":    ippb.RDAPStatus_RDAP_STATUS_RENEW_PROHIBITED,
	"update prohibited":   ippb.RDAPStatus_RDAP_STATUS_UPDATE_PROHIBITED,
	"transfer prohibited": ippb.RDAPStatus_RDAP_STATUS_TRANSFER_PROHIBITED,
	"delete prohibited":   ippb.RDAPStatus_RDAP_STATUS_DELETE_PROHIBITED,
	"proxy":               ippb.RDAPStatus_RDAP_STATUS_PROXY,
	"private":             ippb.RDAPStatus_RDAP_STATUS_PRIVATE,
	"removed":             ippb.RDAPStatus_RDAP_STATUS_REMOVED,
	"obscured":            ippb.RDAPStatus_RDAP_STATUS_OBSCURED,
	"associated":          ippb.RDAPStatus_RDAP_STATUS_ASSOCIATED,
	"locked":              ippb.RDAPStatus_RDAP_STATUS_LOCKED,
	"pending create":      ippb.RDAPStatus_RDAP_STATUS_PENDING_CREATE,
	"pending renew":       ippb.RDAPStatus_RDAP_STATUS_PENDING_RENEW,
	"pending transfer":    ippb.RDAPStatus_RDAP_STATUS_PENDING_TRANSFER,
	"pending update":      ippb.RDAPStatus_RDAP_STATUS_PENDING_UPDATE,
	"pending delete":      ippb.RDAPStatus_RDAP_STATUS_PENDING_DELETE,
	// ICANN RDAP profile qualified forms (client/server + action + "prohibited")
	"client delete prohibited":   ippb.RDAPStatus_RDAP_STATUS_DELETE_PROHIBITED,
	"client transfer prohibited": ippb.RDAPStatus_RDAP_STATUS_TRANSFER_PROHIBITED,
	"client update prohibited":   ippb.RDAPStatus_RDAP_STATUS_UPDATE_PROHIBITED,
	"client renew prohibited":    ippb.RDAPStatus_RDAP_STATUS_RENEW_PROHIBITED,
	"server delete prohibited":   ippb.RDAPStatus_RDAP_STATUS_DELETE_PROHIBITED,
	"server transfer prohibited": ippb.RDAPStatus_RDAP_STATUS_TRANSFER_PROHIBITED,
	"server update prohibited":   ippb.RDAPStatus_RDAP_STATUS_UPDATE_PROHIBITED,
	"server renew prohibited":    ippb.RDAPStatus_RDAP_STATUS_RENEW_PROHIBITED,
	// EPP camelCase forms used by some registries
	"ok":                      ippb.RDAPStatus_RDAP_STATUS_ACTIVE,
	"clientDeleteProhibited":   ippb.RDAPStatus_RDAP_STATUS_DELETE_PROHIBITED,
	"clientTransferProhibited": ippb.RDAPStatus_RDAP_STATUS_TRANSFER_PROHIBITED,
	"clientUpdateProhibited":   ippb.RDAPStatus_RDAP_STATUS_UPDATE_PROHIBITED,
	"clientRenewProhibited":    ippb.RDAPStatus_RDAP_STATUS_RENEW_PROHIBITED,
	"serverDeleteProhibited":   ippb.RDAPStatus_RDAP_STATUS_DELETE_PROHIBITED,
	"serverTransferProhibited": ippb.RDAPStatus_RDAP_STATUS_TRANSFER_PROHIBITED,
	"serverUpdateProhibited":   ippb.RDAPStatus_RDAP_STATUS_UPDATE_PROHIBITED,
	"serverRenewProhibited":    ippb.RDAPStatus_RDAP_STATUS_RENEW_PROHIBITED,
	"pendingCreate":            ippb.RDAPStatus_RDAP_STATUS_PENDING_CREATE,
	"pendingRenew":             ippb.RDAPStatus_RDAP_STATUS_PENDING_RENEW,
	"pendingTransfer":          ippb.RDAPStatus_RDAP_STATUS_PENDING_TRANSFER,
	"pendingUpdate":            ippb.RDAPStatus_RDAP_STATUS_PENDING_UPDATE,
	"pendingDelete":            ippb.RDAPStatus_RDAP_STATUS_PENDING_DELETE,
	"server recover prohibited": ippb.RDAPStatus_RDAP_STATUS_RECOVER_PROHIBITED,
	"client recover prohibited": ippb.RDAPStatus_RDAP_STATUS_RECOVER_PROHIBITED,
}

var entityKindMap = map[string]ippb.RDAPEntityKind{
	"individual":  ippb.RDAPEntityKind_RDAP_ENTITY_KIND_INDIVIDUAL,
	"group":       ippb.RDAPEntityKind_RDAP_ENTITY_KIND_GROUP,
	"org":         ippb.RDAPEntityKind_RDAP_ENTITY_KIND_ORG,
	"location":    ippb.RDAPEntityKind_RDAP_ENTITY_KIND_LOCATION,
	"application": ippb.RDAPEntityKind_RDAP_ENTITY_KIND_APPLICATION,
}

// --- JSON parsing ---

type rdapDomainJSON struct {
	Handle          string           `json:"handle"`
	LdhName         string           `json:"ldhName"`
	UnicodeName     string           `json:"unicodeName"`
	Nameservers     []nameserverJSON  `json:"nameservers"`
	SecureDNS       *secureDNSJSON   `json:"secureDNS"`
	Status          []string         `json:"status"`
	Entities        []entityJSON     `json:"entities"`
	Events          []eventJSON      `json:"events"`
	Links           []linkJSON       `json:"links"`
	RDAPConformance []string         `json:"rdapConformance"`
	Port43          string           `json:"port43"`
}

type nameserverJSON struct {
	Handle      string          `json:"handle"`
	LdhName     string          `json:"ldhName"`
	UnicodeName string          `json:"unicodeName"`
	Status      []string        `json:"status"`
	Links       []linkJSON      `json:"links"`
	IPAddresses *ipAddressesJSON `json:"ipAddresses"`
}

type ipAddressesJSON struct {
	V4 []string `json:"v4"`
	V6 []string `json:"v6"`
}

type secureDNSJSON struct {
	DelegationSigned       bool         `json:"delegationSigned"`
	ZoneSigned             bool         `json:"zoneSigned"`
	CheckSignatureValidity bool         `json:"checkSignatureValidity"`
	MaxSigLife             uint32       `json:"maxSigLife"`
	DSData                 []dsDataJSON `json:"dsData"`
	KeyData                []keyDataJSON `json:"keyData"`
}

type dsDataJSON struct {
	KeyTag     uint32 `json:"keyTag"`
	Algorithm  uint32 `json:"algorithm"`
	DigestType uint32 `json:"digestType"`
	Digest     string `json:"digest"`
}

type keyDataJSON struct {
	Flags     uint32 `json:"flags"`
	Protocol  uint32 `json:"protocol"`
	Algorithm uint32 `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

type entityJSON struct {
	Handle     string          `json:"handle"`
	VcardArray json.RawMessage `json:"vcardArray"`
	Roles      []string        `json:"roles"`
}

type eventJSON struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type linkJSON struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
	Type string `json:"type"`
}

// findRelatedRDAPLink scans the top-level links array of a raw RDAP JSON body
// for an entry with rel=related and type=application/rdap+json, which is the
// registrar's RDAP URL for this domain. Returns "" if not found.
func findRelatedRDAPLink(body []byte) string {
	var top struct {
		Links []linkJSON `json:"links"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return ""
	}
	for _, l := range top.Links {
		if l.Rel == "related" && l.Type == "application/rdap+json" && l.Href != "" {
			return l.Href
		}
	}
	return ""
}

// fetchRaw fetches a URL and decodes it as an rdapDomainJSON. Errors are
// returned so the caller can soft-fail and use registry data alone.
func (c *Client) fetchRaw(ctx context.Context, url string) (*rdapDomainJSON, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	var r rdapDomainJSON
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// mergeRegistrarData folds registrant/admin/tech entities and any additional
// status values from the registrar RDAP response into domain. Roles already
// present in domain are not duplicated; the registrar entity itself is skipped
// since the registry already provided it.
func mergeRegistrarData(domain *domainpb.RDAPDomain, r *rdapDomainJSON) {
	existingRoles := map[ippb.RDAPRole]bool{}
	for _, e := range domain.Entities {
		for _, role := range e.Roles {
			existingRoles[role] = true
		}
	}

	for _, e := range r.Entities {
		vc := parseVCard(e.VcardArray)
		roles := make([]ippb.RDAPRole, 0, len(e.Roles))
		for _, rs := range e.Roles {
			roles = append(roles, roleMap[rs])
		}
		hasNew := false
		for _, role := range roles {
			if role != ippb.RDAPRole_RDAP_ROLE_UNKNOWN && !existingRoles[role] {
				hasNew = true
				break
			}
		}
		if !hasNew {
			continue
		}
		domain.Entities = append(domain.Entities, &ippb.RDAPEntity{
			Handle:  e.Handle,
			Fn:      vc.FN,
			Roles:   roles,
			Emails:  vc.Emails,
			Kind:    entityKindMap[vc.Kind],
			Org:     vc.Org,
			Address: vc.Address,
			Phone:   vc.Phone,
		})
		for _, role := range roles {
			existingRoles[role] = true
		}
	}

	existingStatuses := map[ippb.RDAPStatus]bool{}
	for _, s := range domain.Status {
		existingStatuses[s] = true
	}
	for _, s := range r.Status {
		mapped := statusMap[s]
		if mapped != ippb.RDAPStatus_RDAP_STATUS_UNKNOWN && !existingStatuses[mapped] {
			domain.Status = append(domain.Status, mapped)
			existingStatuses[mapped] = true
		}
	}
}

func parseDomain(body []byte, rdapServer string) (*domainpb.RDAPDomain, error) {
	var r rdapDomainJSON
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}

	nameservers := make([]*domainpb.RDAPNameserver, 0, len(r.Nameservers))
	for _, ns := range r.Nameservers {
		nsStatuses := make([]ippb.RDAPStatus, 0, len(ns.Status))
		for _, s := range ns.Status {
			nsStatuses = append(nsStatuses, statusMap[s])
		}
		nsLinks := make([]string, 0, len(ns.Links))
		for _, l := range ns.Links {
			if l.Href != "" {
				nsLinks = append(nsLinks, l.Href)
			}
		}
		nsEntry := &domainpb.RDAPNameserver{
			Handle:      ns.Handle,
			LdhName:     ns.LdhName,
			UnicodeName: ns.UnicodeName,
			Status:      nsStatuses,
			Links:       nsLinks,
		}
		if ns.IPAddresses != nil {
			nsEntry.Ipv4Addresses = ns.IPAddresses.V4
			nsEntry.Ipv6Addresses = ns.IPAddresses.V6
		}
		nameservers = append(nameservers, nsEntry)
	}

	var secureDNS *domainpb.RDAPSecureDNS
	if r.SecureDNS != nil {
		sd := r.SecureDNS
		dsData := make([]*domainpb.RDAPDSData, 0, len(sd.DSData))
		for _, d := range sd.DSData {
			dsData = append(dsData, &domainpb.RDAPDSData{
				KeyTag:     d.KeyTag,
				Algorithm:  d.Algorithm,
				DigestType: d.DigestType,
				Digest:     d.Digest,
			})
		}
		keyData := make([]*domainpb.RDAPKeyData, 0, len(sd.KeyData))
		for _, k := range sd.KeyData {
			keyData = append(keyData, &domainpb.RDAPKeyData{
				Flags:     k.Flags,
				Protocol:  k.Protocol,
				Algorithm: k.Algorithm,
				PublicKey: k.PublicKey,
			})
		}
		secureDNS = &domainpb.RDAPSecureDNS{
			DelegationSigned:       sd.DelegationSigned,
			ZoneSigned:             sd.ZoneSigned,
			CheckSignatureValidity: sd.CheckSignatureValidity,
			MaxSigLife:             sd.MaxSigLife,
			DsData:                 dsData,
			KeyData:                keyData,
		}
	}

	seenStatus := map[ippb.RDAPStatus]bool{}
	statuses := make([]ippb.RDAPStatus, 0, len(r.Status))
	for _, s := range r.Status {
		mapped := statusMap[s]
		if !seenStatus[mapped] {
			statuses = append(statuses, mapped)
			seenStatus[mapped] = true
		}
	}

	entities := make([]*ippb.RDAPEntity, 0, len(r.Entities))
	for _, e := range r.Entities {
		vc := parseVCard(e.VcardArray)
		roles := make([]ippb.RDAPRole, 0, len(e.Roles))
		for _, rs := range e.Roles {
			roles = append(roles, roleMap[rs])
		}
		entities = append(entities, &ippb.RDAPEntity{
			Handle:  e.Handle,
			Fn:      vc.FN,
			Roles:   roles,
			Emails:  vc.Emails,
			Kind:    entityKindMap[vc.Kind],
			Org:     vc.Org,
			Address: vc.Address,
			Phone:   vc.Phone,
		})
	}

	events := make([]*ippb.RDAPEvent, 0, len(r.Events))
	for _, ev := range r.Events {
		events = append(events, &ippb.RDAPEvent{
			Action: eventActionMap[ev.EventAction],
			Date:   ev.EventDate,
		})
	}

	links := make([]string, 0, len(r.Links))
	for _, l := range r.Links {
		if l.Href != "" {
			links = append(links, l.Href)
		}
	}

	return &domainpb.RDAPDomain{
		Handle:          r.Handle,
		LdhName:         r.LdhName,
		UnicodeName:     r.UnicodeName,
		Nameservers:     nameservers,
		SecureDns:       secureDNS,
		Status:          statuses,
		Entities:        entities,
		Events:          events,
		Links:           links,
		RdapServer:      rdapServer,
		RdapConformance: r.RDAPConformance,
		Port43:          r.Port43,
	}, nil
}

// vcardResult holds the fields extracted from a vCard.
type vcardResult struct {
	FN      string
	Kind    string
	Org     string
	Address string
	Phone   string
	Emails  []string
}

// parseVCard extracts structured fields from an RDAP vCard.
// Format per RFC 6350 / RFC 7483: ["vcard", [[prop, params, type, value], ...]]
func parseVCard(raw json.RawMessage) vcardResult {
	var res vcardResult
	if len(raw) == 0 {
		return res
	}
	var top []json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || len(top) < 2 {
		return res
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(top[1], &entries); err != nil {
		return res
	}
	for _, entry := range entries {
		var fields []json.RawMessage
		if err := json.Unmarshal(entry, &fields); err != nil || len(fields) < 4 {
			continue
		}
		var prop string
		if err := json.Unmarshal(fields[0], &prop); err != nil {
			continue
		}
		switch prop {
		case "fn":
			json.Unmarshal(fields[3], &res.FN) //nolint:errcheck
		case "kind":
			json.Unmarshal(fields[3], &res.Kind) //nolint:errcheck
		case "org":
			json.Unmarshal(fields[3], &res.Org) //nolint:errcheck
		case "email":
			var email string
			if err := json.Unmarshal(fields[3], &email); err == nil && email != "" {
				res.Emails = append(res.Emails, email)
			}
		case "tel":
			if res.Phone == "" {
				json.Unmarshal(fields[3], &res.Phone) //nolint:errcheck
			}
		case "adr":
			var params struct {
				Label string `json:"label"`
			}
			if err := json.Unmarshal(fields[1], &params); err == nil && params.Label != "" {
				res.Address = params.Label
			}
		}
	}
	return res
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
