package main

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
)

// The two DHCP authorization findings, built from the directory's list of
// authorized DHCP servers. Queue item 8 in the portal repository's
// APPLIANCE-BINARY-QUEUE.md, WO-1021-N113 item 1.
//
// The shell reads the list as step 4 of preflight.sh, under
// CN=NetServices,CN=Services,CN=Configuration, and only where Active Directory
// is granted. It writes that read to a directory in the shape -collect-ad
// already takes (<name>.ldif, <name>.status, <name>.said) and hands it over as
// -authorized-dir. This file turns it into the two findings the Windows sender
// already sends, in its vocabulary, with only the item fields the portal's
// DHCP_FINDING_ITEM_FIELDS names. The portal keeps them only where Active
// Directory and DHCP consent were both in force at the reading.
//
// Three outcomes, never two: found; answered and found nothing, not-found with
// examined; and could not look, could-not-answer with Cairn's own reason. A
// reason never quotes a resolver or ldapsearch, whose words name hosts and
// addresses this box should not send.

// hostResolver is the two lookups the findings need, so tests answer them.
type hostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// registration is one authorized server, as the directory records it.
type registration struct {
	Address string
	Name    string
}

// parseRegistration reads one dhcpServers value, i<address>$rcn=<name>$, and
// reports false for anything not in that shape.
func parseRegistration(value string) (registration, bool) {
	if !strings.HasPrefix(value, "i") {
		return registration{}, false
	}
	parts := strings.Split(value[1:], "$")
	address := parts[0]
	if net.ParseIP(address) == nil {
		return registration{}, false
	}
	for _, part := range parts[1:] {
		if name, ok := strings.CutPrefix(part, "rcn="); ok && name != "" {
			return registration{Address: address, Name: name}, true
		}
	}
	return registration{}, false
}

// registrations reads every entry's dhcpServers values. CN=DhcpRoot carries
// none and is not a server, so it contributes nothing.
func registrations(entries []ldifEntry) (found []registration, unreadable int) {
	for _, entry := range entries {
		for _, value := range entry.all("dhcpServers") {
			if r, ok := parseRegistration(value); ok {
				found = append(found, r)
			} else {
				unreadable++
			}
		}
	}
	return found, unreadable
}

// The resolution of one name, in the Windows sender's words.
const (
	resolves          = "resolves"
	resolvesElsewhere = "resolves-elsewhere"
	nxdomain          = "nxdomain"
	lookupFailed      = "lookup-failed"
)

// lookedUp is one registration with what the box's resolver said about it.
type lookedUp struct {
	registration
	Resolution  string
	ReverseName string
	IsThisHost  bool
}

func forward(ctx context.Context, resolver hostResolver, r registration) string {
	addresses, err := resolver.LookupHost(ctx, r.Name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nxdomain
		}
		return lookupFailed
	}
	for _, address := range addresses {
		if address == r.Address {
			return resolves
		}
	}
	return resolvesElsewhere
}

func reverse(ctx context.Context, resolver hostResolver, address string) string {
	names, err := resolver.LookupAddr(ctx, address)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func lookUp(ctx context.Context, resolver hostResolver, found []registration, own map[string]bool) []lookedUp {
	out := make([]lookedUp, 0, len(found))
	for _, r := range found {
		out = append(out, lookedUp{
			registration: r,
			Resolution:   forward(ctx, resolver, r),
			ReverseName:  reverse(ctx, resolver, r.Address),
			IsThisHost:   own[r.Address],
		})
	}
	return out
}

const (
	unresolvableID  = "dhcp-authorizations-unresolvable"
	sharedAddressID = "dhcp-authorizations-shared-address"
)

func unresolvableItem(row lookedUp) map[string]any {
	item := map[string]any{
		"dnsName":    row.Name,
		"ipAddress":  row.Address,
		"resolution": row.Resolution,
		"isThisHost": row.IsThisHost,
	}
	if row.ReverseName != "" {
		item["reverseName"] = row.ReverseName
	}
	if row.Resolution == lookupFailed {
		item["reason"] = "the box's resolver returned an error for this name"
	}
	return item
}

func unresolvableCheck(rows []lookedUp) adCheck {
	items := []map[string]any{}
	failed := 0
	for _, row := range rows {
		switch row.Resolution {
		case resolves:
			continue
		case lookupFailed:
			failed++
		}
		items = append(items, unresolvableItem(row))
	}
	real := len(items) - failed
	examined := intp(len(rows))
	switch {
	case real > 0:
		return adCheck{ID: unresolvableID, State: "found", Count: real, Items: items, Examined: examined,
			Note: "Registrations whose name does not resolve to the address it is registered at, read through the appliance's own resolver. A registration that could not be looked up at all is listed as lookup-failed rather than as unresolvable."}
	case failed > 0:
		return adCheck{ID: unresolvableID, State: "could-not-answer", Items: items,
			Reason: "Every registration that could be looked up resolved to its registered address, and some could not be looked up at all, so this run cannot say the list is clean."}
	}
	return adCheck{ID: unresolvableID, State: "not-found", Items: []map[string]any{}, Examined: examined,
		Note: "Every authorized registration resolves to the address it is registered at."}
}

func sharedAddressCheck(rows []lookedUp) adCheck {
	byAddress := map[string][]lookedUp{}
	for _, row := range rows {
		byAddress[row.Address] = append(byAddress[row.Address], row)
	}
	addresses := make([]string, 0, len(byAddress))
	for address := range byAddress {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	items := []map[string]any{}
	for _, address := range addresses {
		group := byAddress[address]
		if len(group) <= 1 {
			continue
		}
		names := make([]string, 0, len(group))
		thisHost, resolvesHere := false, false
		for _, row := range group {
			names = append(names, row.Name)
			thisHost = thisHost || row.IsThisHost
			resolvesHere = resolvesHere || row.Resolution == resolves
		}
		item := map[string]any{"ipAddress": address, "names": names, "isThisHost": thisHost, "anyNameResolvesHere": resolvesHere}
		if group[0].ReverseName != "" {
			item["reverseName"] = group[0].ReverseName
		}
		items = append(items, item)
	}
	state := "not-found"
	if len(items) > 0 {
		state = "found"
	}
	return adCheck{ID: sharedAddressID, State: state, Count: len(items), Items: items, Examined: intp(len(addresses)),
		Note: "Addresses carrying more than one registered name. Whether such a server is live is not established here: nothing probes, so each item says only whether the address is this appliance's own and whether any of its names resolves to it."}
}

// authorizationChecks builds the two findings from what the shell handed over.
// handed is false where the shell handed nothing, because the step was not
// asked: then neither finding is sent, which is a step not taken rather than a
// read that failed.
func authorizationChecks(ctx context.Context, read adRead, handed bool, resolver hostResolver, own map[string]bool) []adCheck {
	if !handed {
		return nil
	}
	if read.Status != 0 {
		reason := "The directory list of authorized DHCP servers could not be read, so neither finding was looked at."
		return []adCheck{couldNotAnswer(unresolvableID, reason), couldNotAnswer(sharedAddressID, reason)}
	}
	entries, err := parseLDIF(read.Text)
	if err != nil {
		reason := "The directory list of authorized DHCP servers was read and could not be parsed, so neither finding was looked at."
		return []adCheck{couldNotAnswer(unresolvableID, reason), couldNotAnswer(sharedAddressID, reason)}
	}
	found, unreadable := registrations(entries)
	if unreadable > 0 {
		reason := "Some registrations in the directory list of authorized DHCP servers were not in the shape this appliance reads, so the list could not be judged whole."
		return []adCheck{couldNotAnswer(unresolvableID, reason), couldNotAnswer(sharedAddressID, reason)}
	}
	rows := lookUp(ctx, resolver, found, own)
	return []adCheck{unresolvableCheck(rows), sharedAddressCheck(rows)}
}

// ownAddresses is this appliance's own addresses, for isThisHost.
func ownAddresses() map[string]bool {
	own := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return own
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			own[ipnet.IP.String()] = true
		}
	}
	return own
}
