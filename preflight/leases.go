package main

// The DHCP reader's derivation: from the lease list, which never leaves this
// box, to the inventory that does. WO-0928-B item 7, under R20.
//
// ## What leaves, and what does not
//
// R20: a lease list is raw capture, and raw capture never leaves district
// equipment. So the leases are read into memory here, reduced, and dropped.
// What is sent is one item per hardware address carrying exactly:
//
//   - the hardware address, from which the portal derives the vendor;
//   - the hostname, as the DHCP server holds it (R19(2): a hostname is shown as
//     a hostname and never read as an owner);
//
// and the collection time the whole submission carries, which is when these
// were observed. **No IP address, no scope, no subnet, no expiry, no lease
// state.** Those are the lease list, and the lease list stays here.
//
// ## Why last seen is the collection time and not a lease date
//
// A lease records when it EXPIRES, not when the client was last on the
// network. The Windows sender works out "obtained" as the expiry less the
// scope's lease duration, which is a date computed from a duration and a
// start -- the thing 0.3 forbids. This reader does not do that. A lease that
// is present in the table when it is read was observed at that moment, and
// that moment is a reading rather than a calculation.
//
// ## The hardware address is parsed only in shapes the specification names
//
// MS-DHCPM 2.2.1.2.5 lets DHCP_CLIENT_UID carry either a client-identifier
// stored as-is, or a client unique ID: four bytes of subnet (little-endian),
// the byte 0x01, then the client-identifier. Getting this wrong writes a
// subnet prefix into every hardware address the portal keys a device on,
// which fails silently -- a key that matches nothing. So each accepted shape
// is checked against something else in the same record, and anything else is
// refused and counted rather than guessed at:
//
//   - 6 bytes: a bare hardware address. THIS ONE IS AN ASSUMPTION, not a
//     documented representation: MS-DHCPM stores the client-identifier as-is
//     and RFC 2132 section 9.14 describes one as a hardware type followed by
//     an address, so nothing read documents a six-byte form. It is kept
//     because a hardware address with no type byte is what such a value would
//     be, and it stays until a server is seen sending one or not. Read on
//     30 September 2026; WO-0930-F item 5.
//   - 7 bytes starting 0x01: an RFC 2132 client-identifier of hardware type 1.
//   - 11 bytes whose first four equal the client's own address ANDed with its
//     own mask, then 0x01: the client unique ID, as the specification's worked
//     example lays it out.

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// leaseRecord is what the reader keeps of one lease while it is in memory.
// Nothing outside this file sees one.
type leaseRecord struct {
	IP       uint32
	Mask     uint32
	UID      []byte
	HostName string
}

// DerivedItem is what leaves the box. Two fields, and adding a third is a
// change to what R20 permits, not a detail.
type DerivedItem struct {
	MacAddress string `json:"macAddress"`
	HostName   string `json:"hostName,omitempty"`
}

// hardwareAddress reads the MAC out of a client UID, or reports that it could not.
func hardwareAddress(uid []byte, ip, mask uint32) (string, bool) {
	switch {
	case len(uid) == 6:
		return formatMAC(uid), true
	case len(uid) == 7 && uid[0] == 0x01:
		return formatMAC(uid[1:]), true
	case len(uid) == 11 && uid[4] == 0x01 && binary.LittleEndian.Uint32(uid[0:4]) == ip&mask:
		return formatMAC(uid[5:]), true
	}
	return "", false
}

// The ClientUID length histogram, which is the whole reason the lease probe
// exists. WO-1030-N137, 00-i item 6.
//
// ## It was promised and never computed
//
// When no lease came back, the probe said "the ClientUID length histogram is
// still unrecorded", which reads as *it would be recorded if one did*. Nothing
// recorded it. A device could have taken a lease on that scope at any point in
// the six weeks since and the run would have printed a lease count and no
// histogram — so the reading the backlog entry asks the next run to capture
// was not something any run could have produced. *Before trusting a figure,
// check something writes it.*
//
// ## Why the length alone is not the answer
//
// The question is not which lengths a server sends; it is whether what it
// sends parses to a hardware address. A length counted without that says the
// shape and not the outcome, and the outcome is what every device key rests
// on. So each length carries how many parsed and how many were refused: a
// length that arrives and never parses is the failure this probe is for, and
// it looks identical to a length that arrives and always parses if only the
// lengths are counted.
type uidTally struct {
	Keyed   int
	Refused int
}

// uidShape names what a ClientUID of this length is, in the specification's
// terms, so somebody reading the output does not have to hold MS-DHCPM's three
// documented shapes in their head. A length outside them says so rather than
// being given a name it has not earned.
func uidShape(length int) string {
	switch length {
	case 0:
		return "no ClientUID at all"
	case 6:
		return "a bare hardware address"
	case 7:
		return "a client-identifier of type 1"
	case 11:
		return "a client unique id with a subnet prefix"
	default:
		return "a length none of the three documented shapes covers"
	}
}

// tallyUID adds one observation, keyed or refused, to the histogram.
func tallyUID(tally map[int]uidTally, uid []byte, ip, mask uint32) {
	at := tally[len(uid)]
	if _, ok := hardwareAddress(uid, ip, mask); ok {
		at.Keyed++
	} else {
		at.Refused++
	}
	tally[len(uid)] = at
}

// uidHistogramLines renders the tally shortest length first, one line each,
// with the counts beside the shape. Empty where nothing was observed: the
// caller says so in its own words, because *a check that answered nothing and
// a check that could not run must not print the same thing*.
func uidHistogramLines(tally map[int]uidTally) []string {
	lengths := make([]int, 0, len(tally))
	for length := range tally {
		lengths = append(lengths, length)
	}
	sort.Ints(lengths)

	lines := make([]string, 0, len(lengths))
	for _, length := range lengths {
		at := tally[length]
		line := fmt.Sprintf("  %2d bytes: %d parsed", length, at.Keyed)
		if at.Refused > 0 {
			line += fmt.Sprintf(", %d REFUSED", at.Refused)
		}
		lines = append(lines, line+" — "+uidShape(length))
	}
	return lines
}

func formatMAC(b []byte) string {
	parts := make([]string, len(b))
	for i, octet := range b {
		parts[i] = fmt.Sprintf("%02x", octet)
	}
	return strings.Join(parts, ":")
}

// derive reduces a lease list to the inventory that may leave, and counts what
// it refused. One item per hardware address: a device leased on two scopes is
// one device, and which scope it was on is the lease list.
func derive(leases []leaseRecord) (items []DerivedItem, unkeyable int) {
	seen := map[string]int{}
	for _, lease := range leases {
		mac, ok := hardwareAddress(lease.UID, lease.IP, lease.Mask)
		if !ok {
			unkeyable++
			continue
		}
		host := strings.TrimSpace(lease.HostName)
		if at, dup := seen[mac]; dup {
			// Keep a hostname if either lease carried one. Which lease it came
			// from is not recorded, because that would be the scope.
			if items[at].HostName == "" {
				items[at].HostName = host
			}
			continue
		}
		seen[mac] = len(items)
		items = append(items, DerivedItem{MacAddress: mac, HostName: host})
	}
	return items, unkeyable
}
