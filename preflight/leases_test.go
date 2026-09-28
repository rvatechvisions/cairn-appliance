package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// 192.168.1.10/24, the specification's worked example.
const (
	exampleIP   = 0xc0a8010a
	exampleMask = 0xffffff00
)

func TestHardwareAddressShapes(t *testing.T) {
	mac := []byte{0x00, 0x1c, 0x25, 0x80, 0xa0, 0x43}
	want := "00:1c:25:80:a0:43"

	unique := append([]byte{0x00, 0x01, 0xa8, 0xc0, 0x01}, mac...)
	cases := []struct {
		name string
		uid  []byte
		ok   bool
	}{
		{"bare hardware address", mac, true},
		{"client-identifier of type 1", append([]byte{0x01}, mac...), true},
		{"client unique ID, the specification's worked example", unique, true},
	}
	for _, c := range cases {
		got, ok := hardwareAddress(c.uid, exampleIP, exampleMask)
		if ok != c.ok || got != want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, ok, want)
		}
	}
}

func TestHardwareAddressRefusals(t *testing.T) {
	mac := []byte{0x00, 0x1c, 0x25, 0x80, 0xa0, 0x43}
	cases := map[string][]byte{
		// The subnet prefix disagrees with the client's own address and mask,
		// so this is not the shape it looks like -- refused, not trimmed.
		"a prefix naming another subnet":   append([]byte{0x00, 0x02, 0xa8, 0xc0, 0x01}, mac...),
		"a prefix with the wrong type":     append([]byte{0x00, 0x01, 0xa8, 0xc0, 0x06}, mac...),
		"a client-identifier that is text": []byte("host1.contoso.com"),
		"nothing":                          {},
	}
	for name, uid := range cases {
		if got, ok := hardwareAddress(uid, exampleIP, exampleMask); ok {
			t.Errorf("%s: accepted as %q", name, got)
		}
	}
}

func TestDeriveCarriesNothingOfTheLeaseList(t *testing.T) {
	leases := []leaseRecord{
		{IP: exampleIP, Mask: exampleMask, UID: []byte{0, 1, 2, 3, 4, 5}, HostName: "LAB-PC-01"},
		// The same device on a second scope: one item, not two.
		{IP: 0x0a00000a, Mask: 0xffffff00, UID: []byte{0, 1, 2, 3, 4, 5}},
		{IP: exampleIP + 1, Mask: exampleMask, UID: []byte("not-a-mac-at-all")},
	}
	items, unkeyable := derive(leases)
	if len(items) != 1 || unkeyable != 1 {
		t.Fatalf("got %d items and %d unkeyable, want 1 and 1", len(items), unkeyable)
	}

	body, _ := json.Marshal(items)
	text := string(body)
	if text != `[{"macAddress":"00:01:02:03:04:05","hostName":"LAB-PC-01"}]` {
		t.Fatalf("derived inventory is %s", text)
	}
	// R20: nothing that is the lease list leaves. Asserted on the bytes that
	// would be sent rather than on the struct, so a field added later is caught
	// however it is spelled.
	for _, forbidden := range []string{"192.168", "10.0.0", "ip", "scope", "subnet", "expir", "lease"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("derived inventory carries %q: %s", forbidden, text)
		}
	}
}
