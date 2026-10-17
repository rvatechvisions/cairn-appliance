package main

// The DHCP probe's failure path: REFUSED and exit 5 only for the DHCP
// service's own answer. WO-1017-N48 item 2, the change REPORT-WO-1017-N47
// item 2 left untested. probeFailure is what main() calls with the error run()
// returned, so these are the lines and the status a person at the box sees.

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestTheProbeSaysRefusedAndExitsFiveOnlyForAccessDenied(t *testing.T) {
	var out bytes.Buffer
	status := probeFailure(&out, "dhcp01.example.test", errors.New("R_DhcpEnumSubnets: ERROR_ACCESS_DENIED"))
	if status != exitFarEndRefused {
		t.Errorf("ERROR_ACCESS_DENIED exited %d, want %d", status, exitFarEndRefused)
	}
	if !strings.HasPrefix(out.String(), "REFUSED by dhcp01.example.test: ") {
		t.Errorf("ERROR_ACCESS_DENIED printed %q, want it to open REFUSED by the server", out.String())
	}
	if !strings.Contains(out.String(), "THE SERVER ANSWERED") {
		t.Errorf("ERROR_ACCESS_DENIED lost the grant guidance: %q", out.String())
	}
}

func TestTheProbeSaysNeitherForAnyOtherError(t *testing.T) {
	for _, err := range []error{
		errors.New("dialing the endpoint mapper: i/o timeout"),
		errors.New("binding MS-DHCPM: the interface is not registered"),
	} {
		var out bytes.Buffer
		status := probeFailure(&out, "dhcp01.example.test", err)
		if status != 1 {
			t.Errorf("%v exited %d, want 1", err, status)
		}
		if strings.Contains(out.String(), "REFUSED") {
			t.Errorf("%v printed REFUSED: %q", err, out.String())
		}
		if !strings.Contains(out.String(), "ended without a refusal by the server") {
			t.Errorf("%v printed %q, want it to say the read ended without a refusal", err, out.String())
		}
	}
}
