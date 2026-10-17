package main

// Whose an error is, as a type and an exit status rather than a prefix.
// APPLIANCE-BINARY-QUEUE.md item 1 in the portal repository, WO-1004-V item 2,
// built under WO-1017-N47 item 2.
//
// Until this, every failure left the binary as one line, `preflight: <error>`,
// and preflight.sh decided whose it was by the words: Cairn's own portal
// refusing what the box sent, or the system being read saying no. The portal's
// words can themselves say "refused", and on 5 October 2026 a refusal by Cairn
// read as Zabbix, vCenter, Configuration Manager, Proxmox VE or the relay
// refusing us. Now the error carries whose it is, and the exit status says so:
//
//   - exitPortalRefused (4): Cairn's portal refused what this box sent or asked.
//     Never a refusal by the system being read.
//   - exitFarEndRefused (5): the system being read answered, and the answer was
//     no: it refused the account or the token, or declined the request.
//   - 1 stays anything else: no answer, a fault here, or an answer this binary
//     cannot place. The shell says COULD NOT TELL for it.
//
// 3 (not asked) and 2 (the shell's mistake) are unchanged. -speaks declares
// error-source, so a shell can tell a binary that says whose an error is from
// one that does not, and keeps reading the words for the second.

import "errors"

const (
	exitPortalRefused = 4
	exitFarEndRefused = 5
)

// portalRefusal is Cairn's portal refusing this box.
type portalRefusal struct{ err error }

func (p portalRefusal) Error() string { return p.err.Error() }
func (p portalRefusal) Unwrap() error { return p.err }

// farEndRefusal is the system being read answering no.
type farEndRefusal struct{ err error }

func (f farEndRefusal) Error() string { return f.err.Error() }
func (f farEndRefusal) Unwrap() error { return f.err }

func portalRefused(err error) error { return portalRefusal{err} }
func farEndRefused(err error) error { return farEndRefusal{err} }

// failureExit is the exit status for a reader's error. The portal is checked
// first: a submission the portal refused after the far end had answered is the
// portal's refusal, whatever the far end said.
func failureExit(err error) int {
	var portal portalRefusal
	if errors.As(err, &portal) {
		return exitPortalRefused
	}
	var far farEndRefusal
	if errors.As(err, &far) {
		return exitFarEndRefused
	}
	return 1
}
