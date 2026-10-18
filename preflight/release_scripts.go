package main

// Scripts by signed manifest. Slice 6 of APPLIANCE-SELF-UPDATE-DESIGN.md in the
// portal repository, first half, WO-1018-N60 item 1. The order author ruled in
// WO-1017-N46 item 5b that slice 6 extends slice 3's manifest format to the
// scripts, so a release is still one manifest signed once with ssh-keygen -Y
// sign under releaseNamespace, now also listing each script by path, SHA-256
// and size (format cairn-release/2, release.go).
//
// ## What happens, and when
//
//   - **At the end of a run, stageRelease.** The release is fetched from the
//     portal and from nowhere else, verified by verifyRelease against the
//     trusted key, every listed file fetched by its digest and checked against
//     the manifest, written beside the running copy and read back, and only
//     then named as staged. Nothing staged runs.
//   - **At the start of the next run, applyStaged.** The staged release is
//     verified again, signature, expiry, sequence and every file's digest as it
//     lies on disk, because a night passed. Then the `current` pointer is moved
//     to it, the release before it is kept as `previous`, and it is on trial.
//   - **After that run, settleRun.** A run that completed confirms the release
//     as applied. A run in which preflight.sh itself failed on the new scripts
//     moves `current` back to `previous`, says so, and never stages that
//     sequence again. The design's own words: *a run in which preflight.sh
//     itself fails on new scripts (not a reader refused, which is a fact about
//     the far end) moves the link back and says so*. A trial that was never
//     settled, because the run died, counts as that failure.
//   - **A held organization.** The portal answers a held box's manifest request
//     with a refusal naming the hold (slice 9, portal src/collector/update-hold.ts).
//     The box still asks, and still reports its run. It stages nothing and
//     applies nothing, and it records no attempt: a hold is the organization's
//     choice, already in the portal's record, and none of slice 1's five
//     outcomes describes it.
//
// ## Nothing unverifiable runs
//
// A manifest whose signature, format, expiry or sequence fails is refused by
// name. So is a file whose size or digest differs from the manifest, a path
// that is not plainly relative, and a staged file changed after it was staged.
// Each refusal is a slice 1 attempt in the ledger, outcome refused, with
// verifyRelease's own sentence as the reason. The ledger holds each entry in
// the shape the portal's parseAttempt reads, src/collector/update-attempts.ts.
//
// ## Stated rather than discovered
//
//   - The `current` link is a pointer file replaced by rename, not a symbolic
//     link. A rename of one file is atomic, as the design asks, and works the
//     same on the Windows build machine where these tests run, where a symbolic
//     link needs a privilege.
//   - ~~Nothing here is called by preflight.sh or the timer yet. Wiring it in,
//     the portal route that serves a release's files, carrying the ledger on
//     the run report, and the about-to-apply call are the rest of slice 6~~
//     *Built where it stands by WO-1018-N62 item 1:* the portal source, the
//     about-to-apply call and the check before `current` moves are in
//     release_apply.go; the binary's -stage-release, -apply-release,
//     -settle-release and -update-attempts modes are in main.go; the run report
//     carries the ledger. **The timer and preflight.sh do not call the three
//     steps yet**, because entering the current release's preflight.sh changes
//     what the unit runs, which Jackie's ruling of 23 September 2026 fixes as
//     the same script a person runs by hand. That entry is proposed in
//     REPORT-WO-1018-N62, not built. Retiring `git pull` is slice 8, which is
//     Jackie's.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// releaseScript is one script file a cairn-release/2 manifest lists.
type releaseScript struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// releaseScripts is the scripts entry: the commit they were taken from, and
// every file.
type releaseScripts struct {
	Commit string          `json:"commit"`
	Files  []releaseScript `json:"files"`
}

func isHex(value string, length int) bool {
	return len(value) == length && strings.Trim(value, "0123456789abcdef") == ""
}

// validScripts refuses a scripts entry that could not be staged safely. It is
// called from verifyRelease, so it judges the signed bytes before anything is
// fetched.
func validScripts(scripts *releaseScripts) error {
	if scripts == nil {
		return errors.New("are absent, and a cairn-release/2 manifest must name them")
	}
	if !isHex(scripts.Commit, 40) {
		return fmt.Errorf("name no 40-character commit (%q)", scripts.Commit)
	}
	if len(scripts.Files) == 0 {
		return errors.New("list no files")
	}
	seen := map[string]bool{}
	for _, file := range scripts.Files {
		if file.Path == "" || strings.Contains(file.Path, "\\") || strings.HasPrefix(file.Path, "/") || path.Clean(file.Path) != file.Path || file.Path == "." || file.Path == ".." || strings.HasPrefix(file.Path, "../") {
			return fmt.Errorf("name a path that is not plainly relative (%q)", file.Path)
		}
		if seen[file.Path] {
			return fmt.Errorf("name %q twice", file.Path)
		}
		seen[file.Path] = true
		if !isHex(file.Digest, 64) {
			return fmt.Errorf("name no SHA-256 for %q (%q)", file.Path, file.Digest)
		}
		if file.Size < 0 {
			return fmt.Errorf("name a negative size for %q", file.Path)
		}
		if file.Path == releaseBinaryPath {
			return fmt.Errorf("name %q as a script, which is where the release's binary goes", file.Path)
		}
	}
	return nil
}

// releaseStore is where staged and applied releases live, each in a directory
// of its own named by sequence, with the pointer files beside them. installed
// is the binary a person installed, the one the timer's entry runs
// (release_apply.go): a release whose binary is that one is staged with a copy
// of it rather than a fetch.
type releaseStore struct {
	root      string
	installed string
}

func defaultReleaseStore() releaseStore {
	installed, err := os.Executable()
	if err != nil {
		installed = ""
	}
	return releaseStore{root: filepath.Join(filepath.Dir(keyPath), "releases"), installed: installed}
}

func (s releaseStore) dir(sequence int64) string {
	return filepath.Join(s.root, strconv.FormatInt(sequence, 10))
}

func (s releaseStore) pointer(name string) string { return filepath.Join(s.root, name) }

// writePointer names a sequence in a pointer file, by writing beside it and
// renaming over it, so a reader sees the old value or the new one and never
// half of either.
func writePointer(file string, sequence int64) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	staging := file + ".incoming"
	if err := os.WriteFile(staging, []byte(strconv.FormatInt(sequence, 10)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(staging, file)
}

// readPointer reads a pointer file. Absent is (0, false); present and not a
// sequence is an error, never zero.
func readPointer(file string) (int64, bool, error) {
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("could not read %s: %w", file, err)
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || value <= 0 {
		return 0, false, fmt.Errorf("%s holds %q, which is not a sequence", file, strings.TrimSpace(string(raw)))
	}
	return value, true, nil
}

func removePointer(file string) error {
	if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// rejected reports whether a sequence was rolled back on this box.
func (s releaseStore) rejected(sequence int64) (bool, error) {
	raw, err := os.ReadFile(s.pointer("rejected"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, line := range strings.Fields(string(raw)) {
		if line == strconv.FormatInt(sequence, 10) {
			return true, nil
		}
	}
	return false, nil
}

func (s releaseStore) reject(sequence int64) error {
	file, err := os.OpenFile(s.pointer("rejected"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintln(file, sequence)
	return err
}

// updateAttempt is one ledger entry, in the shape the portal's parseAttempt
// reads.
type updateAttempt struct {
	AttemptID  string `json:"attemptId"`
	Outcome    string `json:"outcome"`
	Sequence   int64  `json:"sequence,omitempty"`
	Reason     string `json:"reason,omitempty"`
	FromCommit string `json:"fromCommit,omitempty"`
	ToCommit   string `json:"toCommit,omitempty"`
	BoxTime    string `json:"boxTime"`
}

func newAttemptID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

// record appends one attempt to the ledger. A ledger that cannot be written is
// an error the caller prints, never swallowed.
func (s releaseStore) record(attempt updateAttempt, now time.Time) error {
	id, err := newAttemptID()
	if err != nil {
		return err
	}
	attempt.AttemptID = id
	attempt.BoxTime = now.UTC().Format(time.RFC3339)
	line, err := json.Marshal(attempt)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(s.pointer("update-attempts.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(line, '\n'))
	return err
}

// ledger reads every recorded attempt, oldest first.
func (s releaseStore) ledger() ([]updateAttempt, error) {
	raw, err := os.ReadFile(s.pointer("update-attempts.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var attempts []updateAttempt
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var attempt updateAttempt
		if err := json.Unmarshal([]byte(line), &attempt); err != nil {
			return nil, fmt.Errorf("a ledger line does not parse: %w", err)
		}
		attempts = append(attempts, attempt)
	}
	return attempts, nil
}

// scriptsCommit is the scripts commit a stored release names, or empty.
func (s releaseStore) scriptsCommit(sequence int64) string {
	raw, err := os.ReadFile(filepath.Join(s.dir(sequence), "release.json"))
	if err != nil {
		return ""
	}
	var manifest releaseManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.Scripts == nil {
		return ""
	}
	return manifest.Scripts.Commit
}

// currentCommit is the commit of the release `current` names, or empty.
func (s releaseStore) currentCommit() string {
	current, ok, err := readPointer(s.pointer("current"))
	if err != nil || !ok {
		return ""
	}
	return s.scriptsCommit(current)
}

// releaseSource is the portal, as stageRelease sees it. Release answers the
// manifest request: a non-empty held sentence where the portal refused it for a
// hold. File fetches one listed file by its digest.
type releaseSource interface {
	Release() (held string, served *signedRelease, err error)
	File(digest string) ([]byte, error)
	// Binary fetches the release's binary by its SHA-256. Slice 7.
	Binary(digest string) ([]byte, error)
}

// Outcomes of a stage, an apply and a settle, as the box prints them.
const (
	stageStaged        = "staged"
	stageHeld          = "held"
	stageNothingNewer  = "nothing newer"
	stageBinaryOnly    = "binary only"
	stageRefused       = "refused"
	stageUnreachable   = "could not reach the portal"
	applyNothing       = "nothing staged"
	applyOnTrial       = "on trial"
	applyRefused       = "refused"
	settleNothing      = "nothing on trial"
	settleApplied      = "applied"
	settleRolledBack   = "rolled back"
	attemptRefused     = "refused"
	attemptApplied     = "applied"
	attemptRolledBack  = "rolled-back"
	attemptUnreachable = "could-not-reach-portal"
)

type releaseResult struct {
	Outcome  string
	Sequence int64
	Reason   string
}

// stageRelease is the end-of-run step.
func stageRelease(store releaseStore, source releaseSource, trusted []string, now time.Time) (releaseResult, error) {
	held, served, err := source.Release()
	if err != nil {
		reason := fmt.Sprintf("could not read the release: %v", err)
		return releaseResult{Outcome: stageUnreachable, Reason: reason}, store.record(updateAttempt{Outcome: attemptUnreachable, Reason: reason}, now)
	}
	if held != "" {
		return releaseResult{Outcome: stageHeld, Reason: held}, nil
	}
	// No signed release offered at all is the state of a portal before its first
	// signed release, and is not a refusal: there is nothing to stage, and no
	// attempt, so a box does not alert every night for a release nobody signed.
	// WO-1018-N62 item 1. A release offered and not verifiable is refused below.
	if served == nil {
		return releaseResult{Outcome: stageNothingNewer, Reason: "the portal offers no signed release"}, nil
	}
	highest, _, err := readPointer(store.pointer("applied"))
	if err != nil {
		reason := fmt.Sprintf("REFUSED: %v. Nothing was staged", err)
		return releaseResult{Outcome: stageRefused, Reason: reason}, store.record(updateAttempt{Outcome: attemptRefused, Reason: reason}, now)
	}
	manifest, err := verifyRelease(served, trusted, now, highest)
	if err != nil {
		reason := strings.Replace(err.Error(), "Nothing was installed", "Nothing was staged", 1)
		return releaseResult{Outcome: stageRefused, Reason: reason}, store.record(updateAttempt{Outcome: attemptRefused, Sequence: manifest.Sequence, Reason: reason}, now)
	}
	if manifest.Format == releaseFormat {
		return releaseResult{Outcome: stageBinaryOnly, Sequence: manifest.Sequence, Reason: fmt.Sprintf("signed release %d lists the binary alone, so there are no scripts to stage", manifest.Sequence)}, nil
	}
	// Slice 7, WO-1018-N63 item 1: the release's binary is staged beside its
	// scripts, so one move of `current` changes both. A release whose binary is
	// the one installed carries the scripts alone, as N62's did, and only then
	// does oldestBinary decide anything: a release that brings its own binary is
	// the update that meets the level, and is never blocked by it.
	if err := validManifest(binaryManifest{Digest: manifest.Binary.Digest, Commit: manifest.Binary.Commit, Size: manifest.Binary.Size}); err != nil {
		reason := fmt.Sprintf("REFUSED: signed release %d's binary entry is not one a box can stage: %v. Nothing was staged", manifest.Sequence, err)
		return releaseResult{Outcome: stageRefused, Sequence: manifest.Sequence, Reason: reason}, store.record(updateAttempt{Outcome: attemptRefused, Sequence: manifest.Sequence, Reason: reason}, now)
	}
	installed, installedErr := store.installedBinary()
	carriesOwnBinary := installedErr != nil || digestOf(installed) != manifest.Binary.Digest
	if !carriesOwnBinary {
		if err := binaryTooOld(manifest, "staged"); err != nil {
			reason := err.Error()
			return releaseResult{Outcome: stageRefused, Sequence: manifest.Sequence, Reason: reason}, store.record(updateAttempt{Outcome: attemptRefused, Sequence: manifest.Sequence, Reason: reason}, now)
		}
	}
	if manifest.Sequence == highest {
		return releaseResult{Outcome: stageNothingNewer, Sequence: manifest.Sequence, Reason: fmt.Sprintf("signed release %d is the one applied here", manifest.Sequence)}, nil
	}
	if was, err := store.rejected(manifest.Sequence); err != nil {
		return releaseResult{}, err
	} else if was {
		return releaseResult{Outcome: stageNothingNewer, Sequence: manifest.Sequence, Reason: fmt.Sprintf("signed release %d was rolled back here, so it is not staged again", manifest.Sequence)}, nil
	}

	message, err := base64.StdEncoding.DecodeString(served.Manifest)
	if err != nil {
		return releaseResult{}, err
	}
	incoming := store.dir(manifest.Sequence) + ".incoming"
	if err := os.RemoveAll(incoming); err != nil {
		return releaseResult{}, err
	}
	refuse := func(reason string) (releaseResult, error) {
		_ = os.RemoveAll(incoming)
		return releaseResult{Outcome: stageRefused, Sequence: manifest.Sequence, Reason: reason}, store.record(updateAttempt{Outcome: attemptRefused, Sequence: manifest.Sequence, Reason: reason, FromCommit: store.currentCommit(), ToCommit: manifest.Scripts.Commit}, now)
	}
	for _, file := range manifest.Scripts.Files {
		content, err := source.File(file.Digest)
		if err != nil {
			_ = os.RemoveAll(incoming)
			reason := fmt.Sprintf("could not fetch %s: %v", file.Path, err)
			return releaseResult{Outcome: stageUnreachable, Sequence: manifest.Sequence, Reason: reason}, store.record(updateAttempt{Outcome: attemptUnreachable, Sequence: manifest.Sequence, Reason: reason}, now)
		}
		if int64(len(content)) != file.Size {
			return refuse(fmt.Sprintf("REFUSED: %s arrived as %d bytes and signed release %d names %d. Nothing was staged", file.Path, len(content), manifest.Sequence, file.Size))
		}
		if got := digestOf(content); got != file.Digest {
			return refuse(fmt.Sprintf("REFUSED: %s hashes to %s and signed release %d names %s. Nothing was staged", file.Path, got, manifest.Sequence, file.Digest))
		}
		target := filepath.Join(incoming, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return releaseResult{}, err
		}
		if err := os.WriteFile(target, content, 0o700); err != nil {
			return releaseResult{}, err
		}
		landed, err := os.ReadFile(target)
		if err != nil || digestOf(landed) != file.Digest {
			return refuse(fmt.Sprintf("REFUSED: %s as written does not hash to signed release %d. Nothing was staged", file.Path, manifest.Sequence))
		}
	}
	// The binary, after every script, so a release refused for any one file
	// stages no binary either: both or neither.
	binary := installed
	if carriesOwnBinary {
		fetched, err := source.Binary(manifest.Binary.Digest)
		if err != nil {
			_ = os.RemoveAll(incoming)
			reason := fmt.Sprintf("could not fetch the binary %s: %v", manifest.Binary.Digest, err)
			return releaseResult{Outcome: stageUnreachable, Sequence: manifest.Sequence, Reason: reason}, store.record(updateAttempt{Outcome: attemptUnreachable, Sequence: manifest.Sequence, Reason: reason}, now)
		}
		binary = fetched
	}
	if int64(len(binary)) != manifest.Binary.Size {
		return refuse(fmt.Sprintf("REFUSED: the binary arrived as %d bytes and signed release %d names %d. Nothing was staged", len(binary), manifest.Sequence, manifest.Binary.Size))
	}
	if got := digestOf(binary); got != manifest.Binary.Digest {
		return refuse(fmt.Sprintf("REFUSED: the binary hashes to %s and signed release %d names %s. Nothing was staged", got, manifest.Sequence, manifest.Binary.Digest))
	}
	binaryTarget := filepath.Join(incoming, filepath.FromSlash(releaseBinaryPath))
	if err := os.MkdirAll(filepath.Dir(binaryTarget), 0o700); err != nil {
		return releaseResult{}, err
	}
	if err := os.WriteFile(binaryTarget, binary, 0o700); err != nil {
		return releaseResult{}, err
	}
	if landed, err := os.ReadFile(binaryTarget); err != nil || digestOf(landed) != manifest.Binary.Digest {
		return refuse(fmt.Sprintf("REFUSED: the binary as written does not hash to signed release %d. Nothing was staged", manifest.Sequence))
	}
	if err := os.WriteFile(filepath.Join(incoming, "release.json"), message, 0o600); err != nil {
		return releaseResult{}, err
	}
	if err := os.WriteFile(filepath.Join(incoming, "release.json.sig"), []byte(served.Signature), 0o600); err != nil {
		return releaseResult{}, err
	}
	final := store.dir(manifest.Sequence)
	if current, ok, _ := readPointer(store.pointer("current")); !(ok && current == manifest.Sequence) {
		if err := os.RemoveAll(final); err != nil {
			return releaseResult{}, err
		}
	}
	if err := os.Rename(incoming, final); err != nil {
		return releaseResult{}, err
	}
	if err := writePointer(store.pointer("staged"), manifest.Sequence); err != nil {
		return releaseResult{}, err
	}
	binarySaid := "the installed binary"
	if carriesOwnBinary {
		binarySaid = "its own binary " + manifest.Binary.Commit
	}
	return releaseResult{Outcome: stageStaged, Sequence: manifest.Sequence, Reason: fmt.Sprintf("signed release %d staged, %d scripts from %s and %s, each matching its digest", manifest.Sequence, len(manifest.Scripts.Files), manifest.Scripts.Commit, binarySaid)}, nil
}

// releaseBinaryPath is where a release's binary lies inside its directory: the
// path preflight.sh runs as "${HERE}/preflight/preflight", so a release's
// scripts run the release's binary. Slice 7, WO-1018-N63 item 1.
const releaseBinaryPath = "preflight/preflight"

// installedBinary is the bytes of the binary a person installed.
func (s releaseStore) installedBinary() ([]byte, error) {
	if s.installed == "" {
		return nil, errors.New("this box could not locate its installed binary")
	}
	return os.ReadFile(s.installed)
}

// verifyStaged checks a staged release again as it lies on disk: the signature,
// expiry and sequence, and every listed file's digest.
func verifyStaged(store releaseStore, sequence int64, trusted []string, now time.Time, highest int64) (releaseManifest, error) {
	dir := store.dir(sequence)
	message, err := os.ReadFile(filepath.Join(dir, "release.json"))
	if err != nil {
		return releaseManifest{}, fmt.Errorf("REFUSED: staged release %d has no manifest on disk. Nothing was applied", sequence)
	}
	signature, err := os.ReadFile(filepath.Join(dir, "release.json.sig"))
	if err != nil {
		return releaseManifest{}, fmt.Errorf("REFUSED: staged release %d has no signature on disk. Nothing was applied", sequence)
	}
	manifest, err := verifyRelease(&signedRelease{Manifest: base64.StdEncoding.EncodeToString(message), Signature: string(signature)}, trusted, now, highest)
	if err != nil {
		return manifest, errors.New(strings.Replace(err.Error(), "Nothing was installed", "Nothing was applied", 1))
	}
	if manifest.Sequence != sequence || manifest.Format != releaseFormatScripts {
		return manifest, fmt.Errorf("REFUSED: the manifest staged as release %d is release %d, format %q. Nothing was applied", sequence, manifest.Sequence, manifest.Format)
	}
	if installed, err := store.installedBinary(); err == nil && digestOf(installed) == manifest.Binary.Digest {
		if err := binaryTooOld(manifest, "applied"); err != nil {
			return manifest, err
		}
	}
	for _, file := range manifest.Scripts.Files {
		content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(file.Path)))
		if err != nil {
			return manifest, fmt.Errorf("REFUSED: staged release %d is missing %s. Nothing was applied", sequence, file.Path)
		}
		if got := digestOf(content); got != file.Digest || int64(len(content)) != file.Size {
			return manifest, fmt.Errorf("REFUSED: %s changed after it was staged: it hashes to %s and signed release %d names %s. Nothing was applied", file.Path, got, sequence, file.Digest)
		}
	}
	// Slice 7: the binary is part of the release and is checked the same way.
	binary, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(releaseBinaryPath)))
	if err != nil {
		return manifest, fmt.Errorf("REFUSED: staged release %d is missing its binary. Nothing was applied", sequence)
	}
	if got := digestOf(binary); got != manifest.Binary.Digest || int64(len(binary)) != manifest.Binary.Size {
		return manifest, fmt.Errorf("REFUSED: the binary changed after it was staged: it hashes to %s and signed release %d names %s. Nothing was applied", got, sequence, manifest.Binary.Digest)
	}
	return manifest, nil
}

// currentDir is the directory of the release `current` names, or empty where
// none is current. The timer's entry runs that release's preflight.sh.
func (s releaseStore) currentDir() (string, error) {
	current, ok, err := readPointer(s.pointer("current"))
	if err != nil || !ok {
		return "", err
	}
	return s.dir(current), nil
}

// applyStaged is the start-of-run step. The gate is the portal, asked just
// before `current` moves (release_apply.go, WO-1018-N62 item 0c).
func applyStaged(store releaseStore, trusted []string, now time.Time, gate applyGate) (releaseResult, error) {
	if _, onTrial, err := readPointer(store.pointer("trial")); err != nil {
		return releaseResult{}, err
	} else if onTrial {
		if _, err := settleRun(store, true, "the run on it did not finish, so it never confirmed the release", now); err != nil {
			return releaseResult{}, err
		}
	}
	staged, ok, err := readPointer(store.pointer("staged"))
	if err != nil {
		return releaseResult{}, err
	}
	if !ok {
		return releaseResult{Outcome: applyNothing}, nil
	}
	highest, _, err := readPointer(store.pointer("applied"))
	if err != nil {
		return releaseResult{}, err
	}
	manifest, err := verifyStaged(store, staged, trusted, now, highest)
	if err != nil {
		if removeErr := removePointer(store.pointer("staged")); removeErr != nil {
			return releaseResult{}, removeErr
		}
		reason := err.Error()
		return releaseResult{Outcome: applyRefused, Sequence: staged, Reason: reason}, store.record(updateAttempt{Outcome: attemptRefused, Sequence: staged, Reason: reason, FromCommit: store.currentCommit(), ToCommit: manifest.scriptsCommitOrEmpty()}, now)
	}
	if stopped, stop, err := gateApply(store, gate, trusted, now, staged, highest, manifest.scriptsCommitOrEmpty()); err != nil || stop {
		return stopped, err
	}
	if current, has, err := readPointer(store.pointer("current")); err != nil {
		return releaseResult{}, err
	} else if has {
		if err := writePointer(store.pointer("previous"), current); err != nil {
			return releaseResult{}, err
		}
	} else if err := removePointer(store.pointer("previous")); err != nil {
		return releaseResult{}, err
	}
	if err := writePointer(store.pointer("trial"), staged); err != nil {
		return releaseResult{}, err
	}
	if err := writePointer(store.pointer("current"), staged); err != nil {
		return releaseResult{}, err
	}
	if err := removePointer(store.pointer("staged")); err != nil {
		return releaseResult{}, err
	}
	return releaseResult{Outcome: applyOnTrial, Sequence: staged, Reason: fmt.Sprintf("signed release %d is current, on trial for this run", staged)}, nil
}

func (m releaseManifest) scriptsCommitOrEmpty() string {
	if m.Scripts == nil {
		return ""
	}
	return m.Scripts.Commit
}

// settleRun is the after-run step. failed is true only where preflight.sh
// itself failed on the new scripts, never where a reader was refused.
func settleRun(store releaseStore, failed bool, why string, now time.Time) (releaseResult, error) {
	trial, ok, err := readPointer(store.pointer("trial"))
	if err != nil {
		return releaseResult{}, err
	}
	if !ok {
		return releaseResult{Outcome: settleNothing}, nil
	}
	previous, hasPrevious, err := readPointer(store.pointer("previous"))
	if err != nil {
		return releaseResult{}, err
	}
	fromCommit := ""
	if hasPrevious {
		fromCommit = store.scriptsCommit(previous)
	}
	toCommit := store.scriptsCommit(trial)
	if !failed {
		if err := writePointer(store.pointer("applied"), trial); err != nil {
			return releaseResult{}, err
		}
		if err := removePointer(store.pointer("trial")); err != nil {
			return releaseResult{}, err
		}
		return releaseResult{Outcome: settleApplied, Sequence: trial, Reason: fmt.Sprintf("updated to %s, signed release %d", toCommit, trial)}, store.record(updateAttempt{Outcome: attemptApplied, Sequence: trial, FromCommit: fromCommit, ToCommit: toCommit}, now)
	}
	if hasPrevious {
		if err := writePointer(store.pointer("current"), previous); err != nil {
			return releaseResult{}, err
		}
	} else if err := removePointer(store.pointer("current")); err != nil {
		return releaseResult{}, err
	}
	if err := store.reject(trial); err != nil {
		return releaseResult{}, err
	}
	if err := removePointer(store.pointer("trial")); err != nil {
		return releaseResult{}, err
	}
	back := "the scripts this box had before any release"
	if hasPrevious {
		back = fmt.Sprintf("signed release %d (%s)", previous, fromCommit)
	}
	reason := fmt.Sprintf("signed release %d was moved back to %s: %s", trial, back, why)
	return releaseResult{Outcome: settleRolledBack, Sequence: trial, Reason: reason}, store.record(updateAttempt{Outcome: attemptRolledBack, Sequence: trial, Reason: reason, FromCommit: toCommit, ToCommit: fromCommit}, now)
}
