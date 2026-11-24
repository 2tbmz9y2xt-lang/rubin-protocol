package exclusionjournal

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math"
	"math/bits"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"golang.org/x/sys/unix"
)

type sourceNamespace func(*sourceRoot, string, string) error

const (
	publicStagePrefix = ".staging-"
	heldStagePrefix   = ".stage-hold-"
)

type sourceFS struct {
	statfs          func(int, *syscall.Statfs_t) error
	write           func(*os.File, []byte) (int, error)
	fileSync, close func(*os.File) error
	chmod           func(*os.File, os.FileMode) error
	namespace       func(sourceNamespace, *sourceRoot, string, string) error
	remove          func(*os.Root, string) error
	dirSync         func(*os.File) error
}
type sourceDebt struct {
	name, leaf                string
	file                      filelock.IdentityV1
	binding                   *sourceIncarnation
	size, observed, qualified uint64
	shared, unlinkTried       bool
}

type sourceUsage struct {
	files, bytes, captureFiles, captureBytes             uint64
	visitedBytes, aliasBytes, stageCovered, quotaCovered uint64
	stage, pendingStage                                  sourceDebt
	quota                                                os.FileInfo
	releaseMissing                                       int
	stageErr, visitErr                                   error
	stageReached, overBytes, forRelease, completeCharge  bool
	entries                                              []os.DirEntry
	releaseLeaf                                          string
	read                                                 sourceReadCensus
}

type sourceReadCensus struct {
	name, blockedStage                           string
	names                                        []string
	witness                                      sourceDebt
	target, blockedStageFile                     filelock.IdentityV1
	pending                                      []sourceReadMismatch
	nameIndex                                    []int
	indexLimit, pendingLimit                     int
	ordinal, refusalOrdinal                      int
	hasSpellings, stoppedStageUnknown, localized bool
}

type sourceReadMismatch struct {
	original, observed             filelock.IdentityV1
	ordinal                        int
	identityMismatch, stageReached bool
}

// sourceEntryNames borrows the ordered names from a scoped or strict listing.
type sourceEntryNames struct {
	entries []os.DirEntry
	names   []string
}

func sourceListing(entries []os.DirEntry, read []sourceReadCensus) sourceEntryNames {
	if len(read) != 0 && read[0].name != "" {
		return sourceEntryNames{names: read[0].names}
	}
	return sourceEntryNames{entries: entries}
}

func (s sourceEntryNames) len() int {
	return len(s.entries) + len(s.names)
}

func (s sourceEntryNames) name(i int) string {
	if s.names != nil {
		return s.names[i]
	}
	return s.entries[i].Name()
}

var realSourceFS = sourceFS{statfs: syscall.Fstatfs, write: (*os.File).Write, fileSync: (*os.File).Sync, close: (*os.File).Close, chmod: (*os.File).Chmod, namespace: runSourceNamespace, remove: (*os.Root).Remove, dirSync: (*os.File).Sync}

func runSourceNamespace(op sourceNamespace, r *sourceRoot, from, to string) error {
	return op(r, from, to)
}

func (o *SourceOwnerV1) sourceEntries(r *sourceRoot, read ...sourceReadCensus) ([]os.DirEntry, error) {
	f, err := openSourceAt(int(r.pin.Fd()), ".", unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	if len(read) != 0 {
		return nil, o.sourceReadNames(f, &read[0])
	}
	entries, err := f.ReadDir(int(min(o.limits.Scans, math.MaxInt)))
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if uint64(len(entries)) >= o.limits.Scans {
		return nil, ErrCapacityV1
	}
	return entries, nil
}

// sourceReadNames retains names without looking up their metadata.
func (o *SourceOwnerV1) sourceReadNames(f *os.File, read *sourceReadCensus) error {
	names, err := f.Readdirnames(int(min(o.limits.Scans, math.MaxInt)))
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if uint64(len(names)) >= o.limits.Scans {
		return ErrCapacityV1
	}
	read.names = names
	return nil
}

func (o *SourceOwnerV1) census(r *sourceRoot, forRelease bool) (sourceUsage, error) {
	return o.censusWithRead(r, forRelease)
}

func (o *SourceOwnerV1) censusWithRead(r *sourceRoot, forRelease bool, read ...sourceReadCensus) (sourceUsage, error) {
	entries, err := o.sourceEntries(r, read...)
	if err != nil {
		return sourceUsage{}, err
	}
	o.resolvePublications(r)
	used, err := o.censusFiles(r, entries, forRelease, read...)
	if used.stageReached && used.stage.held() && o.debt.file == used.stage.file {
		o.debt.leaf = used.stage.leaf
		o.stage.Clear()
	}
	return used, err
}

func (o *SourceOwnerV1) censusFiles(r *sourceRoot, entries []os.DirEntry, forRelease bool, read ...sourceReadCensus) (sourceUsage, error) {
	location, err := o.releaseCensusLocation(r)
	if err != nil {
		return sourceUsage{}, err
	}
	if o.debt.unlinkTried {
		_ = o.observeStageRemoval(r)
	}
	stage, prefix, stopErr := o.censusStage(r, entries, read...)
	if stopErr != nil && stage.held() {
		return sourceUsage{}, stopErr
	}
	if err := o.observeCensusReleaseAlias(r, location, stage, stopErr == nil); err != nil {
		return sourceUsage{}, err
	}
	stageErr := o.debt.qualifyStage(&stage)
	used := o.stagingUsage(stage)
	used.entries = entries
	used.forRelease, used.stageErr, used.releaseLeaf = forRelease, stageErr, location
	listed := sourceListing(entries, read)
	used.read = o.startReadCensus(read)
	o.chargeBindings(&used)
	used, err = o.censusCaptures(r, listed, prefix, used, stopErr)
	if stopErr != nil && strings.HasPrefix(listed.name(prefix), heldStagePrefix) {
		return sourceUsage{stage: stage, stageReached: used.stageReached, entries: entries, read: used.read}, stopErr
	}
	return used, err
}

// releaseCensusLocation admits the backing pair before inspecting ordinary entries.
func (o *SourceOwnerV1) releaseCensusLocation(r *sourceRoot) (string, error) {
	location, err := o.release.releaseLocation(r)
	if err == nil && o.release != nil {
		_, err = o.release.checkReleaseScratch(r)
	}
	return location, err
}

// observeCensusReleaseAlias keeps the current spelling for a positively observed alias.
func (o *SourceOwnerV1) observeCensusReleaseAlias(r *sourceRoot, location string, stage sourceDebt, complete bool) error {
	d := o.release
	if d == nil || location == "" || d.phase != releaseBackingPending || !complete {
		return nil
	}
	if err := d.observePriorAlias(r); err != nil {
		return err
	}
	o.rebindReleaseAlias(r, d, stage)
	return nil
}

func (o *SourceOwnerV1) stagingUsage(stage sourceDebt) sourceUsage {
	used := sourceUsage{stage: stage, pendingStage: o.pendingStage}
	used.pendingStage.shared = false
	if info, _ := o.stage.Quota.Stat(); used.pendingStage.binding == nil && sameSourceFile(info, used.pendingStage.file) {
		used.quota = info
	}
	return used
}

// startReadCensus selects the held target identity when its capture is settled.
func (o *SourceOwnerV1) startReadCensus(read []sourceReadCensus) sourceReadCensus {
	if len(read) == 0 {
		return sourceReadCensus{}
	}
	scope := read[0]
	if target := o.live[scope.name]; settledReadBinding(target) {
		scope.target = target.file
	}
	return scope
}

// sourceStageSpelling extracts the capture key from a public or held stage name.
func sourceStageSpelling(leaf string) string {
	if name, ok := strings.CutPrefix(leaf, publicStagePrefix); ok {
		return name
	}
	return strings.TrimPrefix(leaf, heldStagePrefix)
}

// settledReadBinding identifies an issued reserve with a confirmed inode.
func settledReadBinding(b *sourceIncarnation) bool {
	return b != nil && b.issued && !b.uncertain && b.file != (filelock.IdentityV1{})
}

// privateReadBinding excludes live ties to a requested capture or a protected holder.
func (o *SourceOwnerV1) privateReadBinding(used *sourceUsage, name string, b *sourceIncarnation) bool {
	return settledReadBinding(b) && name != used.read.name && !o.readHolder(used, name, b.file, b)
}

// readHolder checks the stage, its pending quota, and the release custody.
func (o *SourceOwnerV1) readHolder(used *sourceUsage, name string, file filelock.IdentityV1, b *sourceIncarnation) bool {
	read := &used.read
	if name == o.observedStage || strings.EqualFold(name, read.blockedStage) || file == read.blockedStageFile {
		return true
	}
	for _, stage := range [...]sourceDebt{used.stage, used.pendingStage, o.debt, read.witness} {
		if strings.EqualFold(name, stage.name) || file == stage.file || b == stage.binding {
			return true
		}
	}
	return o.release.readHolder(name, file)
}

// readHolder covers both release backing spellings and its tracked stage key.
func (d *sourceRelease) readHolder(name string, file filelock.IdentityV1) bool {
	return d != nil && (name == d.name || file == d.file || strings.EqualFold(name, sourceStageSpelling(d.alias)))
}

// acceptReadOmissions clears only distinct missing bindings and leaves their reserves charged.
func (o *SourceOwnerV1) acceptReadOmissions(used *sourceUsage) {
	read := &used.read
	for name, b := range o.live {
		if o.privateReadBinding(used, name, b) && b.file != read.target && o.firstReadName(read, name) == "" {
			used.releaseMissing--
			read.localized = true
			if used.releaseMissing == 0 {
				break
			}
		}
	}
}

// selectReadRefusal preserves the first pending observation when the target was not reached.
func (used *sourceUsage) selectReadRefusal() {
	if read := &used.read; len(read.pending) != 0 {
		used.applyPendingRefusal(read.pending[0])
		read.pending = nil
	}
}

// applyPendingRefusal selects the earlier result and its stage boundary.
func (used *sourceUsage) applyPendingRefusal(pending sourceReadMismatch) {
	read := &used.read
	if used.visitErr != nil && pending.ordinal > read.refusalOrdinal {
		return
	}
	refusal := ErrIntegrityV1
	if pending.identityMismatch {
		refusal = ErrIdentityV1
	}
	used.visitErr, used.stageReached = refusal, pending.stageReached
	read.refusalOrdinal = pending.ordinal
}

// chargeBindings reserves space for bound captures, including missing files.
func (o *SourceOwnerV1) chargeBindings(used *sourceUsage) {
	for _, backing := range o.live {
		if backing.issued {
			used.releaseMissing++
			if used.forRelease {
				continue
			}
		}
		size, _ := used.bindingCharge(backing)
		if used.stage.binding == backing {
			used.coverQuota(backing.file, size, true)
		}
		o.charge(used, size)
	}
}

func (used *sourceUsage) bindingCharge(backing *sourceIncarnation) (uint64, bool) {
	size, shared := backing.size, false
	for _, stage := range [...]*sourceDebt{&used.stage, &used.pendingStage} {
		if stage.binding == backing {
			size, shared, stage.shared = max(size, stage.size), true, true
		}
	}
	return size, shared
}

func (o *SourceOwnerV1) censusCaptures(r *sourceRoot, listed sourceEntryNames, prefix int, used sourceUsage, stopErr error) (sourceUsage, error) {
	absentRelease := o.release
	for i := range prefix {
		used.read.ordinal = i
		name := listed.name(i)
		if err := o.censusEntry(r, name, &used); err != nil {
			used.selectReadRefusal()
			return used, cmp.Or(used.visitErr, err)
		}
		if stopErr != nil && used.visitErr != nil {
			used.selectReadRefusal()
			return used, used.visitErr
		}
		if absentRelease != nil && name == used.releaseLeaf {
			absentRelease = nil
		}
	}
	used.selectReadRefusal()
	if stopErr != nil {
		return used, stopErr
	}
	return o.finishReadCensus(used, absentRelease)
}

// finishReadCensus applies private omissions after the ordered and aggregate checks pass.
func (o *SourceOwnerV1) finishReadCensus(used sourceUsage, absentRelease *sourceRelease) (sourceUsage, error) {
	used, err := o.finishCensus(used, absentRelease)
	if used.read.name != "" && used.visitErr == nil && err == nil && used.releaseMissing > 0 {
		o.acceptReadOmissions(&used)
	}
	return used, err
}

func (o *SourceOwnerV1) censusEntry(r *sourceRoot, name string, used *sourceUsage) error {
	switch name {
	case used.stage.leaf:
		return o.chargeCensusStage(used)
	case releaseFile:
		if o.release == nil {
			return ErrIntegrityV1
		}
	case releaseScratch:
	case releaseDetached:
		if used.releaseLeaf != releaseDetached {
			return ErrIntegrityV1
		}
		return o.censusCaptureAt(r, o.release.name, name, used)
	default:
		return o.censusCapture(r, name, used)
	}
	return nil
}

// chargeCensusStage accounts for the stage at its position in the listing.
func (o *SourceOwnerV1) chargeCensusStage(used *sourceUsage) error {
	if used.stageErr != nil {
		return used.stageErr
	}
	if cmp.Or(o.observedStage, used.stage.name) != used.stage.name {
		return ErrBusyV1
	}
	used.stageReached = used.visitErr == nil
	size := used.stage.size - used.aliasBytes
	if used.forRelease {
		size = used.stage.observed
		o.charge(used, size)
	}
	o.visitCensusBytes(used, size, 0, false)
	return nil
}

func (o *SourceOwnerV1) finishCensus(used sourceUsage, absentRelease *sourceRelease) (sourceUsage, error) {
	if !used.forRelease {
		if absentRelease != nil {
			if backing := o.live[absentRelease.name]; backing == nil {
				o.charge(&used, absentRelease.size)
			} else if backing.issued {
				used.releaseMissing--
			}
		}
		used.captureFiles, used.captureBytes = used.files, used.bytes
		o.chargeStages(&used)
	}
	if used.overBytes || used.files > o.limits.Files || any(used.visitErr) == any(ErrCapacityV1) {
		return used, ErrCapacityV1
	}
	return used, used.stageErr
}

// chargeStages counts shared backing once (RUBIN_COMPACT_BLOCKS.md Section 10).
func (o *SourceOwnerV1) chargeStages(used *sourceUsage) {
	stage, pending := used.stage, used.pendingStage
	if used.quota != nil {
		pending.size = max(pending.size, sourceFileSize(used.quota))
		if stage.file == pending.file {
			pending.size = max(pending.size, stage.size)
			stage = sourceDebt{}
		}
		pending.size -= min(pending.size, used.quotaCovered)
		if pending.shared {
			o.chargeBytes(used, pending.size)
		}
	}
	stage.size -= min(stage.size, used.stageCovered)
	for _, stage := range [...]sourceDebt{stage, pending} {
		if stage.name != "" && !stage.shared {
			o.charge(used, stage.size)
		}
	}
}

func (used sourceUsage) admissionError(err error) error {
	if err := cmp.Or(used.visitErr, err); err != nil {
		return err
	}
	if used.releaseMissing != 0 {
		return ErrIntegrityV1
	}
	return nil
}

func (o *SourceOwnerV1) charge(used *sourceUsage, size uint64) {
	o.chargeBytes(used, size)
	used.files++
}

func (o *SourceOwnerV1) chargeBytes(used *sourceUsage, size uint64) {
	if size > o.limits.Bytes-used.bytes {
		used.overBytes = true
		return
	}
	used.bytes += size
}

// visitCensusBytes charges entries in directory order until the first refusal.
func (o *SourceOwnerV1) visitCensusBytes(used *sourceUsage, size, aliasBytes uint64, alias bool) {
	if used.visitErr != nil || used.completeCharge {
		return
	}
	if covered := min(aliasBytes, used.stage.size); alias && !used.forRelease && covered > used.aliasBytes {
		if used.stageReached {
			size -= covered - used.aliasBytes
		}
		used.aliasBytes = covered
	}
	if size > o.limits.Bytes-used.visitedBytes {
		used.visitErr = ErrCapacityV1
		used.read.refusalOrdinal = used.read.ordinal
		return
	}
	used.visitedBytes += size
}

func (o *SourceOwnerV1) censusCapture(r *sourceRoot, name string, used *sourceUsage) error {
	if !sourceHexKey(name) {
		return ErrIntegrityV1
	}
	return o.censusCaptureAt(r, name, name, used)
}

// censusCaptureAt charges the capture key from the actual backing leaf.
func (o *SourceOwnerV1) censusCaptureAt(r *sourceRoot, name, leaf string, used *sourceUsage) error {
	info, err := sourceEntryInfo(r, leaf, nil)
	if err != nil {
		return ErrIntegrityV1
	}
	id := filelock.FileIdentityV1(info)
	size := sourceFileSize(info)
	if leaf == used.releaseLeaf {
		if err := o.release.matchBacking(id, size); err != nil {
			return err
		}
	}
	backing := o.live[name]
	if err := o.observeCensusCapture(used, name, backing, info, id, size); err != nil {
		return err
	}
	if backing == nil {
		o.chargeNamedCapture(used, nil, id, size)
	} else {
		o.chargeBoundCapture(used, backing, id, size)
	}
	return nil
}

func (o *SourceOwnerV1) chargeNamedCapture(used *sourceUsage, backing *sourceIncarnation, id filelock.IdentityV1, size uint64) {
	o.visitCensusBytes(used, size, size, id == used.stage.file)
	o.charge(used, size)
	used.coverQuota(id, size, true)
	if backing != nil && backing.file != id {
		backing = nil
	}
	used.stage.observeAlias(id, backing)
}

func (o *SourceOwnerV1) chargeBoundCapture(used *sourceUsage, backing *sourceIncarnation, id filelock.IdentityV1, size uint64) {
	reserved, shared := used.bindingCharge(backing)
	if used.namedBackingCharge(backing, id, shared) {
		o.chargeNamedCapture(used, backing, id, size)
		return
	}
	excess := size - min(size, reserved)
	if !shared && backing.issued && !used.completeCharge && used.read.name == "" {
		excess = 0
	}
	o.chargeReservedCapture(used, backing, id, size, reserved, excess)
}

// namedBackingCharge separates a distinct read replacement from its issued reserve.
func (used *sourceUsage) namedBackingCharge(b *sourceIncarnation, id filelock.IdentityV1, shared bool) bool {
	return used.forRelease && b.issued || id != b.file && (shared || used.read.name != "" && b.issued)
}

func (o *SourceOwnerV1) chargeReservedCapture(used *sourceUsage, backing *sourceIncarnation, id filelock.IdentityV1, size, reserved, excess uint64) {
	if !used.forRelease {
		size = max(size, backing.size)
	}
	matches := id == backing.file
	extent, covered := excess, excess
	if matches {
		backing.uncertain = false
		extent = size
		covered += reserved
		used.stage.observeAlias(id, backing)
	} else if id == used.stage.file {
		used.stageCovered = max(used.stageCovered, extent)
	}
	o.visitCensusBytes(used, size, extent, id == used.stage.file)
	o.chargeBytes(used, excess)
	used.coverQuota(id, covered, matches)
}

func (used *sourceUsage) coverQuota(id filelock.IdentityV1, size uint64, full bool) {
	if used.quota != nil && used.pendingStage.file == id {
		used.pendingStage.shared = used.pendingStage.shared || full
		used.quotaCovered = max(used.quotaCovered, size)
	}
}

func (used *sourceUsage) observeIssuedCapture(backing *sourceIncarnation, id filelock.IdentityV1, size uint64) {
	used.releaseMissing--
	if used.visitErr == nil {
		used.visitErr = backing.censusMismatch(id, size)
	}
}

func (b *sourceIncarnation) censusMismatch(id filelock.IdentityV1, size uint64) error {
	switch {
	case b.file != id:
		return ErrIdentityV1
	case b.size != size:
		return ErrIntegrityV1
	default:
		return nil
	}
}

// observeCensusCapture selects the ordered strict or scoped disposition of a listed capture.
func (o *SourceOwnerV1) observeCensusCapture(used *sourceUsage, name string, b *sourceIncarnation, info os.FileInfo, id filelock.IdentityV1, size uint64) error {
	if used.read.name == "" {
		if b != nil && b.issued {
			used.observeIssuedCapture(b, id, size)
		}
		return nil
	}
	stat, _ := info.Sys().(*syscall.Stat_t)
	if stat == nil || stat.Nlink == 0 || id == (filelock.IdentityV1{}) {
		return ErrIntegrityV1
	}
	if !used.completeCharge {
		o.observeReadCapture(used, name, b, id, size, stat.Nlink == 1)
	}
	return nil
}

// observeReadCapture accounts the issued observation before deciding whether its fault is private.
func (o *SourceOwnerV1) observeReadCapture(used *sourceUsage, name string, b *sourceIncarnation, id filelock.IdentityV1, size uint64, singleLink bool) {
	if name == used.read.name {
		used.observeReadTarget(id)
	}
	if b == nil || !b.issued {
		return
	}
	used.releaseMissing--
	refusal := b.censusMismatch(id, size)
	if used.visitErr == nil && refusal != nil {
		private := singleLink && o.privateReadBinding(used, name, b)
		if !o.isolateReadMismatch(used, name, b, id, private) {
			used.visitErr, used.read.refusalOrdinal = refusal, used.read.ordinal
		}
	}
}

// isolateReadMismatch retains a private fault's original position until target identity is known.
func (o *SourceOwnerV1) isolateReadMismatch(used *sourceUsage, name string, b *sourceIncarnation, id filelock.IdentityV1, private bool) bool {
	read := &used.read
	if !private || read.stoppedStageUnknown || read.target == id || read.target == b.file || o.readHolder(used, name, id, b) {
		return false
	}
	if o.hasReadSpelling(read, name) {
		return false
	}
	if read.target == (filelock.IdentityV1{}) {
		return used.deferMismatch(b.file, id)
	}
	read.localized = true
	return true
}

// deferMismatch records a reached candidate in the space bounded by listed issued keys.
func (used *sourceUsage) deferMismatch(original, observed filelock.IdentityV1) bool {
	read := &used.read
	if len(read.pending) >= read.pendingLimit {
		return false
	}
	if read.pending == nil {
		read.pending = make([]sourceReadMismatch, 0, read.pendingLimit)
	}
	read.pending = append(read.pending, sourceReadMismatch{
		original: original, observed: observed, ordinal: read.ordinal,
		identityMismatch: original != observed, stageReached: used.stageReached,
	})
	return true
}

// observeReadTarget resolves reached mismatches against the observed target inode.
func (used *sourceUsage) observeReadTarget(id filelock.IdentityV1) {
	read := &used.read
	if read.target != (filelock.IdentityV1{}) {
		return
	}
	read.target = id
	for _, pending := range read.pending {
		if id == pending.original || id == pending.observed {
			used.applyPendingRefusal(pending)
			break
		}
		read.localized = true
	}
	read.pending = nil
}

// observeReadName counts indexable names and settled issued prefix keys.
func (o *SourceOwnerV1) observeReadName(read *sourceReadCensus, name string, inPrefix bool) {
	include, alternate := o.indexableReadName(name)
	if !include {
		return
	}
	read.indexLimit++
	if alternate {
		read.hasSpellings = true
		return
	}
	if inPrefix && name != read.name && settledReadBinding(o.live[name]) {
		read.pendingLimit++
	}
}

// indexableReadName accepts canonical hex and listed alternates of issued keys.
func (o *SourceOwnerV1) indexableReadName(name string) (include, alternate bool) {
	if len(name) != 2*sha256.Size {
		return false, false
	}
	if strings.ContainsAny(name, "ABCDEF") {
		return o.issuedReadSpelling(name), true
	}
	return sourceHexKey(name), false
}

// issuedReadSpelling matches a case variant to a canonical key of a live issued capture.
func (o *SourceOwnerV1) issuedReadSpelling(name string) bool {
	var key [2 * sha256.Size]byte
	for i := range key {
		c := name[i]
		if c >= 'A' && c <= 'F' {
			c += 'a' - 'A'
		}
		key[i] = c
	}
	b := o.live[string(key[:])]
	return b != nil && b.issued
}

// readNameIndex sorts ordinals into the borrowed listing without changing its order.
func (o *SourceOwnerV1) readNameIndex(read *sourceReadCensus) []int {
	if read.nameIndex == nil && read.indexLimit != 0 {
		read.nameIndex = make([]int, read.indexLimit)
		i := 0
		for ordinal, leaf := range read.names {
			if include, _ := o.indexableReadName(leaf); include {
				read.nameIndex[i] = ordinal
				i++
			}
		}
		slices.SortFunc(read.nameIndex, func(a, b int) int {
			return compareReadName(read.names[a], read.names[b])
		})
	}
	return read.nameIndex
}

// hasReadSpelling checks the first folded match, where alternates precede the lowercase key.
func (o *SourceOwnerV1) hasReadSpelling(read *sourceReadCensus, name string) bool {
	if !read.hasSpellings {
		return false
	}
	match := o.firstReadName(read, name)
	return match != "" && match != name
}

// firstReadName returns the earliest spelling in the key's folded group.
func (o *SourceOwnerV1) firstReadName(read *sourceReadCensus, name string) string {
	index := o.readNameIndex(read)
	i, found := slices.BinarySearchFunc(index, name, func(i int, key string) int {
		return compareCaptureSpelling(read.names[i], key)
	})
	if !found {
		return ""
	}
	return read.names[index[i]]
}

func compareReadName(a, b string) int {
	if order := compareCaptureSpelling(a, b); order != 0 {
		return order
	}
	return cmp.Compare(a, b)
}

// compareCaptureSpelling compares validated hex keys in ASCII-folded order.
func compareCaptureSpelling(a, b string) int {
	for i := range 2 * sha256.Size {
		left, right := a[i]|('a'-'A'), b[i]|('a'-'A')
		if left != right {
			return int(left) - int(right)
		}
	}
	return 0
}

func (d *sourceDebt) observeAlias(id filelock.IdentityV1, backing *sourceIncarnation) {
	if d.name != "" && d.file == id {
		if d.shared {
			backing = cmp.Or(d.binding, backing)
		}
		d.shared, d.binding = true, backing
	}
}

// resolvePublications drops missing captures and confirms matching inodes.
func (o *SourceOwnerV1) resolvePublications(r *sourceRoot) {
	for name, backing := range o.live {
		if !backing.uncertain {
			continue
		}
		info, err := r.Lstat(name)
		switch {
		case errors.Is(err, os.ErrNotExist):
			o.forgetPublication(name, backing)
		case err == nil && sameSourceFile(info, backing.file):
			backing.uncertain = false
		}
	}
}

func (o *SourceOwnerV1) forgetPublication(name string, backing *sourceIncarnation) {
	delete(o.live, name)
	if o.debt.binding == backing {
		o.debt.binding, o.debt.shared = nil, false
	}
}

// openSourceFile checks that a nonblocking, no-follow open pins the observed regular file.
func openSourceFile(r *sourceRoot, name string, unobserved error, expected ...filelock.IdentityV1) (*os.File, error) {
	named, err := sourceEntryInfo(r, name, unobserved)
	if err != nil || len(expected) != 0 && !sameSourceFile(named, expected[0]) {
		return nil, cmp.Or(err, ErrIdentityV1)
	}
	f, err := openSourceAt(int(r.pin.Fd()), name, unix.O_NONBLOCK)
	if err != nil {
		return nil, ErrUnavailableV1
	}
	if info, _ := f.Stat(); !os.SameFile(named, info) {
		_ = f.Close()
		return nil, ErrIntegrityV1
	}
	return f, nil
}

func openSourceAt(parent int, name string, flags int) (*os.File, error) {
	fd, err := -1, error(unix.EINTR)
	for errors.Is(err, unix.EINTR) {
		fd, err = unix.Openat(parent, name, flags|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func sourceEntryInfo(r *sourceRoot, name string, unobserved error) (os.FileInfo, error) {
	info, err := r.Lstat(name)
	if err != nil {
		return nil, cmp.Or(unobserved, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return nil, ErrIntegrityV1
	}
	return info, nil
}

func sourceFileSize(info os.FileInfo) uint64 {
	return uint64(max(0, info.Size()))
}

func sameSourceFile(info os.FileInfo, expected filelock.IdentityV1) bool {
	return info != nil && info.Mode().IsRegular() && filelock.FileIdentityV1(info) == expected
}

func sourceHexKey(name string) bool {
	if len(name) != sha256.Size*2 {
		return false
	}
	var decoded [sha256.Size]byte
	_, err := hex.Decode(decoded[:], []byte(name))
	return err == nil
}

func (d sourceDebt) held() bool { return strings.HasPrefix(d.leaf, heldStagePrefix) }

// censusStage inspects stages through the first staging error and reads the listed spellings.
func (o *SourceOwnerV1) censusStage(r *sourceRoot, entries []os.DirEntry, read ...sourceReadCensus) (sourceDebt, int, error) {
	var stage sourceDebt
	var stopErr error
	listed := sourceListing(entries, read)
	prefix := listed.len()
	for i := range prefix {
		leaf := listed.name(i)
		if len(read) != 0 {
			o.observeReadName(&read[0], leaf, stopErr == nil)
		}
		if stopErr != nil {
			continue
		}
		stopped, err := o.observeStageEntry(r, &stage, leaf)
		if err != nil {
			stopErr = err
			prefix = i
			if len(read) == 0 {
				break
			}
			read[0].blockedStage = sourceStageSpelling(stopped.leaf)
			read[0].blockedStageFile = stopped.file
			read[0].stoppedStageUnknown = stopped.file == (filelock.IdentityV1{}) && strings.HasPrefix(stopped.leaf, publicStagePrefix)
		}
	}
	return stage, prefix, stopErr
}

// observeStageEntry selects the first stage and returns the stopped stage observation.
func (o *SourceOwnerV1) observeStageEntry(r *sourceRoot, stage *sourceDebt, leaf string) (sourceDebt, error) {
	next, err := o.readStageEntry(r, leaf)
	if err != nil {
		return next, err
	}
	switch {
	case next.name == "":
	case stage.name == "":
		*stage = next
	case stage.name == next.name && stage.held() != next.held():
		return next, syscall.EEXIST
	default:
		return next, ErrBusyV1
	}
	return sourceDebt{}, nil
}

func (o *SourceOwnerV1) readStageEntry(r *sourceRoot, leaf string) (sourceDebt, error) {
	name, public := strings.CutPrefix(leaf, publicStagePrefix)
	if !public {
		name, _ = strings.CutPrefix(leaf, heldStagePrefix)
		if name == leaf {
			return sourceDebt{}, nil
		}
	}
	key := strings.ToLower(name)
	if !sourceHexKey(name) || !public && key != name {
		return sourceDebt{}, ErrIntegrityV1
	}
	info, err := sourceEntryInfo(r, leaf, ErrIntegrityV1)
	if err != nil {
		return sourceDebt{leaf: leaf}, err
	}
	size := sourceFileSize(info)
	id := filelock.FileIdentityV1(info)
	o.observeRetainedStage(leaf, id)
	return sourceDebt{name: key, leaf: leaf, size: size, observed: size, file: id}, nil
}

func (d sourceDebt) qualifyStage(next *sourceDebt) error {
	switch {
	case d.name == "":
	case next.name == "":
		return ErrIdentityV1
	case d.name != next.name:
		return ErrBusyV1
	case d.held() && !next.held(), d.file != (filelock.IdentityV1{}) && d.file != next.file:
		return ErrIdentityV1
	default:
		next.binding, next.qualified, next.unlinkTried = d.binding, d.qualified, d.unlinkTried
		next.size = max(next.size, next.qualified)
	}
	return nil
}

// space caps staging credit at the smaller allocation observed around statfs.
func (o *SourceOwnerV1) space(r *sourceRoot, required uint64, stage sourceDebt) (bool, error) {
	credit := stage.diskCredit(r, required)
	var stat syscall.Statfs_t
	err := o.ops.statfs(int(r.pin.Fd()), &stat)
	overflow, available := bits.Mul64(uint64(stat.Bavail), sourceSpaceUnit(&stat))
	if err != nil || overflow != 0 || o.currentRoot() != nil {
		return false, ErrCapacityV1
	}
	full := required + o.limits.Overhead
	if available >= full {
		return false, nil
	}
	if full-available > min(credit, stage.diskCredit(r, required)) {
		return false, ErrCapacityV1
	}
	return true, nil
}

func (d sourceDebt) diskCredit(r *sourceRoot, required uint64) uint64 {
	if d.name == "" || d.shared {
		return 0
	}
	info, err := sourceEntryInfo(r, d.leaf, nil)
	if err != nil {
		return 0
	}
	return d.allocationCredit(info, required)
}

func (d sourceDebt) allocationCredit(info os.FileInfo, required uint64) uint64 {
	if d.file != filelock.FileIdentityV1(info) {
		return 0
	}
	return min(required, d.observed, sourceFileSize(info), singleLinkAllocatedBytes(info))
}

func singleLinkAllocatedBytes(info os.FileInfo) uint64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil || st.Nlink != 1 || st.Blocks <= 0 || uint64(st.Blocks) > math.MaxUint64/512 {
		return 0
	}
	return uint64(st.Blocks) * 512
}

func assurance(part SourcePartV1) error {
	var field [8]byte
	if err := readPartAt(part, field[:1], 0); err != nil {
		return ErrIntegrityV1
	}
	offset := uint64(1)
	if field[0] != 1 {
		if field[0] != 2 {
			return ErrIntegrityV1
		}
		for range 4 {
			next, err := assuranceField(part, offset)
			if err != nil {
				return err
			}
			offset = next
		}
	}
	if offset != part.Length {
		return ErrIntegrityV1
	}
	return nil
}

func assuranceField(part SourcePartV1, offset uint64) (uint64, error) {
	if part.Length-offset < 8 {
		return 0, ErrIntegrityV1
	}
	var field [8]byte
	if err := readPartAt(part, field[:], offset); err != nil {
		return 0, ErrIntegrityV1
	}
	length := binary.LittleEndian.Uint64(field[:])
	offset += 8
	if length == 0 || length > part.Length-offset {
		return 0, ErrIntegrityV1
	}
	return offset + length, nil
}

func stream(m SourceManifestV1, produce func(func(SourcePartV1) error) error, dst io.Writer, scratch []byte, start func() error, checkAssurance bool) error {
	var digest [sha256.Size]byte
	err := produce(func(part SourcePartV1) error {
		if start != nil {
			if err := start(); err != nil {
				return err
			}
			start = nil
		}
		if checkAssurance && part.Kind == OriginalAssuranceV1 {
			if err := assurance(part); err != nil {
				return err
			}
		}
		out := dst
		if part.Kind == AcquiredBlockBytesV1 {
			acquired := sha256.New()
			out = io.MultiWriter(dst, acquired)
			defer func() { copy(digest[:], acquired.Sum(nil)) }()
		}
		return copyPart(part, out, scratch)
	})
	if err != nil {
		return err
	}
	if digest != m.AcquiredDigest {
		return ErrIntegrityV1
	}
	return nil
}

func (o *SourceOwnerV1) qualify(f *os.File, m SourceManifestV1, size uint64, scratch []byte, expected *sourceIncarnation, shapeError error) (sourceIncarnation, error) {
	return o.qualifyWindows(f, m, size, scratch, expected, shapeError, nil)
}

// qualifyWindows binds the optional window digests to the bytes used for the footer check.
func (o *SourceOwnerV1) qualifyWindows(f *os.File, m SourceManifestV1, size uint64, scratch []byte, expected *sourceIncarnation, shapeError error, windows *sourceWindows) (sourceIncarnation, error) {
	var observed sourceIncarnation
	file, actual, err := o.sourceFileHeader(f, m, size, expected, shapeError)
	if err != nil {
		return observed, err
	}
	observed.file = file
	observed.size = size
	hash := sha256.New()
	_, _ = hash.Write(actual)
	var out io.Writer = hash
	if windows != nil {
		*windows = newSourceWindows(m)
		scratch = windows.scratch
		out = io.MultiWriter(hash, windows)
	}
	if err := stream(m, fileExporter(f, m, len(actual)), out, scratch, nil, windows == nil); err != nil {
		return observed, err
	}
	_, err = f.ReadAt(observed.footer[:], int64(min(size, math.MaxInt64))-sha256.Size)
	if err != nil || !bytes.Equal(hash.Sum(nil), observed.footer[:]) || expected != nil && observed.footer != expected.footer {
		return observed, ErrIntegrityV1
	}
	return observed, nil
}

func (o *SourceOwnerV1) sourceFileHeader(f *os.File, m SourceManifestV1, size uint64, expected *sourceIncarnation, shapeError error) (filelock.IdentityV1, []byte, error) {
	info, err := f.Stat()
	if err != nil || info.Size() != int64(min(size, math.MaxInt64)) {
		return filelock.IdentityV1{}, nil, shapeError
	}
	file := filelock.FileIdentityV1(info)
	if expected != nil {
		if file != expected.file {
			return file, nil, ErrIdentityV1
		}
		if size != expected.size {
			return file, nil, shapeError
		}
	}
	header := m.header(o.id)
	actual := make([]byte, len(header))
	if _, err = f.ReadAt(actual, 0); err != nil || !bytes.Equal(actual, header) {
		return file, nil, ErrIntegrityV1
	}
	return file, actual, nil
}

func fileExporter(f *os.File, m SourceManifestV1, header int) func(func(SourcePartV1) error) error {
	return func(visit func(SourcePartV1) error) error {
		offset := int64(header)
		for _, spec := range m.Parts {
			base := offset
			part := SourcePartV1{Kind: spec.Kind, Length: spec.Length, ReadAt: func(dst []byte, off int64) (int, error) { return f.ReadAt(dst, base+off) }}
			if err := visitPart(part, visit); err != nil {
				return err
			}
			offset += int64(min(spec.Length, math.MaxInt64))
		}
		return nil
	}
}

// WithCapturedSourceV1 qualifies retained bytes before visiting (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
func (o *SourceOwnerV1) WithCapturedSourceV1(account *mdbx.OperationAccount, m SourceManifestV1, visit func(SourcePartV1) error) error {
	return o.withFiles(account, m, false, func(r *sourceRoot, m SourceManifestV1, size uint64, used sourceUsage) error {
		name := used.read.name
		switch {
		case o.debt.name == name, o.pendingStage.name == name, o.observedStage == name, o.release != nil && o.release.name == name:
			return ErrBusyV1
		case visit == nil:
			return ErrIntegrityV1
		}
		expected := o.live[name]
		unobserved := ErrUnavailableV1
		if expected != nil {
			unobserved = ErrIntegrityV1
		}
		var reached []filelock.IdentityV1
		if used.read.localized {
			reached = []filelock.IdentityV1{used.read.target}
		}
		f, err := openSourceFile(r, name, unobserved, reached...)
		if err != nil {
			return err
		}
		defer f.Close()
		var windows sourceWindows
		if _, err := o.qualifyWindows(f, m, size, nil, expected, ErrIntegrityV1, &windows); err != nil {
			return err
		}
		return windows.deliver(f, m, len(m.header(o.id)), visit)
	})
}

type sourceWindows struct {
	hashes  [][sha256.Size]byte
	scratch []byte
	failure error
}

func newSourceWindows(m SourceManifestV1) sourceWindows {
	var count uint64
	for _, part := range m.Parts {
		count += sourceWindowCount(part.Length)
	}
	return sourceWindows{hashes: make([][sha256.Size]byte, 0, count), scratch: make([]byte, scratchBytes)}
}

func sourceWindowCount(length uint64) uint64 {
	return (length + scratchBytes - 1) / scratchBytes
}

func (w *sourceWindows) Write(b []byte) (int, error) {
	w.hashes = append(w.hashes, sha256.Sum256(b))
	return len(b), nil
}

func (w *sourceWindows) deliver(f *os.File, m SourceManifestV1, header int, visit func(SourcePartV1) error) error {
	var parts [6]SourcePartV1
	hashes, base := w.hashes, int64(header)
	for i, spec := range m.Parts {
		n := sourceWindowCount(spec.Length)
		section := io.NewSectionReader(f, base, int64(min(spec.Length, math.MaxInt64)))
		parts[i] = w.part(section, spec, hashes[:n])
		hashes, base = hashes[n:], base+section.Size()
		if spec.Kind == OriginalAssuranceV1 {
			if err := w.checkAssurance(parts[i]); err != nil {
				return err
			}
		}
	}
	for _, part := range parts[:len(m.Parts)] {
		err := visitPart(part, visit)
		if err := cmp.Or(w.failure, err); err != nil {
			return err
		}
	}
	return nil
}

func (w *sourceWindows) checkAssurance(part SourcePartV1) error {
	if part.Length > 1 && part.Length <= uint64(len(w.scratch)) {
		data := w.scratch[:part.Length]
		if err := readPartAt(part, data, 0); err != nil {
			return err
		}
		part.ReadAt = bytes.NewReader(data).ReadAt
	}
	return assurance(part)
}

func (w *sourceWindows) part(section *io.SectionReader, spec SourcePartSpecV1, hashes [][sha256.Size]byte) SourcePartV1 {
	return SourcePartV1{Kind: spec.Kind, Length: spec.Length, ReadAt: func(dst []byte, off int64) (int, error) {
		if w.failure != nil {
			return 0, w.failure
		}
		copied := 0
		for len(dst) > 0 {
			index := off / scratchBytes
			start := index * scratchBytes
			buf := w.scratch[:min(int64(scratchBytes), section.Size()-start)]
			n, err := section.ReadAt(buf, start)
			if n != len(buf) || err != nil || sha256.Sum256(buf) != hashes[index] {
				w.failure = ErrIntegrityV1
				return copied, w.failure
			}
			n = copy(dst, buf[off-start:])
			dst, off, copied = dst[n:], off+int64(n), copied+n
		}
		return copied, nil
	}}
}

func (o *SourceOwnerV1) withFiles(account *mdbx.OperationAccount, m SourceManifestV1, preparing bool, use func(*sourceRoot, SourceManifestV1, uint64, sourceUsage) error) error {
	return o.withManifest(account, m, preparing, func(r *sourceRoot, m SourceManifestV1, size uint64) error {
		witness := o.retireStageWitness(r)
		var read []sourceReadCensus
		if !preparing {
			read = []sourceReadCensus{{name: m.name(o.id), witness: witness}}
		}
		used, err := o.censusWithRead(r, false, read...)
		err = used.admissionError(err)
		adopt := preparing || used.stage.name == used.read.name
		if err == nil && adopt {
			err = o.adoptStage(r, used)
		}
		if err != nil || !adopt {
			o.rememberPublicStage(r, used, err == nil)
		}
		if err != nil {
			return err
		}
		return use(r, m, size, used)
	})
}

// rememberPublicStage records a public stage without claiming it.
func (o *SourceOwnerV1) rememberPublicStage(r *sourceRoot, used sourceUsage, funded bool) {
	stage := used.stage
	if !used.stageReached || stage.held() || o.debt.name != "" || o.observedStage != "" {
		return
	}
	if funded || o.stageWitnessFits(r, stage, used.entries, used.read) {
		o.retainStageWitness(r, stage)
	}
	o.observedStage = stage.name
}

func (o *SourceOwnerV1) retainStageWitness(r *sourceRoot, stage sourceDebt) {
	if o.retainStage(r, stage) == nil {
		if info, err := o.stage.File.Stat(); err != nil || sourceFileSize(info) != stage.observed {
			o.stage.Clear()
		}
	}
}

// stageWitnessFits charges the full bounded listing without changing the admission error.
func (o *SourceOwnerV1) stageWitnessFits(r *sourceRoot, stage sourceDebt, entries []os.DirEntry, read ...sourceReadCensus) bool {
	location, err := o.release.releaseLocation(r)
	if err != nil {
		return false
	}
	reserved := o.witnessUsage(stage, location, read)
	o.chargeBindings(&reserved)
	absentRelease := o.release
	listed := sourceListing(entries, read)
	for i := range listed.len() {
		name := listed.name(i)
		if !o.chargeWitnessEntry(r, name, &reserved) {
			return false
		}
		if name == location {
			absentRelease = nil
		}
	}
	_, err = o.finishCensus(reserved, absentRelease)
	return err == nil
}

// chargeWitnessEntry accounts the listed backing or checks its recognized custody name.
func (o *SourceOwnerV1) chargeWitnessEntry(r *sourceRoot, name string, used *sourceUsage) bool {
	switch {
	case sourceHexKey(name), name == releaseDetached:
		return o.censusEntry(r, name, used) == nil
	case name == used.stage.leaf, name == releaseScratch, o.release != nil && name == releaseFile:
		return true
	default:
		return !strings.HasPrefix(name, publicStagePrefix) && !strings.HasPrefix(name, heldStagePrefix)
	}
}

// witnessUsage measures the full stage funding independently of the ordered visit.
func (o *SourceOwnerV1) witnessUsage(stage sourceDebt, location string, read []sourceReadCensus) sourceUsage {
	stage.shared, stage.binding = false, nil
	used := o.stagingUsage(stage)
	used.completeCharge, used.releaseLeaf = true, location
	if len(read) != 0 {
		used.read.name = read[0].name
	}
	return used
}

// retireStageWitness closes the pin when the name no longer identifies its file.
func (o *SourceOwnerV1) retireStageWitness(r *sourceRoot) sourceDebt {
	pin := o.stage.File
	if pin == nil || o.debt.name != "" {
		return sourceDebt{}
	}
	pinned, pinErr := pin.Stat()
	named, err := r.Lstat(pin.Name())
	if pinErr != nil || errors.Is(err, os.ErrNotExist) || err == nil && !os.SameFile(pinned, named) {
		o.stage.Clear()
		return sourceDebt{}
	}
	return sourceDebt{name: sourceStageSpelling(pin.Name()), file: filelock.FileIdentityV1(pinned)}
}

func (o *SourceOwnerV1) adoptStage(r *sourceRoot, used sourceUsage) error {
	stage := used.stage
	if stage.name != "" && !stage.held() {
		if err := o.retainStage(r, stage); err != nil {
			return err
		}
		o.observedStage = ""
	} else if stage.held() {
		if o.debt.name == "" && o.pendingStage.name != "" {
			return ErrIdentityV1
		}
		o.stage.Clear()
	}
	o.debt = stage
	return nil
}

func (o *SourceOwnerV1) retainStage(r *sourceRoot, stage sourceDebt) error {
	if o.limits.Descriptors < 5 {
		return ErrCapacityV1
	}
	if o.stage.File != nil {
		info, _ := o.stage.File.Stat()
		if !sameSourceFile(info, stage.file) {
			return ErrIdentityV1
		}
		return nil
	}
	if o.observedStage != "" {
		return ErrIdentityV1
	}
	var err error
	o.stage.File, err = r.pinFile(stage.leaf, stage.file)
	return err
}

// reconcile returns disk charges only after unlink and parent synchronization both succeed.
func (o *SourceOwnerV1) reconcile(r *sourceRoot) error {
	if err := o.syncStageRemoval(r, false); err != nil || o.debt.name == "" {
		return err
	}
	if err := o.unlinkStage(r); err != nil {
		return err
	}
	return o.syncStageRemoval(r, false)
}

// syncStageRemoval releases quota after the directory sync succeeds.
func (o *SourceOwnerV1) syncStageRemoval(r *sourceRoot, handoff bool) error {
	if !handoff && o.pendingStage.name == "" {
		return nil
	}
	if err := o.ops.dirSync(r.pin); err != nil {
		return err
	}
	o.pendingStage = sourceDebt{}
	o.stage.ClearQuota()
	return nil
}

func (o *SourceOwnerV1) unlinkStage(r *sourceRoot) error {
	d := &o.debt
	if !d.held() {
		if err := o.claimStage(r, d, o.stage.File); err != nil {
			return err
		}
	}
	info, err := sourceEntryInfo(r, d.leaf, nil)
	if err != nil || d.file != (filelock.IdentityV1{}) && !sameSourceFile(info, d.file) {
		return cmp.Or(err, ErrIdentityV1)
	}
	d.size = max(d.qualified, sourceFileSize(info))
	return o.removeStage(r, d)
}

func (o *SourceOwnerV1) removeStage(r *sourceRoot, d *sourceDebt) error {
	if d.shared && d.binding == nil && o.stage.Quota == nil {
		pin, err := r.pinFile(d.leaf, d.file)
		if err != nil {
			return err
		}
		o.stage.Quota = pin
	}
	d.unlinkTried = true
	err := o.ops.remove(r.Root, d.leaf)
	return cmp.Or(err, o.observeStageRemoval(r))
}

// observeStageRemoval resolves an attempted unlink against the protected name.
func (o *SourceOwnerV1) observeStageRemoval(r *sourceRoot) error {
	d := &o.debt
	info, observed := r.Lstat(d.leaf)
	switch {
	case errors.Is(observed, os.ErrNotExist):
		o.pendingStage, o.debt = *d, sourceDebt{}
		return nil
	case sameSourceFile(info, d.file):
		o.observeRetainedStage(d.leaf, d.file)
	}
	return ErrIdentityV1
}

// observeRetainedStage clears the unlink attempt once its protected inode is seen.
func (o *SourceOwnerV1) observeRetainedStage(leaf string, id filelock.IdentityV1) {
	if o.debt.unlinkTried && leaf == o.debt.leaf && id == o.debt.file {
		o.debt.unlinkTried = false
		o.stage.ClearQuota()
	}
}

// claimStage verifies the pinned inode after renaming it.
func (o *SourceOwnerV1) claimStage(r *sourceRoot, d *sourceDebt, pin *os.File) error {
	if info, _ := sourceEntryInfo(r, d.leaf, nil); pin == nil || !sameSourceFile(info, d.file) {
		return ErrIdentityV1
	}
	held := heldStagePrefix + d.name
	if err := o.ops.namespace((*sourceRoot).renameExclusive, r, d.leaf, held); err != nil {
		return err
	}
	info, err := sourceEntryInfo(r, held, ErrIdentityV1)
	if err != nil || !sameSourceFile(info, d.file) {
		if o.ops.namespace((*sourceRoot).renameExclusive, r, held, d.leaf) == nil {
			_ = o.ops.dirSync(r.pin)
		}
		return cmp.Or(err, ErrIdentityV1)
	}
	d.leaf = held
	if pin == o.stage.File {
		o.stage.Clear()
	}
	return nil
}

// PrepareSourceV1 returns a handle after durable publication (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
func (o *SourceOwnerV1) PrepareSourceV1(account *mdbx.OperationAccount, m SourceManifestV1, producer SourceExporterV1) (prepared *PreparedSourceV1, err error) {
	err = o.withFiles(account, m, true, func(r *sourceRoot, m SourceManifestV1, size uint64, used sourceUsage) error {
		prepared, err = o.prepare(r, m, size, used, func(visit func(SourcePartV1) error) error {
			return o.export(account, m, producer, visit)
		})
		return err
	})
	return prepared, err
}

func (o *SourceOwnerV1) prepare(r *sourceRoot, m SourceManifestV1, size uint64, used sourceUsage, produce func(func(SourcePartV1) error) error) (*PreparedSourceV1, error) {
	name := m.name(o.id)
	if stage := cmp.Or(o.debt.name, o.observedStage, o.pendingStage.name); stage != "" && stage != name {
		return nil, ErrBusyV1
	}
	f, err := openSourceFile(r, name, nil)
	if err == nil {
		defer f.Close()
		return o.reuse(r, f, m, name, size, produce)
	}
	if !errors.Is(err, os.ErrNotExist) || o.live[name] != nil {
		return nil, ErrIntegrityV1
	}
	recheck, err := o.admitPublication(r, size, used)
	if err != nil {
		return nil, err
	}
	return o.publish(r, m, name, produce, size, recheck)
}

func (o *SourceOwnerV1) admitPublication(r *sourceRoot, size uint64, used sourceUsage) (bool, error) {
	if used.captureFiles >= o.limits.Files || size > o.limits.Bytes-used.captureBytes {
		return false, ErrCapacityV1
	}
	return o.space(r, size, used.stage)
}

func (o *SourceOwnerV1) prepared(r *sourceRoot, pin *os.File, m SourceManifestV1, name string, scratch []byte) (*PreparedSourceV1, error) {
	if err := o.syncStageRemoval(r, true); err != nil {
		return nil, err
	}
	token := o.live[name]
	info, err := r.Lstat(name)
	if err != nil || !sameSourceFile(info, token.file) || o.currentRoot() != nil {
		return nil, ErrIdentityV1
	}
	if err := o.finalCaptureName(r, pin, m, name, token, scratch); err != nil {
		return nil, err
	}
	if o.observedStage == name {
		o.observedStage = ""
		o.stage.Clear()
	}
	token.issued = true
	return &PreparedSourceV1{manifest: m, name: name, incarnation: token}, nil
}

func (o *SourceOwnerV1) finalCaptureName(r *sourceRoot, pin *os.File, m SourceManifestV1, name string, token *sourceIncarnation, scratch []byte) error {
	present, slotErr := o.captureSlot(r, name)
	if _, err := o.qualify(pin, m, token.size, scratch, token, ErrIntegrityV1); err != nil {
		return err
	}
	if slotErr != nil || !present {
		return cmp.Or(slotErr, ErrIdentityV1)
	}
	info, err := r.Lstat(name)
	if err != nil || !sameSourceFile(info, token.file) {
		return ErrIdentityV1
	}
	if sourceFileSize(info) != token.size {
		return ErrIntegrityV1
	}
	return o.currentRoot()
}

// captureSlot rejects same-key staging names regardless of hex case.
func (o *SourceOwnerV1) captureSlot(r *sourceRoot, name string) (bool, error) {
	entries, err := o.sourceEntries(r)
	if any(err) == any(ErrCapacityV1) {
		return false, err
	}
	if err != nil {
		return false, ErrIdentityV1
	}
	present := false
	for _, entry := range entries {
		leaf := entry.Name()
		present = present || leaf == name
		if samePublicStage(leaf, name) {
			return false, ErrIdentityV1
		}
	}
	if _, err := r.Lstat(publicStagePrefix + name); !errors.Is(err, os.ErrNotExist) {
		return false, ErrIdentityV1
	}
	return present, nil
}

func samePublicStage(leaf, name string) bool {
	key, public := strings.CutPrefix(leaf, publicStagePrefix)
	return public && sourceHexKey(key) && strings.EqualFold(name, key)
}

func (o *SourceOwnerV1) publish(r *sourceRoot, m SourceManifestV1, name string, produce func(func(SourcePartV1) error) error, size uint64, recheck bool) (_ *PreparedSourceV1, err error) {
	w := &sourceFileWriter{o: o}
	cleanup := true
	defer o.closeStagedWrite(r, w, &cleanup, &err)
	scratch := make([]byte, scratchBytes)
	observed, err := o.writeBundle(r, w, m, name, produce, size, recheck, scratch)
	if err != nil {
		return nil, err
	}
	o.debt.size, o.debt.observed, o.debt.qualified = observed.size, observed.size, observed.size
	pin, err := o.finishPinned(r, o.debt.leaf, w.file, observed.file)
	if err != nil {
		return nil, err
	}
	defer pin.Close()
	if _, err := o.captureSlot(r, name); err != nil {
		cleanup = false
		return nil, err
	}
	if info, _ := r.Lstat(o.debt.leaf); !sameSourceFile(info, observed.file) {
		cleanup = false
		return nil, ErrIdentityV1
	}
	cleanup = false
	visibility, err := o.linkCapture(r, name, &observed)
	cleanup = visibility == sourceNotVisible
	if err != nil {
		return nil, err
	}
	if err := o.unlinkStage(r); err != nil {
		return nil, err
	}
	return o.prepared(r, pin, m, name, scratch)
}

func (o *SourceOwnerV1) closeStagedWrite(r *sourceRoot, w *sourceFileWriter, cleanup *bool, result *error) {
	if w.file == nil {
		return
	}
	_ = w.file.Close()
	if *cleanup {
		if err := o.reconcile(r); err != nil {
			*result = errors.Join(*result, err)
		}
	}
}

func (o *SourceOwnerV1) finishFile(f *os.File) error {
	if err := o.ops.fileSync(f); err != nil {
		return err
	}
	return o.ops.close(f)
}

// finishPinned pins the inode before closing the writer.
func (o *SourceOwnerV1) finishPinned(r *sourceRoot, name string, f *os.File, id filelock.IdentityV1) (*os.File, error) {
	pin, pinErr := r.pinFile(name, id)
	err := cmp.Or(o.finishFile(f), pinErr)
	if err != nil {
		_ = pin.Close()
		return nil, err
	}
	return pin, nil
}

// writeBundle verifies the file against the producer digest.
func (o *SourceOwnerV1) writeBundle(r *sourceRoot, w *sourceFileWriter, m SourceManifestV1, name string, produce func(func(SourcePartV1) error) error, size uint64, recheck bool, scratch []byte) (sourceIncarnation, error) {
	hash := sha256.New()
	out := io.MultiWriter(w, hash)
	start := func() error {
		if err := o.reconcile(r); err != nil {
			return err
		}
		if recheck {
			if _, err := o.space(r, size, sourceDebt{}); err != nil {
				return err
			}
		}
		leaf := heldStagePrefix + name
		f, err := r.OpenFile(leaf, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		w.file = f
		o.debt = sourceDebt{name: name, leaf: leaf, size: size}
		info, err := f.Stat()
		if err != nil {
			return err
		}
		o.debt.file = filelock.FileIdentityV1(info)
		o.debt.size = sourceFileSize(info)
		_, err = out.Write(m.header(o.id))
		return cmp.Or(err, o.ops.chmod(f, 0o600))
	}
	if err := stream(m, produce, out, scratch, start, true); err != nil {
		return sourceIncarnation{}, err
	}
	expected := sourceIncarnation{file: o.debt.file, size: size, footer: [sha256.Size]byte(hash.Sum(nil))}
	if _, err := w.Write(expected.footer[:]); err != nil {
		return sourceIncarnation{}, err
	}
	return o.qualify(w.file, m, size, scratch, &expected, ErrIntegrityV1)
}

type sourceFileWriter struct {
	o    *SourceOwnerV1
	file *os.File
}

func (w sourceFileWriter) Write(data []byte) (int, error) {
	n, err := w.o.ops.write(w.file, data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

type sourceVisibility uint8

const (
	sourceNotVisible sourceVisibility = iota
	sourceVisible
	sourceIndeterminate
)

// linkCapture records the inode before attempting the link.
func (o *SourceOwnerV1) linkCapture(r *sourceRoot, name string, observed *sourceIncarnation) (sourceVisibility, error) {
	observed.uncertain = true
	o.live[name] = observed
	o.debt.binding, o.debt.shared = observed, true
	err := o.ops.namespace((*sourceRoot).Link, r, o.debt.leaf, name)
	visibility, out := observeLink(r, name, observed.file, err)
	switch {
	case visibility == sourceNotVisible:
		o.forgetPublication(name, observed)
	case err == nil || visibility == sourceVisible:
		observed.uncertain = false
	}
	return visibility, out
}

func observeLink(r *sourceRoot, name string, id filelock.IdentityV1, err error) (sourceVisibility, error) {
	disagrees := sourceIndeterminate
	if err != nil {
		disagrees = sourceNotVisible
	}
	info, statErr := r.Lstat(name)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		return disagrees, cmp.Or(err, ErrIntegrityV1)
	case statErr != nil:
		return sourceIndeterminate, cmp.Or(err, statErr)
	case !sameSourceFile(info, id):
		if errors.Is(err, os.ErrExist) {
			err = ErrIntegrityV1
		}
		return disagrees, cmp.Or(err, ErrIdentityV1)
	}
	return sourceVisible, err
}

type compareSourceWriter struct {
	file    *os.File
	offset  int64
	scratch []byte
	digest  hash.Hash
}

func (w *compareSourceWriter) Write(data []byte) (int, error) {
	scratch := w.scratch[:len(data)]
	if _, err := w.file.ReadAt(scratch, w.offset); err != nil || !bytes.Equal(data, scratch) {
		return 0, ErrIntegrityV1
	}
	w.offset += int64(len(data))
	return w.digest.Write(data)
}

func (o *SourceOwnerV1) reuse(r *sourceRoot, f *os.File, m SourceManifestV1, name string, size uint64, produce func(func(SourcePartV1) error) error) (*PreparedSourceV1, error) {
	scratch := make([]byte, scratchBytes)
	observed, err := o.qualify(f, m, size, scratch, o.live[name], ErrIntegrityV1)
	if err != nil {
		return nil, err
	}
	o.live[name] = cmp.Or(o.live[name], &observed)
	if o.debt.name == name && o.debt.file == observed.file {
		o.debt.binding = o.live[name]
	}
	if err := o.compareBundle(r, f, m, observed, produce, scratch); err != nil {
		return nil, err
	}
	pin, err := o.finishPinned(r, name, f, observed.file)
	if err != nil {
		return nil, err
	}
	defer pin.Close()
	return o.prepared(r, pin, m, name, scratch)
}

// compareBundle checks the file again after the producer returns.
func (o *SourceOwnerV1) compareBundle(r *sourceRoot, f *os.File, m SourceManifestV1, observed sourceIncarnation, produce func(func(SourcePartV1) error) error, scratch []byte) error {
	header := m.header(o.id)
	compared := sha256.New()
	_, _ = compared.Write(header)
	w := &compareSourceWriter{file: f, offset: int64(len(header)), scratch: scratch[scratchBytes/2:], digest: compared}
	start := func() error { return o.reconcile(r) }
	if err := stream(m, produce, w, scratch[:scratchBytes/2], start, true); err != nil {
		return err
	}
	if [sha256.Size]byte(compared.Sum(nil)) != observed.footer {
		return ErrIntegrityV1
	}
	_, err := o.qualify(f, m, observed.size, scratch, &observed, ErrIntegrityV1)
	return err
}
