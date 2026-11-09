package policycontrol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

var crossingStages = []stage{stageCreate, stageWrite, stageFileSync, stageRename, stageDirSync, stageClose}

// H1: a crash at every crossing stage reopens to exactly the predecessor or the successor image, never a third image or partial rows.
func TestCrashPointsReopenOldOrNew(t *testing.T) {
	id := testIdentity(1)
	for _, at := range append(crossingStages, stageAck) {
		dir, s := seedStore(t, ownerlessState(id, 40))
		old := fileBytes(t, dir)
		s.fault = failWith(errInjectedCrash, at)
		r, _ := batchTx(t, s, 0, 128, "b").Commit()
		if r.Truth != UNKNOWN {
			t.Fatalf("stage %d: crash returned %v", at, r.Truth)
		}
		successor := s.pending.new
		must(t, s.Close())
		got := fileBytes(t, dir)
		reopened := mustView(t, mustOpen(t, dir, id))
		wantImage, wantSeq := old, uint64(40)
		if at > stageRename {
			wantImage, wantSeq = successor, 41
		}
		if !bytes.Equal(got, wantImage) || reopened.Sequence != wantSeq {
			t.Fatalf("stage %d: reopened at %d with a third image", at, reopened.Sequence)
		}
	}
}

// H1: a non-crash failure at each stage is OLD before the rename, UNKNOWN after it, and a lost acknowledgement resolves by Recover.
func TestFailurePointsClassification(t *testing.T) {
	want := map[stage]Truth{stageCreate: OLD, stageWrite: OLD, stageFileSync: OLD, stageRename: OLD, stageDirSync: UNKNOWN, stageClose: UNKNOWN, stageAck: UNKNOWN}
	for at, truth := range want {
		_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
		s.fault = failAt(at)
		r, err := controlTx(t, s, "a").Commit()
		if r.Truth != truth || err == nil {
			t.Fatalf("stage %d: %v %v, want %v", at, r.Truth, err, truth)
		}
		s.fault = nil
		rec, _ := s.Recover()
		wantRec := map[Truth]Truth{OLD: 0, UNKNOWN: UNKNOWN}[truth] // OLD leaves nothing pending to classify
		if at == stageAck {
			wantRec = NEW
		}
		if rec.Truth != wantRec {
			t.Fatalf("stage %d: recover %v, want %v", at, rec.Truth, wantRec)
		}
	}
}

// H1, A1: a crash while creating leaves either no P (missing control, Create may run again) or exactly the initial image.
func TestCreateCrashPoints(t *testing.T) {
	id := testIdentity(1)
	proof := NewInstallationProof{Identity: id}
	for _, at := range crossingStages {
		dir := storeDir(t)
		h := productionHooks
		h.fault = failWith(errInjectedCrash, at)
		if s, err := start(dir, id, &proof, h); s != nil || !errors.Is(err, errInjectedCrash) {
			t.Fatalf("stage %d: create %v", at, err)
		}
		s, err := Open(dir, id)
		if at <= stageRename {
			if !errors.Is(err, ErrMissingControl) {
				t.Fatalf("stage %d: open %v", at, err)
			}
			s = mustCreate(t, dir, id)
		} else if err != nil {
			t.Fatalf("stage %d: open %v", at, err)
		}
		if v := mustView(t, s); v.Sequence != 0 || v.Receipt != nil {
			t.Fatalf("stage %d: view %+v", at, v)
		}
		_ = s.Close()
	}
}

const childEnv = "RUBIN_POLICYCONTROL_CHILD"

// TestChildContender is the H2 child process body; it is inert unless exec'd.
func TestChildContender(t *testing.T) {
	arg := os.Getenv(childEnv)
	if arg == "" {
		return
	}
	dir, idHex, _ := bytes.Cut([]byte(arg), []byte{'|'})
	raw, _ := hex.DecodeString(string(idHex))
	var id Identity
	copy(id.InstallationID[:], raw[0:32])
	copy(id.ChainID[:], raw[32:64])
	copy(id.GenesisHash[:], raw[64:96])
	id.Profile = ProfileV1
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		s, err := Open(string(dir), id)
		switch {
		case err == nil:
			fmt.Println("open")
			_ = s.Close()
		case errors.Is(err, ErrBusy):
			fmt.Println("busy")
		default:
			fmt.Println("error", err)
		}
	}
}

// H2, X4: a second process contends on the directory inode after every one of many commits (each atomically replacing the P file); goroutines race Begin with exactly one winner and no lost update.
func TestWriterExclusionAcrossProcessesAndGoroutines(t *testing.T) {
	id := testIdentity(1)
	dir := storeDir(t)
	must(t, mustCreate(t, dir, id).Close())
	s := mustOpen(t, dir, id)
	idHex := hex.EncodeToString(append(append(id.InstallationID[:], id.ChainID[:]...), id.GenesisHash[:]...))
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestChildContender$", "-test.count=1")
	cmd.Env = append(os.Environ(), childEnv+"="+dir+"|"+idHex)
	stdin, err := cmd.StdinPipe()
	must(t, err)
	stdout, err := cmd.StdoutPipe()
	must(t, err)
	must(t, cmd.Start())
	out := bufio.NewReader(stdout)
	ask := func() string {
		if _, err := io.WriteString(stdin, "try\n"); err != nil {
			t.Fatal(err)
		}
		line, err := out.ReadString('\n')
		if err != nil {
			t.Fatalf("child: %v", err)
		}
		return line
	}
	const rounds = 64
	for i := 1; i <= rounds; i++ {
		var wg sync.WaitGroup
		txs := make(chan *Tx, 2)
		busy := make(chan error, 2)
		for g := 0; g < 2; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if tx, err := s.Begin(); err == nil {
					txs <- tx
				} else {
					busy <- err
				}
			}()
		}
		wg.Wait()
		if len(txs) != 1 || len(busy) != 1 || !errors.Is(<-busy, ErrBusy) {
			t.Fatalf("round %d: %d writers", i, len(txs))
		}
		tx := <-txs
		tx.Ownerless()
		tx.Operation(ClassControl, 0)
		put(t, tx, KindAudit, fmt.Sprintf("r%03d", i), "v")
		mustCommit(t, tx, NEW, uint64(i))
		if got := ask(); got != "busy\n" {
			t.Fatalf("round %d: child got %q while the writer is held", i, got)
		}
	}
	if rows, _ := s.Membership(); len(rows) != rounds {
		t.Fatalf("lost update: %d rows", len(rows))
	}
	must(t, s.Close())
	if got := ask(); got != "open\n" {
		t.Fatalf("child after release: %q", got)
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child: %v", err)
	}
}

// H1: the crossing syncs the scratch before the rename and the directory after it, and the old P stays in place until the rename.
func TestCrossingStageOrder(t *testing.T) {
	dir, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	old := fileBytes(t, dir)
	var seen []stage
	s.fault = func(st stage) error {
		if seen = append(seen, st); st <= stageRename && !bytes.Equal(fileBytes(t, dir), old) {
			t.Errorf("stage %d: old P changed before the rename", st)
		}
		return nil
	}
	mustCommit(t, controlTx(t, s, "a"), NEW, 41)
	want := []stage{stageCreate, stageWrite, stageFileSync, stageRename, stageDirSync, stageClose, stageAck}
	if !slices.Equal(seen, want) {
		t.Fatalf("crossing stages %v, want %v", seen, want)
	}
}

// recordFS wraps realFS, records each call (marking the control path as P) and fails the call named fail.
func recordFS(calls *[]string, dir, fail string) fsOps {
	do := func(op, path string, real func() error) error {
		if path == filepath.Join(dir, controlFile) {
			op += "(P)"
		}
		if *calls = append(*calls, op); op == fail {
			return errors.New("injected " + op)
		}
		return real()
	}
	r := realFS
	return fsOps{
		remove:  func(p string) error { return do("remove", p, func() error { return r.remove(p) }) },
		syncDir: func(d string) error { return do("syncDir", "", func() error { return r.syncDir(d) }) },
		write:   func(f *os.File, b []byte) error { return do("write", "", func() error { return r.write(f, b) }) },
		sync:    func(f *os.File) error { return do("sync", "", func() error { return r.sync(f) }) },
		close:   func(f *os.File) error { return do("close", "", func() error { return r.close(f) }) },
		rename:  func(a, b string) error { return do("rename", b, func() error { return r.rename(a, b) }) },
		open: func(p string) (f *os.File, err error) {
			err = do("open", p, func() error { f, err = r.open(p); return err })
			return f, err
		},
	}
}

// H1: Create and a commit sync the scratch, rename it over P and sync the directory, in that order, never remove P, and propagate each failure into its stage's OLD/UNKNOWN classification.
func TestCrossingFileSystemCalls(t *testing.T) {
	id, want := testIdentity(1), "[remove open write sync rename(P) syncDir close]"
	var calls []string
	dir, h := storeDir(t), productionHooks
	h.ops = recordFS(&calls, dir, "")
	if s, err := start(dir, id, &NewInstallationProof{Identity: id}, h); err != nil || fmt.Sprint(calls) != want[:len(want)-1]+" sync syncDir]" {
		t.Fatalf("Create calls %v: %v", calls, err)
	} else {
		_ = s.Close()
	}
	for fail, truth := range map[string]Truth{"": NEW, "sync": OLD, "rename(P)": OLD, "syncDir": UNKNOWN} {
		dir, s := seedStore(t, ownerlessState(id, 40))
		calls, s.ops = nil, recordFS(&calls, dir, fail)
		if r, _ := controlTx(t, s, "a").Commit(); r.Truth != truth || bytes.Contains([]byte(fmt.Sprint(calls)), []byte("remove(P)")) || (fail == "" && fmt.Sprint(calls) != want) {
			t.Fatalf("fail %q: %v with calls %v, want %v", fail, r.Truth, calls, truth)
		}
	}
	// A7, X7: readback establishes durability before classifying; a failed synchronization stays UNKNOWN.
	for fail, truth := range map[string]Truth{"": NEW, "sync": UNKNOWN, "syncDir": UNKNOWN} {
		dir, s := seedStore(t, ownerlessState(id, 40))
		s.fault = failAt(stageAck)
		wantResult(t, func() Result { r, _ := controlTx(t, s, "a").Commit(); return r }(), UNKNOWN, 0)
		s.fault, calls, s.ops = nil, nil, recordFS(&calls, dir, fail)
		if r, _ := s.Recover(); r.Truth != truth || !slices.Contains(calls, "syncDir") || !slices.Contains(calls, "sync") {
			t.Fatalf("readback fail %q: %v with calls %v, want %v", fail, r.Truth, calls, truth)
		}
	}
}
