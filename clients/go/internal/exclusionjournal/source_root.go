package exclusionjournal

import (
	"errors"
	"io"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
	"golang.org/x/sys/unix"
)

type sourceRoot struct {
	*os.Root
	pin *os.File
}

// renameExclusive transfers one leaf without replacing its destination.
func (r *sourceRoot) renameExclusive(from, to string) error {
	return renameSourceAt(int(r.pin.Fd()), from, to)
}

// pinFile holds the expected regular incarnation through a namespace operation.
func (r *sourceRoot) pinFile(name string, id filelock.IdentityV1) (*os.File, error) {
	f, err := openSourceFile(r, name, ErrIdentityV1)
	if err != nil {
		return nil, ErrIdentityV1
	}
	info, err := f.Stat()
	if err != nil || !sameSourceFile(info, id) {
		_ = f.Close()
		return nil, ErrIdentityV1
	}
	return f, nil
}

const sourceInitDirectory = "." + sourceDirectory + ".init"

func (o *SourceOwnerV1) withRoot(open func(*os.Root) (*os.Root, error), use func(*sourceRoot) error) error {
	parent, err := o.parentRoot()
	if err != nil {
		return err
	}
	r, err := open(parent)
	_ = parent.Close()
	if err != nil {
		return err
	}
	defer r.Close()
	pin, err := r.Open(".")
	if err != nil {
		return ErrUnavailableV1
	}
	defer pin.Close()
	root := &sourceRoot{Root: r, pin: pin}
	held, _ := pin.Stat()
	if !os.SameFile(o.info, held) || held.Mode() != o.info.Mode() {
		return ErrIdentityV1
	}
	return use(root)
}

func (o *SourceOwnerV1) parentRoot() (*os.Root, error) {
	parent, err := os.OpenRoot(o.dir)
	if err != nil {
		return nil, ErrIdentityV1
	}
	info, err := parent.Stat(".")
	if err != nil || o.parent != filelock.FileIdentityV1(info) {
		_ = parent.Close()
		return nil, ErrIdentityV1
	}
	return parent, nil
}

func (o *SourceOwnerV1) currentRoot() error {
	parent, err := o.parentRoot()
	if err != nil {
		return err
	}
	defer parent.Close()
	leaf, _ := sourceRootInfo(parent)
	if !os.SameFile(leaf, o.info) {
		return ErrIdentityV1
	}
	current, err := os.Lstat(o.dir)
	if err != nil || o.parent != filelock.FileIdentityV1(current) {
		return ErrIdentityV1
	}
	return nil
}

func (o *SourceOwnerV1) createSourceRoot(parent *os.Root) (*os.Root, error) {
	leaf, err := sourceRootInfo(parent)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ErrIdentityV1
	}
	f, err := parent.Open(".")
	if err != nil {
		return nil, err
	}
	var pin *os.File
	if leaf == nil {
		pin, leaf, err = publishSourceRoot(int(f.Fd()))
	}
	defer pin.Close()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return nil, err
	}
	o.info = leaf
	return o.bindRoot(parent)
}

// publishSourceRoot syncs and publishes the empty directory and returns its open pin.
func publishSourceRoot(parent int) (*os.File, os.FileInfo, error) {
	pin, err := openSourceInit(parent)
	if err != nil {
		return nil, nil, err
	}
	info, err := pin.Stat()
	if err != nil || info.Mode() != os.ModeDir|0o700 {
		return pin, nil, ErrIdentityV1
	}
	if _, err := pin.ReadDir(1); err != io.EOF {
		return pin, nil, ErrIdentityV1
	}
	if err := pin.Sync(); err != nil {
		return pin, nil, err
	}
	return pin, info, renameSourceAt(parent, sourceInitDirectory, sourceDirectory)
}

// openSourceInit replaces only an empty directory at the reserved name and pins the replacement.
func openSourceInit(parent int) (*os.File, error) {
	if err := unix.Unlinkat(parent, sourceInitDirectory, unix.AT_REMOVEDIR); err != nil && err != unix.ENOENT {
		return nil, ErrIdentityV1
	}
	if err := unix.Mkdirat(parent, sourceInitDirectory, 0o700); err != nil {
		return nil, err
	}
	if err := chmodSourceInit(parent); err != nil {
		return nil, err
	}
	return openSourceAt(parent, sourceInitDirectory, unix.O_DIRECTORY)
}

func (o *SourceOwnerV1) bindRoot(parent *os.Root) (*os.Root, error) {
	leaf, _ := sourceRootInfo(parent)
	if !os.SameFile(o.info, leaf) {
		return nil, ErrIdentityV1
	}
	r, err := parent.OpenRoot(sourceDirectory)
	if err != nil {
		return nil, ErrUnavailableV1
	}
	return r, nil
}

func sourceRootInfo(parent *os.Root) (os.FileInfo, error) {
	info, err := parent.Lstat(sourceDirectory)
	if err == nil && info.Mode() != os.ModeDir|0o700 {
		return nil, ErrIdentityV1
	}
	return info, err
}

func (o *SourceOwnerV1) openSourceRoot() error {
	return o.withRoot(o.createSourceRoot, o.recoverSourceRoot)
}

// recoverSourceRoot admits the existing namespace before restoring protected staging.
func (o *SourceOwnerV1) recoverSourceRoot(r *sourceRoot) error {
	if err := o.syncBoundRoot(r); err != nil {
		return err
	}
	if err := o.openRelease(r); err != nil {
		return err
	}
	used, err := o.census(r)
	if err != nil {
		return err
	}
	if err := o.qualifyReopenedRelease(r); err != nil {
		return err
	}
	if used.stage.held() {
		return o.restoreHeldStage(r, used.stage)
	}
	return o.adoptStage(r, used)
}

// qualifyReopenedRelease checks the existing release intent against admitted backing.
func (o *SourceOwnerV1) qualifyReopenedRelease(r *sourceRoot) error {
	if o.release == nil {
		return nil
	}
	if !o.manifestFits(o.release.manifest, o.release.size) {
		return ErrCapacityV1
	}
	_, err := o.releaseBacking(r, o.release, make([]byte, scratchBytes))
	return err
}

// restoreHeldStage retains the same staging incarnation across the exclusive move.
func (o *SourceOwnerV1) restoreHeldStage(r *sourceRoot, stage sourceDebt) error {
	if err := o.retainStage(r, stage); err != nil {
		return err
	}
	public := publicStagePrefix + stage.name
	if err := o.ops.namespace((*sourceRoot).renameExclusive, r, stage.leaf, public); err != nil {
		return err
	}
	if err := o.syncBoundRoot(r); err != nil {
		return err
	}
	info, err := r.Lstat(public)
	if err != nil || !sameSourceFile(info, stage.file) {
		return ErrIdentityV1
	}
	stage.leaf = public
	o.debt = stage
	return nil
}

// syncBoundRoot makes namespace changes durable and verifies current root reachability.
func (o *SourceOwnerV1) syncBoundRoot(r *sourceRoot) error {
	if err := o.ops.dirSync(r.pin); err != nil {
		return err
	}
	return o.currentRoot()
}
