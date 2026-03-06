package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var (
	readFileByPathFn  = readFileByPath
	writeFileAtomicFn = writeFileAtomic
)

const (
	blockStoreIndexVersion = 1
	blockStoreDirName      = "blockstore"
)

type BlockStore struct {
	rootPath   string
	indexPath  string
	blocksDir  string
	headersDir string
	undoDir    string
	index      blockStoreIndexDisk
}

type blockStoreIndexDisk struct {
	Canonical []string `json:"canonical"`
	Version   uint32   `json:"version"`
}

func BlockStorePath(dataDir string) string {
	return filepath.Join(dataDir, blockStoreDirName)
}

func OpenBlockStore(rootPath string) (*BlockStore, error) {
	indexPath := filepath.Join(rootPath, "index.json")
	blocksDir := filepath.Join(rootPath, "blocks")
	headersDir := filepath.Join(rootPath, "headers")
	undoDir := filepath.Join(rootPath, "undo")

	if err := os.MkdirAll(blocksDir, 0o750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(headersDir, 0o750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(undoDir, 0o750); err != nil {
		return nil, err
	}

	index, err := loadBlockStoreIndex(indexPath)
	if err != nil {
		return nil, err
	}

	bs := &BlockStore{
		rootPath:   rootPath,
		indexPath:  indexPath,
		blocksDir:  blocksDir,
		headersDir: headersDir,
		undoDir:    undoDir,
		index:      index,
	}
	return bs, nil
}

func (bs *BlockStore) PutBlock(height uint64, blockHash [32]byte, headerBytes []byte, blockBytes []byte) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	if err := validateBlockHeaderHash(headerBytes, blockHash); err != nil {
		return err
	}
	if err := bs.persistBlockBytes(blockHash, headerBytes, blockBytes); err != nil {
		return err
	}
	return bs.SetCanonicalTip(height, blockHash)
}

func (bs *BlockStore) SetCanonicalTip(height uint64, blockHash [32]byte) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	nextCanonical, changed, err := updatedCanonicalHashes(bs.index.Canonical, height, blockHash)
	if err != nil {
		return err
	}
	if !changed {
		return saveBlockStoreIndex(bs.indexPath, bs.index)
	}
	bs.index.Canonical = nextCanonical
	return saveBlockStoreIndex(bs.indexPath, bs.index)
}

func (bs *BlockStore) RewindToHeight(height uint64) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	if len(bs.index.Canonical) == 0 {
		return nil
	}
	if height >= uint64(len(bs.index.Canonical)) {
		return fmt.Errorf("rewind height out of range: %d", height)
	}
	return bs.TruncateCanonical(height + 1)
}

func (bs *BlockStore) TruncateCanonical(count uint64) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	if count > uint64(len(bs.index.Canonical)) {
		return fmt.Errorf("truncate count out of range: %d", count)
	}
	bs.index.Canonical = append([]string(nil), bs.index.Canonical[:count]...)
	return saveBlockStoreIndex(bs.indexPath, bs.index)
}

func (bs *BlockStore) CanonicalHash(height uint64) ([32]byte, bool, error) {
	var out [32]byte
	if bs == nil {
		return out, false, errors.New("nil blockstore")
	}
	if height >= uint64(len(bs.index.Canonical)) {
		return out, false, nil
	}
	hash, err := parseHex32("canonical hash", bs.index.Canonical[height])
	if err != nil {
		return out, false, err
	}
	return hash, true, nil
}

func (bs *BlockStore) Tip() (uint64, [32]byte, bool, error) {
	var out [32]byte
	if bs == nil {
		return 0, out, false, errors.New("nil blockstore")
	}
	height, ok := canonicalTipHeight(bs.index.Canonical)
	if !ok {
		return 0, out, false, nil
	}
	hash, err := parseHex32("tip hash", bs.index.Canonical[height])
	if err != nil {
		return 0, out, false, err
	}
	return height, hash, true, nil
}

func (bs *BlockStore) GetBlockByHash(blockHash [32]byte) ([]byte, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	return readFileFromDir(bs.blocksDir, hex.EncodeToString(blockHash[:])+".bin")
}

func (bs *BlockStore) GetHeaderByHash(blockHash [32]byte) ([]byte, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	return readFileFromDir(bs.headersDir, hex.EncodeToString(blockHash[:])+".bin")
}

func (bs *BlockStore) PutUndo(blockHash [32]byte, undo *BlockUndo) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	raw, err := marshalBlockUndo(undo)
	if err != nil {
		return err
	}
	return writeFileIfAbsent(filepath.Join(bs.undoDir, hex.EncodeToString(blockHash[:])+".json"), raw)
}

func (bs *BlockStore) GetUndo(blockHash [32]byte) (*BlockUndo, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	raw, err := readFileFromDir(bs.undoDir, hex.EncodeToString(blockHash[:])+".json")
	if err != nil {
		return nil, err
	}
	return unmarshalBlockUndo(raw)
}

func loadBlockStoreIndex(path string) (blockStoreIndexDisk, error) {
	raw, err := readFileByPath(path)
	if errors.Is(err, os.ErrNotExist) {
		return blockStoreIndexDisk{
			Version:   blockStoreIndexVersion,
			Canonical: []string{},
		}, nil
	}
	if err != nil {
		return blockStoreIndexDisk{}, err
	}
	var index blockStoreIndexDisk
	if err := json.Unmarshal(raw, &index); err != nil {
		return blockStoreIndexDisk{}, fmt.Errorf("decode blockstore index: %w", err)
	}
	if index.Version != blockStoreIndexVersion {
		return blockStoreIndexDisk{}, fmt.Errorf("unsupported blockstore index version: %d", index.Version)
	}
	for i, hashHex := range index.Canonical {
		if _, err := parseHex32(fmt.Sprintf("canonical[%d]", i), hashHex); err != nil {
			return blockStoreIndexDisk{}, err
		}
	}
	return index, nil
}

func saveBlockStoreIndex(path string, index blockStoreIndexDisk) error {
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeFileAtomicFn(path, raw, 0o600)
}

func validateBlockHeaderHash(headerBytes []byte, blockHash [32]byte) error {
	if len(headerBytes) != consensus.BLOCK_HEADER_BYTES {
		return fmt.Errorf("invalid header length: %d", len(headerBytes))
	}
	computedHash, err := consensus.BlockHash(headerBytes)
	if err != nil {
		return err
	}
	if computedHash != blockHash {
		return errors.New("header hash mismatch")
	}
	return nil
}

func (bs *BlockStore) persistBlockBytes(blockHash [32]byte, headerBytes []byte, blockBytes []byte) error {
	hashHex := hex.EncodeToString(blockHash[:])
	if err := writeFileIfAbsent(filepath.Join(bs.blocksDir, hashHex+".bin"), blockBytes); err != nil {
		return err
	}
	return writeFileIfAbsent(filepath.Join(bs.headersDir, hashHex+".bin"), headerBytes)
}

func updatedCanonicalHashes(canonical []string, height uint64, blockHash [32]byte) ([]string, bool, error) {
	hashHex := hex.EncodeToString(blockHash[:])
	currentLen := uint64(len(canonical))
	switch {
	case height > currentLen:
		return nil, false, fmt.Errorf("height gap: got %d, expected <= %d", height, currentLen)
	case height == currentLen:
		return append(canonical, hashHex), true, nil
	case canonical[height] == hashHex:
		return canonical, false, nil
	default:
		nextCanonical := append([]string(nil), canonical[:height]...)
		nextCanonical = append(nextCanonical, hashHex)
		return nextCanonical, true, nil
	}
}

func canonicalTipHeight(canonical []string) (uint64, bool) {
	if len(canonical) == 0 {
		return 0, false
	}
	return uint64(len(canonical) - 1), true
}

func writeFileIfAbsent(path string, content []byte) error {
	existing, err := readFileByPathFn(path)
	if err == nil {
		if !bytes.Equal(existing, content) {
			return fmt.Errorf("file already exists with different content: %s", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeFileAtomicFn(path, content, 0o600); err != nil {
		return err
	}
	existing, err = readFileByPathFn(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(existing, content) {
		return fmt.Errorf("written content mismatch: %s", path)
	}
	return nil
}
