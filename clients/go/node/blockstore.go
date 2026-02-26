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

const (
	blockStoreIndexVersion = 1
	blockStoreDirName      = "blockstore"
)

type BlockStore struct {
	rootPath   string
	indexPath  string
	blocksDir  string
	headersDir string
	index      blockStoreIndexDisk
}

type blockStoreIndexDisk struct {
	Version   uint32   `json:"version"`
	Canonical []string `json:"canonical"`
}

func BlockStorePath(dataDir string) string {
	return filepath.Join(dataDir, blockStoreDirName)
}

func OpenBlockStore(rootPath string) (*BlockStore, error) {
	indexPath := filepath.Join(rootPath, "index.json")
	blocksDir := filepath.Join(rootPath, "blocks")
	headersDir := filepath.Join(rootPath, "headers")

	if err := os.MkdirAll(blocksDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(headersDir, 0o755); err != nil {
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
		index:      index,
	}
	return bs, nil
}

func (bs *BlockStore) PutBlock(height uint64, blockHash [32]byte, headerBytes []byte, blockBytes []byte) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
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

	hashHex := hex.EncodeToString(blockHash[:])
	if err := writeFileIfAbsent(filepath.Join(bs.blocksDir, hashHex+".bin"), blockBytes); err != nil {
		return err
	}
	if err := writeFileIfAbsent(filepath.Join(bs.headersDir, hashHex+".bin"), headerBytes); err != nil {
		return err
	}
	return bs.SetCanonicalTip(height, blockHash)
}

func (bs *BlockStore) SetCanonicalTip(height uint64, blockHash [32]byte) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	hashHex := hex.EncodeToString(blockHash[:])
	currentLen := uint64(len(bs.index.Canonical))
	switch {
	case height > currentLen:
		return fmt.Errorf("height gap: got %d, expected <= %d", height, currentLen)
	case height == currentLen:
		bs.index.Canonical = append(bs.index.Canonical, hashHex)
	default:
		if bs.index.Canonical[height] == hashHex {
			return saveBlockStoreIndex(bs.indexPath, bs.index)
		}
		bs.index.Canonical = append(bs.index.Canonical[:height], hashHex)
	}
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
	bs.index.Canonical = append([]string(nil), bs.index.Canonical[:height+1]...)
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
	if len(bs.index.Canonical) == 0 {
		return 0, out, false, nil
	}
	height := uint64(len(bs.index.Canonical) - 1)
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
	return os.ReadFile(filepath.Join(bs.blocksDir, hex.EncodeToString(blockHash[:])+".bin"))
}

func (bs *BlockStore) GetHeaderByHash(blockHash [32]byte) ([]byte, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	return os.ReadFile(filepath.Join(bs.headersDir, hex.EncodeToString(blockHash[:])+".bin"))
}

func loadBlockStoreIndex(path string) (blockStoreIndexDisk, error) {
	raw, err := os.ReadFile(path)
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
	return writeFileAtomic(path, raw, 0o644)
}

func writeFileIfAbsent(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err == nil {
		_, writeErr := f.Write(content)
		closeErr := f.Close()
		if writeErr != nil {
			_ = os.Remove(path)
			return writeErr
		}
		if closeErr != nil {
			_ = os.Remove(path)
			return closeErr
		}
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(existing, content) {
		return fmt.Errorf("file already exists with different content: %s", path)
	}
	return nil
}
