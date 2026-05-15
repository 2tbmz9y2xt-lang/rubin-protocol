package p2p

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func encodeVersionPayload(v node.VersionPayloadV1) ([]byte, error) {
	return encodePayload(func(w io.Writer) error {
		return encodeVersionPayloadTo(w, v)
	})
}

func encodeVersionPayloadTo(w io.Writer, v node.VersionPayloadV1) error {
	if err := binary.Write(w, binary.LittleEndian, v.ProtocolVersion); err != nil {
		return err
	}
	txRelay := byte(0)
	if v.TxRelay {
		txRelay = 1
	}
	if _, err := w.Write([]byte{txRelay}); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, v.PrunedBelowHeight); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, v.DaMempoolSize); err != nil {
		return err
	}
	if _, err := w.Write(v.ChainID[:]); err != nil {
		return err
	}
	if _, err := w.Write(v.GenesisHash[:]); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, v.BestHeight); err != nil {
		return err
	}
	return nil
}

func decodeVersionPayload(payload []byte) (node.VersionPayloadV1, error) {
	var out node.VersionPayloadV1
	if len(payload) != versionPayloadBytes {
		if len(payload) < versionPayloadBytes {
			return out, errors.New("version payload too short")
		}
		return out, errors.New("trailing bytes in version payload")
	}
	reader := bytes.NewReader(payload)
	if err := binary.Read(reader, binary.LittleEndian, &out.ProtocolVersion); err != nil {
		return out, errors.New("version payload too short")
	}
	var txRelay [1]byte
	if _, err := io.ReadFull(reader, txRelay[:]); err != nil {
		return out, errors.New("version payload too short")
	}
	out.TxRelay = txRelay[0] == 1
	if err := binary.Read(reader, binary.LittleEndian, &out.PrunedBelowHeight); err != nil {
		return out, errors.New("version payload too short")
	}
	if err := binary.Read(reader, binary.LittleEndian, &out.DaMempoolSize); err != nil {
		return out, errors.New("version payload too short")
	}
	if _, err := io.ReadFull(reader, out.ChainID[:]); err != nil {
		return out, errors.New("version payload too short")
	}
	if _, err := io.ReadFull(reader, out.GenesisHash[:]); err != nil {
		return out, errors.New("version payload too short")
	}
	if err := binary.Read(reader, binary.LittleEndian, &out.BestHeight); err != nil {
		return out, errors.New("version payload too short")
	}
	if reader.Len() != 0 {
		return out, errors.New("trailing bytes in version payload")
	}
	return out, nil
}

func encodePayload(encode func(io.Writer) error) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
