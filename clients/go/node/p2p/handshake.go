package p2p

import (
	"fmt"
	"net"
	"time"

	"rubin.dev/node/crypto"
)

const (
	HandshakeTimeout = 10 * time.Second
)

type HandshakeResult struct {
	PeerVersion VersionPayload
	Ready       bool
}

// Handshake performs the minimum v1.1 P2P handshake:
// - send version
// - receive+validate peer version (incl chain_id match)
// - exchange verack
//
// It returns an error for any handshake failure. The caller is responsible for closing conn.
func Handshake(
	conn net.Conn,
	p crypto.CryptoProvider,
	magic uint32,
	ourVersion VersionPayload,
	localChainID [32]byte,
) (*HandshakeResult, error) {
	if conn == nil {
		return nil, fmt.Errorf("p2p: handshake: nil conn")
	}

	ourVersion.ProtocolVersion = ProtocolVersionV1
	ourVersion.ChainID = localChainID

	versionPayload, err := EncodeVersionPayload(ourVersion)
	if err != nil {
		return nil, err
	}
	if err := WriteMessage(conn, p, magic, CmdVersion, versionPayload); err != nil {
		return nil, err
	}

	// INIT: expect peer version within 10 seconds.
	_ = conn.SetReadDeadline(time.Now().Add(HandshakeTimeout))

	var peerVersion *VersionPayload
	for {
		msg, rerr := ReadMessage(conn, p, magic)
		if rerr != nil {
			// checksum mismatch and similar are surfaced as non-disconnect errors.
			if !rerr.Disconnect {
				continue
			}
			return nil, rerr
		}
		switch msg.Command {
		case CmdVersion:
			v, err := DecodeVersionPayload(msg.Payload)
			if err != nil {
				return nil, err
			}
			// chain_id mismatch: send reject + disconnect, no ban-score.
			if v.ChainID != localChainID {
				rp, _ := EncodeRejectPayload(RejectPayload{
					Message: CmdVersion,
					Code:    RejectInvalid,
					Reason:  "chain_id mismatch",
				})
				_ = WriteMessage(conn, p, magic, CmdReject, rp)
				return nil, fmt.Errorf("p2p: handshake: chain_id mismatch")
			}
			if v.ProtocolVersion != ProtocolVersionV1 {
				// Spec doesn't define explicit obsolete behavior yet; treat as malformed.
				return nil, fmt.Errorf("p2p: handshake: unsupported protocol_version")
			}
			peerVersion = v
			goto gotVersion
		case CmdReject:
			rp, err := DecodeRejectPayload(msg.Payload)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("p2p: handshake: reject(%s) code=0x%02x reason=%q", rp.Message, rp.Code, rp.Reason)
		case CmdVerack:
			// Early verack should be ignored.
			continue
		default:
			// Ignore unknown/unsolicited; higher layers can apply ban-score if repeated.
			continue
		}
	}

gotVersion:
	// GOT_VERSION: send verack and require peer verack within 10 seconds.
	if err := WriteMessage(conn, p, magic, CmdVerack, nil); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(HandshakeTimeout))

	for {
		msg, rerr := ReadMessage(conn, p, magic)
		if rerr != nil {
			if !rerr.Disconnect {
				continue
			}
			return nil, rerr
		}
		switch msg.Command {
		case CmdVerack:
			if len(msg.Payload) != 0 {
				return nil, fmt.Errorf("p2p: handshake: verack payload must be empty")
			}
			_ = conn.SetReadDeadline(time.Time{})
			return &HandshakeResult{PeerVersion: *peerVersion, Ready: true}, nil
		case CmdVersion:
			// A second version after handshake start is malformed; in READY it's +10 ban+disconnect.
			return nil, fmt.Errorf("p2p: handshake: duplicate version")
		case CmdReject:
			rp, err := DecodeRejectPayload(msg.Payload)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("p2p: handshake: reject(%s) code=0x%02x reason=%q", rp.Message, rp.Code, rp.Reason)
		default:
			// Ignore until verack arrives.
			continue
		}
	}
}
