package consensus

import (
	"encoding/binary"
	"strings"
	"testing"
)

func makeCoreExtCovenantDataWithPayload(extID uint16, payload []byte) []byte {
	out := make([]byte, 0, 2+1+len(payload))
	var extIDBuf [2]byte
	binary.LittleEndian.PutUint16(extIDBuf[:], extID)
	out = append(out, extIDBuf[:]...)
	out = AppendCompactSize(out, uint64(len(payload)))
	out = append(out, payload...)
	return out
}

func TestBuildTxContext_NoTxContextEnabledInputsReturnsNil(t *testing.T) {
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 90, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(9, []byte{0xaa})},
		},
	}
	resolved := []UtxoEntry{
		{Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(9, []byte{0x01})},
	}
	profiles := &testCoreExtProfileProvider{
		profile: CoreExtProfile{
			Active:           true,
			TxContextEnabled: false,
		},
		found: true,
	}

	bundle, err := BuildTxContext(tx, resolved, 101, profiles)
	if err != nil {
		t.Fatalf("BuildTxContext: %v", err)
	}
	if bundle != nil {
		t.Fatalf("expected nil bundle, got %#v", bundle)
	}
}

func TestBuildTxContext_BuildsBaseAndContinuingOutputsDeterministically(t *testing.T) {
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevVout: 0},
			{PrevVout: 1},
			{PrevVout: 2},
		},
		Outputs: []TxOutput{
			{Value: 11, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(7, []byte{0x07, 0x01})},
			{Value: 12, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
			{Value: 13, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(5, []byte{0x05, 0x01})},
			{Value: 14, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(7, []byte{0x07, 0x02})},
			{Value: 15, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(5, []byte{0x05, 0x02})},
		},
	}
	resolved := []UtxoEntry{
		{Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(7, []byte{0xaa})},
		{Value: 200, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(5, []byte{0xbb})},
		{Value: 300, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
	}

	profiles := &staticMapCoreExtProfileProvider{
		profiles: map[uint16]CoreExtProfile{
			5: {Active: true, TxContextEnabled: true},
			7: {Active: true, TxContextEnabled: true},
		},
	}

	bundle, err := BuildTxContext(tx, resolved, 222, profiles)
	if err != nil {
		t.Fatalf("BuildTxContext: %v", err)
	}
	if bundle == nil || bundle.Base == nil {
		t.Fatalf("expected non-nil bundle/base")
	}
	if got := bundle.Base.TotalIn; got != (Uint128{Lo: 600, Hi: 0}) {
		t.Fatalf("TotalIn=%+v want %+v", got, Uint128{Lo: 600, Hi: 0})
	}
	if got := bundle.Base.TotalOut; got != (Uint128{Lo: 65, Hi: 0}) {
		t.Fatalf("TotalOut=%+v want %+v", got, Uint128{Lo: 65, Hi: 0})
	}
	if bundle.Base.Height != 222 {
		t.Fatalf("Height=%d want 222", bundle.Base.Height)
	}

	cont5, ok := bundle.Continuing(5)
	if !ok {
		t.Fatalf("missing ext_id=5 bundle")
	}
	if cont5.ContinuingOutputCount != 2 {
		t.Fatalf("ext 5 count=%d want 2", cont5.ContinuingOutputCount)
	}
	if cont5.ContinuingOutputs[0].Value != 13 || string(cont5.ContinuingOutputs[0].ExtPayload) != string([]byte{0x05, 0x01}) {
		t.Fatalf("ext 5 first output=%+v", cont5.ContinuingOutputs[0])
	}
	if cont5.ContinuingOutputs[1].Value != 15 || string(cont5.ContinuingOutputs[1].ExtPayload) != string([]byte{0x05, 0x02}) {
		t.Fatalf("ext 5 second output=%+v", cont5.ContinuingOutputs[1])
	}

	cont7, ok := bundle.Continuing(7)
	if !ok {
		t.Fatalf("missing ext_id=7 bundle")
	}
	if cont7.ContinuingOutputCount != 2 {
		t.Fatalf("ext 7 count=%d want 2", cont7.ContinuingOutputCount)
	}
	if cont7.ContinuingOutputs[0].Value != 11 || string(cont7.ContinuingOutputs[0].ExtPayload) != string([]byte{0x07, 0x01}) {
		t.Fatalf("ext 7 first output=%+v", cont7.ContinuingOutputs[0])
	}
	if cont7.ContinuingOutputs[1].Value != 14 || string(cont7.ContinuingOutputs[1].ExtPayload) != string([]byte{0x07, 0x02}) {
		t.Fatalf("ext 7 second output=%+v", cont7.ContinuingOutputs[1])
	}
}

func TestBuildTxContext_RejectsThirdContinuingOutputForLowestExtID(t *testing.T) {
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevVout: 0},
			{PrevVout: 1},
		},
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(9, []byte{0x91})},
			{Value: 2, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(7, []byte{0x71})},
			{Value: 3, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(9, []byte{0x92})},
			{Value: 4, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(7, []byte{0x72})},
			{Value: 5, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(7, []byte{0x73})},
			{Value: 6, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(9, []byte{0x93})},
		},
	}
	resolved := []UtxoEntry{
		{Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(9, []byte{0xaa})},
		{Value: 200, CovenantType: COV_TYPE_CORE_EXT, CovenantData: makeCoreExtCovenantDataWithPayload(7, []byte{0xbb})},
	}
	profiles := &staticMapCoreExtProfileProvider{
		profiles: map[uint16]CoreExtProfile{
			7: {Active: true, TxContextEnabled: true},
			9: {Active: true, TxContextEnabled: true},
		},
	}

	_, err := BuildTxContext(tx, resolved, 99, profiles)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
	if !strings.Contains(err.Error(), "ext_id=7") {
		t.Fatalf("expected lowest ext_id attribution in error, got %v", err)
	}
}

func TestStaticCoreExtProfileProvider_PropagatesTxContextEnabled(t *testing.T) {
	provider, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 5,
		TxContextEnabled: true,
		AllowedSuites:    map[uint8]struct{}{0x42: {}},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}

	profile, ok, err := provider.LookupCoreExtProfile(7, 5)
	if err != nil {
		t.Fatalf("LookupCoreExtProfile: %v", err)
	}
	if !ok {
		t.Fatalf("expected active profile")
	}
	if !profile.TxContextEnabled {
		t.Fatalf("expected TxContextEnabled=true")
	}
}

type staticMapCoreExtProfileProvider struct {
	profiles map[uint16]CoreExtProfile
}

func (p *staticMapCoreExtProfileProvider) LookupCoreExtProfile(extID uint16, _ uint64) (CoreExtProfile, bool, error) {
	profile, ok := p.profiles[extID]
	return profile, ok, nil
}
