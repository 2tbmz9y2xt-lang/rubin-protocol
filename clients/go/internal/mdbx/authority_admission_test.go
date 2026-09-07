package mdbx

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"
)

// NONE/STABLE, pruned profile, active generation 1, next generation 2.
func admissionNone() []byte {
	return []byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 1, 1, 0, 0, 0, 0}
}

func admissionMaximum() []byte {
	// NONE's 40 bytes plus InvalidBranch's height/hash/length (44 bytes).
	b := append(admissionNone()[:37], 1)
	b = binary.BigEndian.AppendUint64(b, 7)
	b = append(b, make([]byte, 31)...)
	b = append(b, 72)
	b = binary.BigEndian.AppendUint32(b, 1_048_492)
	b = append(b, make([]byte, 1_048_492)...)
	return append(b, 0, 0)
}

func TestStorageAuthorityAdmissionMetaAccepted(t *testing.T) {
	for _, row := range codecLiteralCases(t) {
		t.Run(row.name, func(t *testing.T) {
			before := bytes.Clone(row.b)
			got, err := MetaValue(2, row.b)
			if err != nil || !bytes.Equal(got, before) || !bytes.Equal(row.b, before) {
				t.Fatalf("authority MetaValue accepted bytes: %v", err)
			}
			if err := ValidateRow(DBI{Name: "meta-v1"}, []byte{2}, row.b); err != nil || !bytes.Equal(row.b, before) {
				t.Fatalf("authority ValidateRow accepted bytes: %v", err)
			}
		})
	}
	t.Run("exact-cap", func(t *testing.T) {
		b := admissionMaximum()
		before := bytes.Clone(b)
		got, err := MetaValue(2, b)
		if len(b) != 1_048_576 || err != nil || !bytes.Equal(got, before) || !bytes.Equal(b, before) || ValidateRow(DBI{Name: "meta-v1"}, []byte{2}, b) != nil {
			t.Fatalf("authority exact-cap accepted bytes: size=%d err=%v", len(b), err)
		}
	})
}

func admissionRejected(t *testing.T) map[string][]byte {
	t.Helper()
	none := admissionNone()
	rows := map[string][]byte{"nil": nil, "empty": {}, "opaque-9": {9}, "short-header": none[:18], "trailing-zero": append(bytes.Clone(none), 0), "concatenated": append(bytes.Clone(none), none...), "exact-cap-invalid": make([]byte, 1_048_576), "cap-plus-one": make([]byte, 1_048_577)}
	for _, row := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"version", 0, 2}, {"active-profile", 1, 3}, {"phase", 34, 5}, {"lifecycle", 35, 3}, {"presence", 37, 2}, {"scalar-next-equals-active", 33, 1},
	} {
		b := bytes.Clone(none)
		b[row.offset] = row.value
		rows[row.name] = b
	}
	for _, row := range codecLiteralCases(t) {
		rows["prefix-"+row.name] = row.b[:len(row.b)-1]
	}
	for _, n := range []int{1, 2, 34, 35, 36, 37, 38, 39} {
		rows["none-prefix-"+strconv.Itoa(n)] = none[:n]
	}
	return rows
}

func TestStorageAuthorityAdmissionMetaRejected(t *testing.T) {
	for name, b := range admissionRejected(t) {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(b)
			got, err := MetaValue(2, b)
			if got != nil || !exactErr(err) || !bytes.Equal(b, before) {
				t.Fatalf("authority MetaValue rejection tuple: output=%d err=%v", len(got), err)
			}
		})
	}
}

func TestStorageAuthorityAdmissionRowRejected(t *testing.T) {
	for name, b := range admissionRejected(t) {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(b)
			if err := ValidateRow(DBI{Name: "meta-v1"}, []byte{2}, b); !exactErr(err) || !bytes.Equal(b, before) {
				t.Fatalf("authority ValidateRow rejection tuple: %v", err)
			}
		})
	}
	for _, row := range []struct {
		dbi DBI
		key []byte
	}{{DBI{Name: "wrong"}, []byte{2}}, {DBI{Name: "meta-v1"}, []byte{2, 0}}} {
		if !exactErr(ValidateRow(row.dbi, row.key, admissionNone())) {
			t.Fatal("authority DBI/key validation changed")
		}
	}
}

func TestStorageAuthorityAdmissionOwnership(t *testing.T) {
	b := admissionNone()
	before := bytes.Clone(b)
	got, err := MetaValue(2, b)
	if err != nil || !bytes.Equal(got, before) || !bytes.Equal(b, before) {
		t.Fatalf("authority MetaValue accepted bytes: %v", err)
	}
	got[0] ^= 0xff
	if !bytes.Equal(b, before) {
		t.Fatal("authority MetaValue aliases input")
	}
}
