package node

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// cxSource supplies point facts and freshness only; it never computes context or admission.
type cxSource struct {
	mu sync.Mutex
	raws map[[32]byte][148]byte
	reads [][32]byte
	calls int
	current func() (bool, error)
	read func([32]byte, *[148]byte) (HeaderContextRead148V1, error)
}

func (s *cxSource) CurrentV1() (bool, error) {
	if s == nil {
		return false, nil
	}
	s.mu.Lock()
	s.calls++
	fn := s.current
	s.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return true, nil
}

func (s *cxSource) Header148V1(hash [32]byte, dst *[148]byte) (HeaderContextRead148V1, error) {
	s.mu.Lock()
	s.reads = append(s.reads, hash)
	fn := s.read
	raw, ok := s.raws[hash]
	s.mu.Unlock()
	if fn != nil {
		return fn(hash, dst)
	}
	if !ok {
		return HeaderContextReadUnavailable148V1, nil
	}
	*dst = raw
	return HeaderContextPresent148V1, nil
}

func cxLimits() HeaderContextLimits148V1 {
	return HeaderContextLimits148V1{MaxRecords:32, MaxBytes:1<<20, MaxPins:16, MaxReads:20000, MaxReadBytes:4<<20, MaxReadWork:20000, MaxScratchBytes:8<<20, MaxSuffix:16, MaxWorkBytes:64}
}

func cxTarget(first byte) [32]byte {
	var target [32]byte
	for i := range target {
		target[i] = 255
	}
	target[0] = first
	return target
}

func cxHash(raw [148]byte) [32]byte {
	hash, _ := consensus.Initial148BlockHash(raw[:])
	return hash
}

// cxMine constructs supported raw inputs; expected context arithmetic never uses C2 helpers.
func cxMine(parent [32]byte, timestamp uint64, target [32]byte) [148]byte {
	var raw [148]byte
	binary.LittleEndian.PutUint32(raw[:4], 1)
	copy(raw[4:36], parent[:])
	binary.LittleEndian.PutUint64(raw[68:76], timestamp)
	copy(raw[76:108], target[:])
	for nonce := uint64(0); ; nonce++ {
		binary.LittleEndian.PutUint64(raw[140:], nonce)
		hash := cxHash(raw)
		if bytes.Compare(hash[:], target[:]) < 0 {
			return raw
		}
	}
}

func cxNew(t *testing.T, l HeaderContextLimits148V1, cl HeaderCandidateLimits148V1, raw [148]byte) (*HeaderCandidateOwner148V1, HeaderContextView148V1, *cxSource) {
	t.Helper()
	o, err := NewHeaderCandidateContext148V1(cl, l, 7, [32]byte{91}, cxHash(raw))
	if err != nil {
		t.Fatal(err)
	}
	pub, out := o.EstablishV1([32]byte{1}, nil)
	if out != 0 || !pub.Changed || pub.Version != 2 {
		t.Fatalf("establish: %+v %d", pub, out)
	}
	v := HeaderContextView148V1{Incarnation:7, Version:2, Source:[32]byte{1}, Authority:[32]byte{8}, Network:[32]byte{91}, Genesis:cxHash(raw)}
	return o, v, &cxSource{raws:map[[32]byte][148]byte{cxHash(raw):raw}}
}

func cxDecision(t *testing.T, label string, got HeaderContextDecision148V1, outcome, mismatch, candidate uint8, cause error) {
	t.Helper()
	want := HeaderContextDecision148V1{Outcome:HeaderContextOutcome148V1(outcome), Mismatch:HeaderContextMismatch148V1(mismatch), CandidateOutcome:HeaderCandidateOutcome148V1(candidate), Cause:cause}
	if got != want {
		t.Fatalf("%s DECISION_TUPLE: got %+v want %+v", label, got, want)
	}
}

func cxEqual(t *testing.T, label string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got %#v want %#v", label, got, want)
	}
}

func cxSeed(t *testing.T, o *HeaderCandidateOwner148V1, v HeaderContextView148V1, raw [148]byte, s HeaderContextSource148V1) HeaderContextRecord148V1 {
	t.Helper()
	cxDecision(t, "seed", o.SeedGenesisContextV1(v, raw, [32]byte{9}, s), 0, 0, 0, nil)
	r, d := o.LookupContextV1(v, cxHash(raw))
	cxDecision(t, "seed lookup", d, 0, 0, 0, nil)
	return r
}

func cxProof(r HeaderContextRecord148V1, kind HeaderContextAnchorKind148V1) *HeaderContextAnchor148V1 {
	return &HeaderContextAnchor148V1{Kind:kind, Raw:r.Raw, Hash:r.Hash, Height:r.Height, Work:new(big.Int).Set(r.Work), Provenance:r.Provenance}
}

func cxInput(v HeaderContextView148V1, raw [148]byte, proof *HeaderContextAnchor148V1, source HeaderContextSource148V1) HeaderContextInput148V1 {
	return HeaderContextInput148V1{View:v, Raw:raw, WarmParent:proof, Source:source, Tip:HeaderContextTip148V1{Height:proof.Height, Hash:proof.Hash, Work:new(big.Int).Set(proof.Work), Provenance:[32]byte{10}, Authority:v.Authority}}
}

func cxPublish(t *testing.T, o *HeaderCandidateOwner148V1, in HeaderContextInput148V1) (HeaderContextRecord148V1, HeaderCandidatePublication148V1) {
	t.Helper()
	h, d := o.PrepareContextV1(in)
	cxDecision(t, "prepare", d, 0, 0, 0, nil)
	if h == nil {
		t.Fatal("prepare returned nil")
	}
	type publication struct {
		record HeaderContextRecord148V1
		receipt HeaderCandidatePublication148V1
		decision HeaderContextDecision148V1
	}
	done := make(chan publication, 1)
	go func() {
		r, pub, result := h.PublishV1()
		done <- publication{r, pub, result}
	}()
	var result publication
	select {
	case result = <-done:
	case <-time.After(5 * time.Second):
		o.CloseV1()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("PUBLISH_GUARD: publication did not join after owner Close")
		}
		t.Fatal("PUBLISH_GUARD: publication retained an invocation guard")
	}
	r, pub, d := result.record, result.receipt, result.decision
	cxDecision(t, "publish", d, 0, 0, 0, nil)
	cxClean(t, o, false)
	return r, pub
}

func cxClean(t *testing.T, o *HeaderCandidateOwner148V1, unknown bool) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.context.active != nil || o.context.scratch != 0 || (!o.closed && (o.prepared != nil) != unknown) {
		t.Fatalf("CHARGE_RELEASE: active=%v scratch=%d prepared=%v", o.context.active != nil, o.context.scratch, o.prepared != nil)
	}
}

// cxState observes complete retained C2 facts, accounting and C1 membership without a write seam.
func cxState(o *HeaderCandidateOwner148V1) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var keys [][32]byte
	for hash := range o.context.records {
		keys = append(keys, hash)
	}
	slices.SortFunc(keys, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	value := fmt.Sprintf("%d/%x/%d/%d/%d/%d/%d/%d/%v/%v/%v/%v/%v/%d", o.version.Load(), o.source, len(o.recs), o.context.bytes, o.context.pins, o.context.scratch, o.leases, len(o.context.pinned), o.prepared!=nil, o.context.active!=nil, o.closed, o.latched, o.established, o.tips)
	for _, hash := range keys {
		r := o.context.records[hash]
		work,clamp:=r.Work.String(),r.LastClampedTimestamp.String()
		r.Work,r.LastClampedTimestamp=nil,nil
		value += fmt.Sprintf("/%#v/work=%s/clamp=%s/pins=%d", r, work, clamp, o.context.pinned[hash])
	}
	keys=keys[:0]
	for hash:=range o.recs {keys=append(keys,hash)}
	slices.SortFunc(keys,func(a,b [32]byte)int{return bytes.Compare(a[:],b[:])})
	for _,hash:=range keys {
		e:=o.recs[hash]
		value+=fmt.Sprintf("/C1=%#v/charge=%d/kids=%d/leased=%d",e.rec,e.charge,o.kids[hash],o.leased[hash])
	}
	return value
}

func cxRefuse(t *testing.T, label string, o *HeaderCandidateOwner148V1, in HeaderContextInput148V1, outcome, mismatch, candidate uint8, cause error) {
	t.Helper()
	before := cxState(o)
	h, d := o.PrepareContextV1(in)
	cxDecision(t, label, d, outcome, mismatch, candidate, cause)
	if h != nil {
		t.Fatalf("%s returned a handle", label)
	}
	cxEqual(t, label+" unchanged", cxState(o), before)
	cxClean(t, o, candidate == 2 || candidate == 4)
	want:=uint8(0)
	if candidate>=1 && candidate<=4 {want=candidate}
	next,out:=o.PrepareV1(hcTr(o,nil))
	if uint8(out)!=want {t.Fatalf("%s next C1 operation: %d want %d",label,out,want)}
	if next!=nil {
		if result:=next.AbortV1();result!=0 {t.Fatalf("%s next C1 abort: %d",label,result)}
	}else if want==0 {t.Fatalf("%s next C1 returned nil",label)}
	cxEqual(t,label+" next operation preserved state",cxState(o),before)
}

// cxExpected fixes raw input facts only; each test supplies the independent derived fields.
func cxExpected(raw [148]byte, height uint64, work *big.Int, v HeaderContextView148V1) HeaderContextRecord148V1 {
	r := HeaderContextRecord148V1{Raw:raw, Hash:cxHash(raw), Height:height, Work:work, Provenance:[32]byte{9}, View:v}
	copy(r.Parent[:], raw[4:36])
	copy(r.CurrentTarget[:], raw[76:108])
	return r
}

func TestHeaderContext148Genesis(t *testing.T) {
	for _, timestamp := range []uint64{0, 10} {
		raw := cxMine([32]byte{}, timestamp, cxTarget(255))
		o, v, source := cxNew(t, cxLimits(), hcLim(), raw)
		r := cxSeed(t, o, v, raw, source)
		want := cxExpected(raw, 0, big.NewInt(1), v)
		want.RawCount, want.EpochCount, want.FirstRawTimestamp = 1, 1, timestamp
		want.RawTimestamps[0], want.LastClampedTimestamp = timestamp, new(big.Int).SetUint64(timestamp)
		cxEqual(t, "GENESIS_ZERO/WORK_GENESIS complete", r, want)
		before := cxState(o)
		cxDecision(t, "repeat", o.SeedGenesisContextV1(v, raw, [32]byte{9}, source), 0, 0, 0, nil)
		cxEqual(t, "repeat no membership/version", cxState(o), before)
		cxDecision(t, "conflicting provenance", o.SeedGenesisContextV1(v, raw, [32]byte{10}, source), 4, 0, 0, nil)
		cxEqual(t, "conflict unchanged", cxState(o), before)
		child := cxMine(r.Hash, timestamp+1, cxTarget(255))
		got, pub := cxPublish(t, o, cxInput(v, child, cxProof(r, HeaderContextCanonical148V1), source))
		if got.Height != 1 || got.Work.Cmp(big.NewInt(2)) != 0 || !pub.Changed || pub.Version != 3 {
			t.Fatalf("first child: %+v %+v", got, pub)
		}
		admitted, ok := o.LookupV1(got.Hash)
		if !ok || !admitted.External {
			t.Fatal("WARM_EXTERNAL: canonical genesis must cover first child")
		}
	}
	for _,defect:=range []string{"range","pow","hash","provenance","nil-source"} {
		raw:=cxMine([32]byte{},0,cxTarget(255))
		if defect=="range"{clear(raw[76:108])};if defect=="pow"{raw=cxBadPoW(raw,[32]byte{1})}
		o,v,s:=cxNew(t,cxLimits(),hcLim(),raw);prov:=[32]byte{9};var source HeaderContextSource148V1=s
		if defect=="hash"{raw[140]^=1};if defect=="provenance"{prov=[32]byte{}};if defect=="nil-source"{source=nil}
		before:=cxState(o);out:=uint8(4);if defect=="nil-source"{out=2}
		cxDecision(t,"local genesis "+defect,o.SeedGenesisContextV1(v,raw,prov,source),out,0,0,nil)
		cxEqual(t,"genesis refusal unchanged",cxState(o),before);cxClean(t,o,false)
	}
}

func cxWarm(t *testing.T, times []uint64) (*HeaderCandidateOwner148V1, HeaderContextRecord148V1, *cxSource) {
	t.Helper()
	raw := cxMine([32]byte{}, times[0], cxTarget(255))
	cl := hcLim(); cl.MaxHeaders,cl.MaxTransitionHeaders=64,64
	o, v, source := cxNew(t, cxLimits(), cl, raw)
	r := cxSeed(t, o, v, raw, source)
	kind := HeaderContextCanonical148V1
	for _, timestamp := range times[1:] {
		raw = cxMine(r.Hash, timestamp, cxTarget(255))
		source.raws[cxHash(raw)] = raw
		r, _ = cxPublish(t, o, cxInput(r.View, raw, cxProof(r, kind), source))
		kind = HeaderContextAdmitted148V1
	}
	return o, r, source
}

func TestHeaderContext148Timestamp(t *testing.T) {
	for k := 1; k <= 11; k++ {
		t.Run(fmt.Sprintf("raw-count-%d", k), func(t *testing.T) {
			times := make([]uint64, k)
			for i := range times {
				times[i] = 10+10*uint64(i)
			}
			o, p, source := cxWarm(t, times)
			kind := HeaderContextAdmitted148V1
			if k == 1 {
				kind = HeaderContextCanonical148V1
			}
			median := uint64(10+10*((k-1)/2))
			in := cxInput(p.View, cxMine(p.Hash, median+1, cxTarget(255)), cxProof(p, kind), source)
			r, pub := cxPublish(t, o, in)
			v := p.View
			v.Version = pub.Version
			want := cxExpected(in.Raw, uint64(k), big.NewInt(int64(k+1)), v)
			want.RawCount, want.EpochCount, want.FirstRawTimestamp = uint8(min(11,k+1)), uint64(k+1), 10
			want.RawTimestamps[0] = median+1
			for i := 1; i < int(want.RawCount); i++ {
				want.RawTimestamps[i] = times[k-i]
			}
			want.LastClampedTimestamp = new(big.Int).SetUint64(max(times[k-1]+1, median+1))
			cxEqual(t, "MTP_EVEN complete lower-median extension", r, want)
			old := cxInput(p.View, cxMine(p.Hash, median, cxTarget(255)), cxProof(p, kind), source)
			// A fresh owner isolates the floor from the publication's stale view.
			o2, p2, s2 := cxWarm(t, times)
			old.View, old.WarmParent, old.Source = p2.View, cxProof(p2, kind), s2
			cxRefuse(t, "MTP_FLOOR", o2, old, 6, 5, 0, nil)
			old.Raw = cxMine(p2.Hash, median+7201, cxTarget(255))
			cxRefuse(t, "MTP_CEILING", o2, old, 6, 6, 0, nil)
		})
	}
	o, p, source := cxWarm(t, []uint64{10,20})
	r, _ := cxPublish(t, o, cxInput(p.View, cxMine(p.Hash,15,cxTarget(255)), cxProof(p,HeaderContextAdmitted148V1), source))
	cxEqual(t, "literal 10->20->15 raw order", r.RawTimestamps, [11]uint64{15,20,10})
	cxEqual(t, "CLAMP_LOWER", r.LastClampedTimestamp, big.NewInt(21))
	o, p, source = cxWarm(t, []uint64{0,7200,7200})
	cxEqual(t, "CLAMP_UPPER", p.LastClampedTimestamp, big.NewInt(2400))
	cxRefuse(t, "MTP_RAW", o, cxInput(p.View,cxMine(p.Hash,3000,cxTarget(255)),cxProof(p,HeaderContextAdmitted148V1),source),6,5,0,nil)
	o, p, source = cxWarm(t, []uint64{math.MaxUint64-10,math.MaxUint64-1})
	r, _ = cxPublish(t,o,cxInput(p.View,cxMine(p.Hash,math.MaxUint64,cxTarget(255)),cxProof(p,HeaderContextAdmitted148V1),source))
	cxEqual(t,"wide MTP_CEILING does not wrap",r.LastClampedTimestamp,new(big.Int).SetUint64(math.MaxUint64))
	genesis:=cxMine([32]byte{},10,cxTarget(127));o,v,source:=cxNew(t,cxLimits(),hcLim(),genesis)
	p=cxSeed(t,o,v,genesis,source);cxEqual(t,"nondefault genesis work",p.Work,big.NewInt(2))
	p,_=cxPublish(t,o,cxInput(v,cxMine(p.Hash,20,cxTarget(127)),cxProof(p,HeaderContextCanonical148V1),source))
	raw:=cxMine(p.Hash,15,cxTarget(127));r,_=cxPublish(t,o,cxInput(p.View,raw,cxProof(p,HeaderContextAdmitted148V1),source))
	expectedView:=p.View;expectedView.Version=p.View.Version+1
	want:=cxExpected(raw,2,big.NewInt(6),expectedView);want.RawCount,want.EpochCount,want.FirstRawTimestamp=3,3,10;want.RawTimestamps=[11]uint64{15,20,10};want.LastClampedTimestamp=big.NewInt(21)
	cxEqual(t,"nondefault warm complete",r,want)
}

// cxChain creates only independently chosen raw source facts; its heights are array positions plus base.
func cxChain(base uint64, count int, first, step uint64, target [32]byte, half bool) ([][148]byte, *cxSource) {
	raws := make([][148]byte,count)
	source := &cxSource{raws:map[[32]byte][148]byte{}}
	parent := [32]byte{}
	if base != 0 {
		parent = [32]byte{42}
	}
	for i := range raws {
		timestamp := 121*base+first+uint64(i)*step
		if half {
			timestamp = first+uint64((i+1)/2)
		}
		raws[i] = cxMine(parent,timestamp,target)
		parent = cxHash(raws[i])
		source.raws[parent] = raws[i]
	}
	return raws,source
}

func cxCold(v HeaderContextView148V1, raw [148]byte, a HeaderContextAnchor148V1, suffix uint64, source HeaderContextSource148V1) HeaderContextInput148V1 {
	in := cxInput(v,raw,&a,source)
	in.WarmParent = nil
	in.ColdParent = &HeaderContextCold148V1{Anchor:a,Suffix:suffix}
	in.Tip.Height = a.Height+suffix
	copy(in.Tip.Hash[:],raw[4:36])
	in.Tip.Work.Add(in.Tip.Work,new(big.Int).SetUint64(suffix))
	return in
}

func TestHeaderContext148Epoch(t *testing.T) {
	for _, tc := range []struct {
		name string
		first, step uint64
		old byte
		half bool
		mode string
	}{
		{"RETARGET_DELTA",10,120,255,false,"floor"},
		{"RETARGET_PARENT_TARGET",10,1,255,false,"lower"},
		{"upper",10,1200,31,false,"upper"},
		{"limit",10,1200,127,false,"limit"},
		{"RETARGET_WIDE_DELTA",math.MaxUint64-6000,1,255,true,"lower"},
	} {
		t.Run(tc.name,func(t *testing.T) {
			raws,source := cxChain(0,10080,tc.first,tc.step,cxTarget(tc.old),tc.half)
			o,v,_ := cxNew(t,cxLimits(),hcLim(),raws[0])
			old := cxTarget(tc.old)
			expected := new(big.Int).SetBytes(old[:])
			switch tc.mode {
			case "lower": expected.Rsh(expected,2)
			case "upper": expected.Lsh(expected,2)
			case "limit": maximum := cxTarget(255); expected.SetBytes(maximum[:])
			case "floor": expected.Mul(expected,big.NewInt(10079)); expected.Div(expected,big.NewInt(10080))
			}
			var nextTarget [32]byte
			expected.FillBytes(nextTarget[:])
			lastRaw := binary.LittleEndian.Uint64(raws[10079][68:76])
			child := cxMine(cxHash(raws[10079]),lastRaw+1,nextTarget)
			perBlock := new(big.Int).Quo(new(big.Int).Lsh(big.NewInt(1),256),new(big.Int).SetBytes(old[:]))
			anchorWork := new(big.Int).Mul(perBlock,big.NewInt(10080))
			a := HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:raws[10079],Hash:cxHash(raws[10079]),Height:10079,Work:anchorWork,Provenance:[32]byte{9}}
			in := cxCold(v,child,a,0,source)
			r,pub := cxPublish(t,o,in)
			wantWork := new(big.Int).Quo(new(big.Int).Lsh(big.NewInt(1),256),expected)
			wantWork.Add(wantWork,anchorWork)
			expectedView:=v;expectedView.Version=3
			want := cxExpected(child,10080,wantWork,expectedView)
			want.RawCount, want.EpochStart, want.EpochCount = 11,10080,1
			want.FirstRawTimestamp, want.LastClampedTimestamp = lastRaw+1,new(big.Int).SetUint64(lastRaw+1)
			want.RawTimestamps[0] = lastRaw+1
			for i:=1;i<11;i++ { want.RawTimestamps[i] = binary.LittleEndian.Uint64(raws[10080-i][68:76]) }
			cxEqual(t,"EPOCH_TARGET_BEFORE_RESET complete",r,want)
			cxEqual(t,"boundary only child addition",pub.Added,[][32]byte{cxHash(child)})
			cxEqual(t,"COLD_BOUND",len(source.reads),10080)
			if tc.half {
				o3,v3,_:=cxNew(t,cxLimits(),hcLim(),raws[0])
				prior:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:raws[10078],Hash:cxHash(raws[10078]),Height:10078,Work:big.NewInt(10079),Provenance:[32]byte{9}}
				wide,_:=cxPublish(t,o3,cxCold(v3,raws[10079],prior,0,source))
				clamp:=new(big.Int).Add(new(big.Int).SetUint64(math.MaxUint64),big.NewInt(4079))
				cxEqual(t,"CLAMP_WIDE full value",wide.LastClampedTimestamp,clamp)
			}
			wrong := in
			wrong.Raw = cxMine(a.Hash,lastRaw+1,old)
			// The same raw epoch is still a valid source; this view has advanced independently.
			o2,v2,_ := cxNew(t,cxLimits(),hcLim(),raws[0]); wrong.View=v2
			cxRefuse(t,"EPOCH_TARGET_BEFORE_RESET",o2,wrong,6,4,0,nil)
		})
	}
	// A later complete epoch includes the ten raw predecessors before its epoch start.
	raws,source:=cxChain(10070,10090,10,120,cxTarget(255),false)
	genesis:=cxMine([32]byte{},0,cxTarget(255));o,v,_:=cxNew(t,cxLimits(),hcLim(),genesis)
	oldTarget:=cxTarget(255)
	expected:=new(big.Int).Mul(new(big.Int).SetBytes(oldTarget[:]),big.NewInt(10079));expected.Div(expected,big.NewInt(10080))
	var target [32]byte;expected.FillBytes(target[:])
	last:=raws[len(raws)-1];timestamp:=binary.LittleEndian.Uint64(last[68:76])+1
	a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:last,Hash:cxHash(last),Height:20159,Work:big.NewInt(20160),Provenance:[32]byte{9}}
	r,_:=cxPublish(t,o,cxCold(v,cxMine(a.Hash,timestamp,target),a,0,source))
	if r.Height!=20160 || r.EpochStart!=20160 || r.EpochCount!=1 || r.CurrentTarget!=target || r.FirstRawTimestamp!=timestamp || r.LastClampedTimestamp.Cmp(new(big.Int).SetUint64(timestamp))!=0 {t.Fatal("later EPOCH_TARGET_BEFORE_RESET")}
	cxEqual(t,"later read bound",len(source.reads),10090)
}

func TestHeaderContext148Cold(t *testing.T) {
	for _, tc := range []struct{anchor, suffix, base uint64}{
		{0,0,0},{0,2,0},{5,0,0},{5,3,0},{5,16,0},{10080,0,10070},{20165,2,20150},
	} {
		t.Run(fmt.Sprintf("a%d-D%d",tc.anchor,tc.suffix),func(t *testing.T) {
			count := int(tc.anchor+tc.suffix-tc.base+1)
			raws,source := cxChain(tc.base,count,10,1,cxTarget(255),false)
			genesis := raws[0]
			if tc.base!=0 { genesis = cxMine([32]byte{},0,cxTarget(255)) }
			cl:=hcLim(); cl.MaxHeaders,cl.MaxTransitionHeaders=64,64
			o,v,_ := cxNew(t,cxLimits(),cl,genesis)
			idx := int(tc.anchor-tc.base)
			a := HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:raws[idx],Hash:cxHash(raws[idx]),Height:tc.anchor,Work:new(big.Int).SetUint64(tc.anchor+1),Provenance:[32]byte{9}}
			parent := raws[len(raws)-1]
			child := cxMine(cxHash(parent),121*tc.base+10+uint64(count),cxTarget(255))
			in := cxCold(v,child,a,tc.suffix,source)
			r,pub := cxPublish(t,o,in)
			expectedView:=v;expectedView.Version=3
			want := cxExpected(child,tc.anchor+tc.suffix+1,new(big.Int).SetUint64(tc.anchor+tc.suffix+2),expectedView)
			want.RawCount = uint8(min(uint64(11),want.Height+1))
			want.EpochStart = want.Height/10080*10080
			want.EpochCount = want.Height-want.EpochStart+1
			want.FirstRawTimestamp = 121*tc.base+10+want.EpochStart-tc.base
			want.LastClampedTimestamp = new(big.Int).SetUint64(121*tc.base+10+uint64(count))
			for j:=0;j<int(want.RawCount);j++ { want.RawTimestamps[j]=121*tc.base+10+uint64(count-j) }
			cxEqual(t,"cold complete",r,want)
			var sequence [][32]byte
			for i:=len(raws)-1;i>=0;i-- { sequence=append(sequence,cxHash(raws[i])) }
			cxEqual(t,"COLD_BOUND exact backward sequence",source.reads,sequence)
			cxEqual(t,"read bytes",len(source.reads)*148,count*148)
			var added [][32]byte
			for i:=idx+1;i<len(raws);i++ { added=append(added,cxHash(raws[i])) }
			added=append(added,cxHash(child))
			cxEqual(t,"COLD_C1_SUFFIX",pub.Added,added)
			for i,hash:=range added {
				c1,ok:=o.LookupV1(hash)
				if !ok || c1.External!=(i==0) || c1.Height!=tc.anchor+uint64(i)+1 || c1.Work.Cmp(new(big.Int).SetUint64(c1.Height+1))!=0 {
					t.Fatalf("COLD_C1_SUFFIX member %d: %+v %v",i,c1,ok)
				}
			}
			if tc.base==0 {
				times:=make([]uint64,len(raws)); for i:=range times {times[i]=10+uint64(i)}
				o2,p,s2:=cxWarm(t,times)
				kind:=HeaderContextAdmitted148V1; if p.Height==0 {kind=HeaderContextCanonical148V1}
				warm,_:=cxPublish(t,o2,cxInput(p.View,child,cxProof(p,kind),s2))
				expectedWarmView:=p.View;expectedWarmView.Version=p.View.Version+1
				cxEqual(t,"warm View independent of cold output",warm.View,expectedWarmView)
				warm.View=r.View
				cxEqual(t,"cold/warm full equivalence",r,warm)
			}
		})
	}
	// Each malformed local suffix is read exactly once and can never become an incoming mismatch.
	for _, defect:=range []string{"range","pow","target","old","future","wrong-hash","absent"} {
		t.Run("local-"+defect,func(t *testing.T) {
			genesis:=cxMine([32]byte{},10,cxTarget(255))
			o,v,s:=cxNew(t,cxLimits(),hcLim(),genesis)
			parent:=cxMine(cxHash(genesis),11,cxTarget(255))
			switch defect {
			case "range": clear(parent[76:108])
			case "pow": parent=cxBadPoW(parent,cxTarget(0))
			case "target": parent=cxMine(cxHash(genesis),11,cxTarget(127))
			case "old": parent=cxMine(cxHash(genesis),10,cxTarget(255))
			case "future": parent=cxMine(cxHash(genesis),7211,cxTarget(255))
			}
			child:=cxMine(cxHash(parent),12,cxTarget(255))
			s.raws[cxHash(parent)]=parent
			if defect=="wrong-hash" {s.raws[cxHash(parent)]=genesis}
			if defect=="absent" {delete(s.raws,cxHash(parent))}
			a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:genesis,Hash:cxHash(genesis),Work:big.NewInt(1),Provenance:[32]byte{9}}
			outcome:=uint8(4); if defect=="absent" {outcome=2}
			cxRefuse(t,"SUFFIX_LOCAL_INCONSISTENT",o,cxCold(v,child,a,1,s),outcome,0,0,nil)
			wantReads:=2; if defect=="range" || defect=="pow" || defect=="wrong-hash" || defect=="absent" {wantReads=1}
			cxEqual(t,"COLD_NO_RETRY",len(s.reads),wantReads)
		})
	}
	// The point source returns exactly the requested branch; its anchor slot still disagrees.
	genesis:=cxMine([32]byte{},0,cxTarget(255))
	a1,b1:=cxMine(cxHash(genesis),1,cxTarget(255)),cxMine(cxHash(genesis),2,cxTarget(255))
	o,v,s:=cxNew(t,cxLimits(),hcLim(),genesis)
	s.raws[cxHash(a1)],s.raws[cxHash(b1)]=a1,b1
	a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:a1,Hash:cxHash(a1),Height:1,Work:big.NewInt(2),Provenance:[32]byte{9}}
	cxRefuse(t,"exact hash on wrong anchor branch",o,cxCold(v,cxMine(cxHash(b1),3,cxTarget(255)),a,0,s),4,0,0,nil)
	cxEqual(t,"anchor disagreement stops at first observation",s.reads,[][32]byte{cxHash(b1)})
	for _,field:=range []string{"Work","Height","Provenance"} {
		o,v,s=cxNew(t,cxLimits(),hcLim(),genesis)
		s.raws[cxHash(a1)]=a1
		admitted:=HeaderCandidateRecord148V1{Raw:a1,Hash:cxHash(a1),Parent:cxHash(genesis),Height:1,Work:big.NewInt(2),Provenance:[32]byte{9},External:true}
		switch field {case "Work":admitted.Work=big.NewInt(3);case "Height":admitted.Height=2;case "Provenance":admitted.Provenance=[32]byte{10}}
		pub,out:=hcPublish(t,o,hcTr(o,[]HeaderCandidateRecord148V1{admitted}));if out!=0{t.Fatal(out)}
		v.Version=pub.Version
		anchor:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:genesis,Hash:cxHash(genesis),Work:big.NewInt(1),Provenance:[32]byte{9}}
		cxRefuse(t,"admitted suffix conflicting "+field,o,cxCold(v,cxMine(cxHash(a1),2,cxTarget(255)),anchor,1,s),4,0,0,nil)
		cxEqual(t,"admitted suffix exact single pass",s.reads,[][32]byte{cxHash(a1),cxHash(genesis)})
	}
}

func TestHeaderContext148Work(t *testing.T) {
	for _, power:=range []uint{64,256,300} {
		anchorHeight:=uint64(10080)*(1<<40)
		raws,source:=cxChain(anchorHeight-10,11,10,1,cxTarget(255),false)
		genesis:=cxMine([32]byte{},0,cxTarget(255))
		o,v,_:=cxNew(t,cxLimits(),hcLim(),genesis)
		work:=new(big.Int).Lsh(big.NewInt(1),power)
		a:=HeaderContextAnchor148V1{Kind:HeaderContextAcceptedTarget148V1,Raw:raws[10],Hash:cxHash(raws[10]),Height:anchorHeight,Work:work,Provenance:[32]byte{9}}
		child:=cxMine(a.Hash,121*(anchorHeight-10)+21,cxTarget(255))
		in:=cxCold(v,child,a,0,source)
		r,_:=cxPublish(t,o,in)
		cxEqual(t,"WORK_EXACT",r.Work,new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1),power),big.NewInt(1)))
		cxEqual(t,"ANCHOR_ACTUAL_WORK input unchanged",work,new(big.Int).Lsh(big.NewInt(1),power))
	}
	o,p,s:=cxWarm(t,[]uint64{10,20})
	child:=cxMine(p.Hash,21,cxTarget(255))
	in:=cxInput(p.View,child,cxProof(p,HeaderContextAdmitted148V1),s)
	hash:=cxHash(child)
	for _,tc:=range []struct{name string; work int64; hash [32]byte; height uint64; out uint8}{
		{"below",2,[32]byte{42},1,0},{"above",4,[32]byte{42},3,7},
		{"equal",3,hash,2,7},{"smaller-hash",3,cxTarget(255),2,0},{"larger-hash",3,[32]byte{},2,7},
		{"H+2",1,in.View.Genesis,0,0},
	} {
		t.Run(tc.name,func(t *testing.T) {
			x:=in; x.Tip.Work=big.NewInt(tc.work); x.Tip.Hash=tc.hash; x.Tip.Height=tc.height
			if tc.out!=0 {cxRefuse(t,"WORK_HASH_ORDER/ELIGIBILITY_OVERFLOW",o,x,tc.out,0,0,nil);return}
			h,d:=o.PrepareContextV1(x);cxDecision(t,"rank",d,0,0,0,nil)
			cxDecision(t,"rank abort",h.AbortV1(),0,0,0,nil);cxClean(t,o,false)
		})
	}
	o,p,s=cxWarm(t,[]uint64{10,20,30})
	in=cxInput(p.View,cxMine(p.Hash,31,cxTarget(255)),cxProof(p,HeaderContextAdmitted148V1),s)
	in.Tip.Height,in.Tip.Hash,in.Tip.Work=0,in.View.Genesis,big.NewInt(1)
	cxRefuse(t,"ELIGIBILITY_HEIGHT H+3",o,in,7,0,0,nil)
	in.Tip.Height,in.Tip.Hash,in.Tip.Work=math.MaxUint64,[32]byte{42},new(big.Int).Lsh(big.NewInt(1),64)
	cxRefuse(t,"ELIGIBILITY_OVERFLOW",o,in,5,0,0,nil)
}

type cxNilError struct{}
func (*cxNilError) Error() string { return "typed nil source error" }

func TestHeaderContext148Outcomes(t *testing.T) {
	for _, tc:=range []struct{name string; change func(*HeaderContextInput148V1); out,sub uint8}{
		{"neither",func(in *HeaderContextInput148V1){in.WarmParent=nil},2,0},
		{"both",func(in *HeaderContextInput148V1){in.ColdParent=&HeaderContextCold148V1{Missing:true}},4,0},
		{"missing",func(in *HeaderContextInput148V1){in.WarmParent=nil;in.ColdParent=&HeaderContextCold148V1{Missing:true}},1,0},
		{"missing-suffix",func(in *HeaderContextInput148V1){in.WarmParent=nil;in.ColdParent=&HeaderContextCold148V1{Missing:true,Suffix:1}},4,0},
		{"missing-extra",func(in *HeaderContextInput148V1){in.ColdParent=&HeaderContextCold148V1{Missing:true,Anchor:*in.WarmParent};in.WarmParent=nil},4,0},
		{"unknown-kind",func(in *HeaderContextInput148V1){in.WarmParent.Kind=4},4,0},
		{"zero-kind",func(in *HeaderContextInput148V1){in.WarmParent.Kind=0},4,0},
		{"nil-work",func(in *HeaderContextInput148V1){in.WarmParent.Work=nil},4,0},
		{"zero-work",func(in *HeaderContextInput148V1){in.WarmParent.Work.SetInt64(0)},4,0},
		{"negative-work",func(in *HeaderContextInput148V1){in.WarmParent.Work.SetInt64(-1)},4,0},
		{"work-domain",func(in *HeaderContextInput148V1){in.WarmParent.Work.Lsh(big.NewInt(1),512)},5,0},
		{"zero-provenance",func(in *HeaderContextInput148V1){in.WarmParent.Provenance=[32]byte{}},4,0},
		{"wrong-provenance",func(in *HeaderContextInput148V1){in.WarmParent.Provenance=[32]byte{12}},4,0},
		{"wrong-hash",func(in *HeaderContextInput148V1){in.WarmParent.Hash=[32]byte{1}},4,0},
		{"wrong-height",func(in *HeaderContextInput148V1){in.WarmParent.Height=1},4,0},
		{"successor-overflow",func(in *HeaderContextInput148V1){in.WarmParent.Height=math.MaxUint64},5,0},
		{"warm-miss",func(in *HeaderContextInput148V1){a:=cxMine(in.View.Genesis,11,cxTarget(255));in.WarmParent.Raw=a;in.WarmParent.Hash=cxHash(a);in.WarmParent.Height=1;in.WarmParent.Work=big.NewInt(2);in.Tip.Hash=cxHash(a);in.Tip.Height=1;in.Tip.Work=big.NewInt(2)},2,0},
		{"admitted-absent",func(in *HeaderContextInput148V1){in.WarmParent.Kind=HeaderContextAdmitted148V1},4,0},
		{"nil-source",func(in *HeaderContextInput148V1){in.Source=nil},2,0},
		{"typed-nil-source",func(in *HeaderContextInput148V1){var source *cxSource;in.Source=source},3,0},
		{"incarnation-zero",func(in *HeaderContextInput148V1){in.View.Incarnation=0},4,0},
		{"incarnation-stale",func(in *HeaderContextInput148V1){in.View.Incarnation++},3,0},
		{"version-zero",func(in *HeaderContextInput148V1){in.View.Version=0},4,0},
		{"version-stale",func(in *HeaderContextInput148V1){in.View.Version++},3,0},
		{"source-zero",func(in *HeaderContextInput148V1){in.View.Source=[32]byte{}},4,0},
		{"source-stale",func(in *HeaderContextInput148V1){in.View.Source=[32]byte{2}},3,0},
		{"authority-zero",func(in *HeaderContextInput148V1){in.View.Authority=[32]byte{};in.Tip.Authority=[32]byte{}},4,0},
		{"network",func(in *HeaderContextInput148V1){in.View.Network=[32]byte{1}},4,0},
		{"genesis",func(in *HeaderContextInput148V1){in.View.Genesis=[32]byte{1}},4,0},
		{"tip-nil",func(in *HeaderContextInput148V1){in.Tip.Work=nil},4,0},
		{"tip-zero",func(in *HeaderContextInput148V1){in.Tip.Work=big.NewInt(0)},4,0},
		{"tip-negative",func(in *HeaderContextInput148V1){in.Tip.Work=big.NewInt(-1)},4,0},
		{"tip-large",func(in *HeaderContextInput148V1){in.Tip.Work=new(big.Int).Lsh(big.NewInt(1),512)},5,0},
		{"tip-authority",func(in *HeaderContextInput148V1){in.Tip.Authority=[32]byte{1}},4,0},
		{"tip-provenance",func(in *HeaderContextInput148V1){in.Tip.Provenance=[32]byte{}},4,0},
		{"tip-anchor-height",func(in *HeaderContextInput148V1){in.Tip.Height++},4,0},
		{"tip-anchor-work",func(in *HeaderContextInput148V1){in.Tip.Work.Add(in.Tip.Work,big.NewInt(1))},4,0},
		{"tip-anchor-before-stale",func(in *HeaderContextInput148V1){in.Tip.Height++;in.View.Version++},4,0},
		{"target-zero",func(in *HeaderContextInput148V1){clear(in.Raw[76:108])},6,1},
		{"pow",func(in *HeaderContextInput148V1){in.Raw=cxBadPoW(in.Raw,[32]byte{1})},6,2},
		{"linkage",func(in *HeaderContextInput148V1){in.Raw=cxMine([32]byte{2},11,cxTarget(255))},6,3},
		{"target",func(in *HeaderContextInput148V1){in.Raw=cxMine(in.WarmParent.Hash,11,cxTarget(127))},6,4},
		{"floor",func(in *HeaderContextInput148V1){in.Raw=cxMine(in.WarmParent.Hash,10,cxTarget(255))},6,5},
		{"ceiling",func(in *HeaderContextInput148V1){in.Raw=cxMine(in.WarmParent.Hash,7211,cxTarget(255))},6,6},
		{"mixed-link-target-time",func(in *HeaderContextInput148V1){in.Raw=cxMine([32]byte{2},10,cxTarget(127))},6,3},
		{"mixed-target-time",func(in *HeaderContextInput148V1){in.Raw=cxMine(in.WarmParent.Hash,10,cxTarget(127))},6,4},
		{"shape-before-stale",func(in *HeaderContextInput148V1){in.WarmParent.Kind=4;in.View.Version++},4,0},
	} {
		t.Run(tc.name,func(t *testing.T){
			o,p,s:=cxWarm(t,[]uint64{10})
			in:=cxInput(p.View,cxMine(p.Hash,11,cxTarget(255)),cxProof(p,HeaderContextCanonical148V1),s)
			tc.change(&in)
			cxRefuse(t,"MIXED_ORDER/"+tc.name,o,in,tc.out,tc.sub,0,nil)
		})
	}
	direct:=errors.New("source direct")
	wrapped:=fmt.Errorf("source wrapped: %w",direct)
	var typed *cxNilError
	for _,cause:=range []error{nil,direct,wrapped,typed} {
		for _,current:=range []bool{false,true} {
			for _,operation:=range []string{"seed","rebind","prepare","publish"} {
				t.Run(fmt.Sprintf("current-%s-%v-%T",operation,current,cause),func(t *testing.T){
					genesis:=cxMine([32]byte{},10,cxTarget(255));o,v,s:=cxNew(t,cxLimits(),hcLim(),genesis)
					p:=cxSeed(t,o,v,genesis,s)
					in:=cxInput(v,cxMine(p.Hash,11,cxTarget(255)),cxProof(p,HeaderContextCanonical148V1),s)
					retainedBefore:=cxState(o)
					var h *HeaderContextPrepared148V1
					if operation == "publish" {
						var d HeaderContextDecision148V1
						h, d = o.PrepareContextV1(in)
						cxDecision(t, "setup", d, 0, 0, 0, nil)
					}
					s.current=func()(bool,error){return current,cause}
					want := uint8(0)
					if !current {
						want = 3
					} else if cause != nil {
						want = 2
					}
					before:=cxState(o)
					var d HeaderContextDecision148V1
					switch operation {
					case "seed":
						d = o.SeedGenesisContextV1(v, genesis, [32]byte{9}, s)
					case "rebind":
						var r HeaderContextRecord148V1
						r, d = o.RebindContextV1(v, *in.WarmParent, s)
						if want != 0 {
							cxEqual(t, "rebind zero", r, HeaderContextRecord148V1{})
						}
					case "prepare":
						h, d = o.PrepareContextV1(in)
						if want != 0 && h != nil {
							t.Fatal("failure handle")
						}
						if h != nil {
							cxDecision(t, "abort", h.AbortV1(), 0, 0, 0, nil)
						}
					case "publish":
						r, pub, result := h.PublishV1()
						d = result
						if want != 0 {
							cxEqual(t, "publish zero record", r, HeaderContextRecord148V1{})
							cxEqual(t, "publish zero receipt", pub, HeaderCandidatePublication148V1{})
						}
					}
					cxDecision(t,"Current exact",d,want,0,0,cause)
					cxClean(t,o,false)
					if operation!="publish" {cxEqual(t,"Current unchanged",cxState(o),before)}
					if operation=="publish" && want!=0 {cxEqual(t,"publication refusal unchanged retained state",cxState(o),retainedBefore)}
					s.current=nil
					if operation != "publish" || want != 0 {
						next, result := o.PrepareContextV1(in)
						cxDecision(t, "next legal operation", result, 0, 0, 0, nil)
						next.AbortV1()
					}
				})
			}
		}
	}
	for _,status:=range []HeaderContextRead148V1{0,1,2,3,4,255} {
		for _,readError:=range []error{nil,direct,wrapped,typed} {
			t.Run(fmt.Sprintf("read-%d-%T",status,readError),func(t *testing.T){
				genesis:=cxMine([32]byte{},10,cxTarget(255));o,v,s:=cxNew(t,cxLimits(),hcLim(),genesis)
				a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:genesis,Hash:cxHash(genesis),Work:big.NewInt(1),Provenance:[32]byte{9}}
				in:=cxCold(v,cxMine(a.Hash,11,cxTarget(255)),a,0,s)
				s.read=func(_ [32]byte,dst *[148]byte)(HeaderContextRead148V1,error){*dst=genesis;return status,readError}
				want := uint8(4)
				switch status {
				case 0:
					want = 0
				case 1:
					want = 2
				case 2:
					want = 3
				}
				if readError != nil {
					want = 2
				}
				if want != 0 {
					cxRefuse(t, "COLD_NO_RETRY", o, in, want, 0, 0, readError)
				} else {
					h, d := o.PrepareContextV1(in)
					cxDecision(t, "read present", d, 0, 0, 0, nil)
					h.AbortV1()
				}
				cxEqual(t,"one observation",s.reads,[][32]byte{a.Hash})
			})
		}
	}
	cxSourceFailures(t)
}

func cxBadPoW(raw [148]byte,target [32]byte) [148]byte {
	copy(raw[76:108],target[:])
	for nonce:=uint64(0);;nonce++ {
		binary.LittleEndian.PutUint64(raw[140:],nonce)
		hash:=cxHash(raw)
		if bytes.Compare(hash[:],target[:])>=0 {return raw}
	}
}

func cxSourceFailures(t *testing.T) {
	e1,e2:=errors.New("Header E1"),errors.New("Current E2")
	for _,headerError:=range []error{nil,e1} {
		for _,fresh:=range []bool{true,false} {
			t.Run(fmt.Sprintf("SOURCE_CAUSE_FIRST-%v-%v",headerError!=nil,fresh),func(t *testing.T){
				genesis:=cxMine([32]byte{},10,cxTarget(255));o,v,s:=cxNew(t,cxLimits(),hcLim(),genesis)
				a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:genesis,Hash:cxHash(genesis),Work:big.NewInt(1),Provenance:[32]byte{9}}
				read:=false
				s.current=func()(bool,error){if read{return fresh,e2};return true,nil}
				s.read=func(_ [32]byte,dst *[148]byte)(HeaderContextRead148V1,error){read=true;*dst=genesis;return HeaderContextReadInconsistent148V1,headerError}
				cause:=e2;if headerError!=nil {cause=headerError};out:=uint8(2);if !fresh {out=3}
				cxRefuse(t,"SOURCE_CAUSE_FIRST",o,cxCold(v,cxMine(a.Hash,11,cxTarget(255)),a,0,s),out,0,0,cause)
				cxEqual(t,"no second read",len(s.reads),1)
			})
		}
	}
	for _,phase:=range []string{"before","between","after","publish"} {
		t.Run("STALE_NO_EFFECT-"+phase,func(t *testing.T){
			raws,s:=cxChain(0,3,10,1,cxTarget(255),false)
			o,v,_:=cxNew(t,cxLimits(),hcLim(),raws[0])
			a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:raws[0],Hash:cxHash(raws[0]),Work:big.NewInt(1),Provenance:[32]byte{9}}
			in:=cxCold(v,cxMine(cxHash(raws[2]),13,cxTarget(255)),a,2,s)
			stale:=false
			if phase=="before" {stale=true}
			threshold:=1;if phase=="after" {threshold=3}
			s.current=func()(bool,error){return !stale,nil}
			s.read=func(hash [32]byte,dst *[148]byte)(HeaderContextRead148V1,error){*dst=s.raws[hash];if len(s.reads)==threshold && phase!="publish" {stale=true};return HeaderContextPresent148V1,nil}
			if phase=="publish" {
				retainedBefore:=cxState(o)
				h,d:=o.PrepareContextV1(in);cxDecision(t,"fresh prepare",d,0,0,0,nil);stale=true
				r,pub,d:=h.PublishV1();cxDecision(t,"stale publish",d,3,0,0,nil);cxEqual(t,"stale output",r,HeaderContextRecord148V1{});cxEqual(t,"stale receipt",pub,HeaderCandidatePublication148V1{});cxClean(t,o,false)
				cxEqual(t,"prepublish stale retained state",cxState(o),retainedBefore)
			}else{cxRefuse(t,"stale cold",o,in,3,0,0,nil)}
			reads:=threshold;if phase=="before" {reads=0};if phase=="publish" {reads=3}
			cxEqual(t,"no read after stale",len(s.reads),reads)
		})
	}
	for _,phase:=range []string{"current","header","publish"} {
		for _,closeOwner:=range []bool{false,true} {
			t.Run(fmt.Sprintf("SOURCE_PANIC-%s-close%v",phase,closeOwner),func(t *testing.T){
				genesis:=cxMine([32]byte{},10,cxTarget(255));l:=cxLimits();l.MaxRecords=1
				o,v,s:=cxNew(t,l,hcLim(),genesis);p:=cxSeed(t,o,v,genesis,s)
				retainedBefore:=cxState(o)
				in:=cxInput(p.View,cxMine(p.Hash,11,cxTarget(255)),cxProof(p,HeaderContextCanonical148V1),s)
				marker:=&struct{phase string}{phase}
				panicFn := func() {
					if closeOwner {
						o.CloseV1()
					}
					panic(marker)
				}
				var h *HeaderContextPrepared148V1
				if phase == "publish" {
					var d HeaderContextDecision148V1
					h, d = o.PrepareContextV1(in)
					cxDecision(t, "panic prepare", d, 0, 0, 0, nil)
				}
				if phase == "header" {
					in = cxCold(p.View, in.Raw, *in.WarmParent, 0, s)
					s.read = func([32]byte, *[148]byte) (HeaderContextRead148V1, error) {
						panicFn()
						return 0, nil
					}
				} else {
					s.current = func() (bool, error) {
						panicFn()
						return true, nil
					}
				}
				func() {
					defer func() {
						if got := recover(); got != marker {
							t.Fatalf("SOURCE_PANIC identity: %v", got)
						}
					}()
					if h != nil {
						h.PublishV1()
					} else {
						o.PrepareContextV1(in)
					}
				}()
				cxClean(t,o,false)
				if phase=="publish" && closeOwner && o.prepared==nil {t.Fatal("C1 Close must retain its historical prepared slot")}
				if h!=nil && (h.reservation.record.Work!=nil || h.reservation.record.LastClampedTimestamp!=nil || h.reservation.victims!=nil || h.reservation.source!=nil) {t.Fatal("CLEANUP_CLOSE staged payload/capability retained")}
				if !closeOwner {cxEqual(t,"panic retained state unchanged",cxState(o),retainedBefore)}else if len(o.recs)!=0 || o.VersionV1()!=2 {t.Fatal("panic rolled back or published through independent Close")}
				s.current,s.read=nil,nil
				if !closeOwner {
					next, d := o.PrepareContextV1(in)
					cxDecision(t, "PUBLISH_PANIC_ABORT next", d, 0, 0, 0, nil)
					next.AbortV1()
				} else {
					cxDecision(t, "closed remains closed", o.SeedGenesisContextV1(p.View, p.Raw, [32]byte{9}, s), 2, 0, 1, nil)
				}
			})
		}
	}
}

func TestHeaderContext148Limits(t *testing.T) {
	genesis:=cxMine([32]byte{},0,cxTarget(255))
	for _,tc:=range []struct{name string; bytes,scratch uint64; out uint8}{
		{"retained exact",1190,8<<20,0},{"retained one less",1189,8<<20,5},
		{"seed scratch exact",1<<20,5058,0},{"seed scratch one less",1<<20,5057,5},
	} {
		t.Run(tc.name,func(t *testing.T){
			l:=cxLimits();l.MaxBytes,l.MaxScratchBytes=tc.bytes,tc.scratch
			o,v,s:=cxNew(t,l,hcLim(),genesis)
			before:=cxState(o)
			cxDecision(t,"LOGICAL_BYTES/SCRATCH_EXACT",o.SeedGenesisContextV1(v,genesis,[32]byte{9},s),tc.out,0,0,nil)
			if tc.out!=0 {cxEqual(t,"seed refused unchanged",cxState(o),before)}else{
				cxEqual(t,"Q=542 B=1118",o.context.bytes,uint64(1118))
				cxEqual(t,"record exact count",len(o.context.records),1)
			}
			cxClean(t,o,false)
		})
	}
	for _,limit:=range []uint64{5502,5503,6300,6301} {
		l:=cxLimits();l.MaxScratchBytes=limit
		o,v,s:=cxNew(t,l,hcLim(),genesis);p:=cxSeed(t,o,v,genesis,s)
		in:=cxInput(v,cxMine(p.Hash,1,cxTarget(255)),cxProof(p,HeaderContextCanonical148V1),s)
		if limit==5502 {cxRefuse(t,"SCRATCH_EXACT warm S5503",o,in,5,0,0,nil);continue}
		h,d:=o.PrepareContextV1(in);cxDecision(t,"warm exact",d,0,0,0,nil)
		cxEqual(t,"S(0,1,1)=5503",o.context.scratch,uint64(5503))
		r,d:=o.LookupContextV1(v,p.Hash)
		out:=uint8(5);if limit==6301 {out=0}
		cxDecision(t,"OUTPUT_HANDOFF L798",d,out,0,0,nil)
		if out==5 {cxEqual(t,"lookup zero",r,HeaderContextRecord148V1{})}else{cxEqual(t,"lookup exact",r,p)}
		cxEqual(t,"lookup scratch released",o.context.scratch,uint64(5503))
		h.AbortV1();cxClean(t,o,false)
		r,d=o.LookupContextV1(v,p.Hash);cxDecision(t,"next lookup",d,0,0,0,nil);cxEqual(t,"next exact",r,p)
	}
	for _,tc:=range []struct{field string; exact,less uint64}{
		{"MaxReads",2,1},{"MaxReadBytes",296,295},{"MaxReadWork",2,1},{"MaxSuffix",1,0},
	} {
		for _,fit:=range []bool{true,false} {
			t.Run(fmt.Sprintf("%s-fit%v",tc.field,fit),func(t *testing.T){
				l:=cxLimits();value:=tc.exact;if !fit {value=tc.less}
				d:=uint64(1)
				if tc.field=="MaxSuffix" && !fit {value=1;d=2}
				reflect.ValueOf(&l).Elem().FieldByName(tc.field).SetUint(value)
				raws,s:=cxChain(0,int(d)+1,0,1,cxTarget(255),false)
				o,v,_:=cxNew(t,l,hcLim(),raws[0])
				a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:raws[0],Hash:cxHash(raws[0]),Work:big.NewInt(1),Provenance:[32]byte{9}}
				in:=cxCold(v,cxMine(cxHash(raws[d]),d+1,cxTarget(255)),a,d,s)
				if !fit {cxRefuse(t,"COLD_PRE_READ",o,in,5,0,0,nil);cxEqual(t,"zero reads",len(s.reads),0)}else{cxPublish(t,o,in);cxEqual(t,"exact reads",len(s.reads),2)}
			})
		}
	}
	for _,limit:=range []uint64{1,2} {
		raws,s:=cxChain(0,2,0,1,cxTarget(255),false)
		cl:=hcLim();cl.MaxTransitionHeaders=limit
		o,v,_:=cxNew(t,cxLimits(),cl,raws[0])
		a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:raws[0],Hash:cxHash(raws[0]),Work:big.NewInt(1),Provenance:[32]byte{9}}
		in:=cxCold(v,cxMine(cxHash(raws[1]),2,cxTarget(255)),a,1,s)
		if limit==1 {cxRefuse(t,"C1 A before copy/read",o,in,5,0,0,nil);cxEqual(t,"no reads",len(s.reads),0)}else{cxPublish(t,o,in)}
	}
	for _,height:=range []uint64{253,254,255} {
		l:=cxLimits();l.MaxWorkBytes=1
		raws,s:=cxChain(0,int(height)+1,0,1,cxTarget(255),false)
		o,v,_:=cxNew(t,l,hcLim(),raws[0])
		a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:raws[height],Hash:cxHash(raws[height]),Height:height,Work:new(big.Int).SetUint64(height+1),Provenance:[32]byte{9}}
		in:=cxCold(v,cxMine(a.Hash,height+1,cxTarget(255)),a,0,s)
		if height==253 {r,_:=cxPublish(t,o,in);cxEqual(t,"work exact one byte",r.Work,big.NewInt(255))}else{
			cxRefuse(t,"work one over",o,in,5,0,0,nil)
			want:=int(height)+1;if height==255 {want=0};cxEqual(t,"bounded work reads",len(s.reads),want)
		}
	}
	for _,field:=range []string{"MaxScratchBytes","MaxWorkBytes","MaxReadBytes"} {
		l:=cxLimits();reflect.ValueOf(&l).Elem().FieldByName(field).SetUint(math.MaxUint64-1)
		o,v,s:=cxNew(t,l,hcLim(),genesis)
		if field=="MaxWorkBytes" {cxDecision(t,"checked S overflow",o.SeedGenesisContextV1(v,genesis,[32]byte{9},s),5,0,0,nil);cxClean(t,o,false)}else{cxSeed(t,o,v,genesis,s)}
	}
	// Checked a+D/successor/N arithmetic is decided before any point observation.
	o,v,s:=cxNew(t,cxLimits(),hcLim(),genesis)
	a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:genesis,Hash:cxHash(genesis),Height:math.MaxUint64-1,Work:big.NewInt(1),Provenance:[32]byte{9}}
	in:=cxCold(v,cxMine(a.Hash,1,cxTarget(255)),a,2,s);in.Tip.Hash=[32]byte{42}
	cxRefuse(t,"height sum overflow",o,in,5,0,0,nil)
	cxEqual(t,"overflow no reads",len(s.reads),0)
}

func TestHeaderContext148Configuration(t *testing.T) {
	valid:=cxLimits();genesis:=cxMine([32]byte{},0,cxTarget(255));hash:=cxHash(genesis)
	minimum:=valid;minimum.MaxBytes=512
	empty,minimumError:=NewHeaderCandidateContext148V1(hcLim(),minimum,7,[32]byte{1},hash)
	if minimumError!=nil || empty==nil || empty.context.bytes!=512 {t.Fatal("fixed state exact constructor limit")}
	for i:=0;i<reflect.TypeOf(valid).NumField();i++ {
		for _,value:=range []uint64{0,math.MaxUint64} {
			l:=valid;reflect.ValueOf(&l).Elem().Field(i).SetUint(value)
			o,err:=NewHeaderCandidateContext148V1(hcLim(),l,7,[32]byte{1},hash)
			if o!=nil || err!=ErrHeaderContextConfig148V1 {t.Fatalf("limit %d=%d: %v %v",i,value,o,err)}
		}
	}
	for _,tc:=range []struct{bytes uint64;network,genesis [32]byte}{{511,[32]byte{1},hash},{512,[32]byte{},hash},{512,[32]byte{1},[32]byte{}}} {
		l:=valid;l.MaxBytes=tc.bytes
		o,err:=NewHeaderCandidateContext148V1(hcLim(),l,7,tc.network,tc.genesis)
		if o!=nil || err!=ErrHeaderContextConfig148V1 {t.Fatalf("config: %v %v",o,err)}
	}
	cl:=hcLim();cl.MaxHeaders=0
	o,err:=NewHeaderCandidateContext148V1(cl,HeaderContextLimits148V1{},0,[32]byte{},[32]byte{})
	if o!=nil || err!=ErrHeaderCandidateConfig148V1 {t.Fatalf("C1 identity first: %v %v",o,err)}
	o,err=NewHeaderCandidateOwner148V1(hcLim(),7)
	if err!=nil || o.context!=nil {t.Fatalf("old constructor: %v",err)}
	hcEstablish(t,o)
	_,d:=o.LookupContextV1(HeaderContextView148V1{},hash);cxDecision(t,"old constructor no context",d,2,0,0,nil)
}

func TestHeaderContext148Pins(t *testing.T) {
	genesis:=cxMine([32]byte{},0,cxTarget(255))
	for _,limit:=range []uint64{1245,1246} {
		l:=cxLimits();l.MaxBytes=limit
		o,v,s:=cxNew(t,l,hcLim(),genesis);p:=cxSeed(t,o,v,genesis,s)
		before:=cxState(o)
		lease,d:=o.PinContextV1(v,p.Hash)
		if limit==1245 {cxDecision(t,"LEASE_BYTES one less",d,5,0,0,nil);if lease!=nil{t.Fatal("refused lease")};cxEqual(t,"pin refused unchanged",cxState(o),before);continue}
		cxDecision(t,"LEASE_BYTES exact",d,0,0,0,nil)
		cxEqual(t,"B=1246",o.context.bytes,uint64(1246));cxEqual(t,"external no C1 lease",o.leases,uint64(0))
		lease.ReleaseV1();lease.ReleaseV1();cxEqual(t,"RELEASE_ONCE",cxState(o),before)
	}
	l:=cxLimits();l.MaxPins=1
	o,v,s:=cxNew(t,l,hcLim(),genesis);p:=cxSeed(t,o,v,genesis,s)
	lease,d:=o.PinContextV1(v,p.Hash);cxDecision(t,"pin one",d,0,0,0,nil)
	before:=cxState(o)
	next,d:=o.PinContextV1(v,p.Hash);cxDecision(t,"pins one over",d,5,0,0,nil)
	if next!=nil {t.Fatal("pin over returned lease")};cxEqual(t,"pins unchanged",cxState(o),before)
	lease.ReleaseV1()
	l=cxLimits();l.MaxRecords=1
	o,v,s=cxNew(t,l,hcLim(),genesis);p=cxSeed(t,o,v,genesis,s)
	in:=cxInput(v,cxMine(p.Hash,1,cxTarget(255)),cxProof(p,HeaderContextCanonical148V1),s)
	lease,d=o.PinContextV1(v,p.Hash);cxDecision(t,"protect cache",d,0,0,0,nil)
	cxRefuse(t,"PIN_SURVIVES",o,in,5,0,0,nil)
	lease.ReleaseV1()
	h,d:=o.PrepareContextV1(in);cxDecision(t,"one victim prepared",d,0,0,0,nil)
	calls:=s.calls
	next,d=o.PinContextV1(v,p.Hash);cxDecision(t,"RESERVED_VICTIM",d,5,0,0,nil);if next!=nil{t.Fatal("victim pin")}
	cxDecision(t,"RESERVATION_BUSY seed",o.SeedGenesisContextV1(v,genesis,[32]byte{9},s),5,0,0,nil)
	_,d=o.RebindContextV1(v,*in.WarmParent,s);cxDecision(t,"RESERVATION_BUSY rebind",d,5,0,0,nil)
	other,d:=o.PrepareContextV1(in);cxDecision(t,"RESERVATION_BUSY prepare",d,5,0,0,nil);if other!=nil{t.Fatal("second reservation")}
	cxEqual(t,"busy no source call",s.calls,calls);cxEqual(t,"victim no C1 lease",o.leases,uint64(0))
	h.AbortV1();cxClean(t,o,false)
	lease,d=o.PinContextV1(v,p.Hash);cxDecision(t,"victim restored after abort",d,0,0,0,nil);lease.ReleaseV1()
	r,pub:=cxPublish(t,o,in)
	_,d=o.LookupContextV1(r.View,p.Hash);cxDecision(t,"CACHE_VERSION cache miss",d,2,0,0,nil)
	missingLease,d:=o.PinContextV1(r.View,p.Hash);cxDecision(t,"pin cache miss",d,2,0,0,nil);if missingLease!=nil{t.Fatal("pin miss lease")}
	if pub.Version!=3 || len(o.recs)!=1 || len(o.context.records)!=1 {t.Fatalf("cache eviction changed admitted semantics: %+v",pub)}
	cxEqual(t,"immutable child after parent eviction",r.RawTimestamps,[11]uint64{1,0})
	// An admitted context takes the real C1 lease and protects received ancestry after a version advance.
	o,p,s=cxWarm(t,[]uint64{0,1,2})
	lease,d=o.PinContextV1(p.View,p.Hash);cxDecision(t,"candidate dependency",d,0,0,0,nil)
	if o.leases!=1 {t.Fatal("CANDIDATE_DEPENDENCY absent")}
	child:=cxMine(p.Hash,3,cxTarget(255));r,_=cxPublish(t,o,cxInput(p.View,child,cxProof(p,HeaderContextAdmitted148V1),s))
	var first [32]byte;copy(first[:],p.Raw[4:36])
	tr:=hcTr(o,nil,first,p.Hash,r.Hash)
	candidate,out:=o.PrepareV1(tr);if candidate!=nil || out!=10 {t.Fatalf("dependency ancestor protection: %d",out)}
	version:=o.VersionV1();lease.ReleaseV1();lease.ReleaseV1();cxEqual(t,"lease release no version",o.VersionV1(),version)
	candidate,out=o.PrepareV1(tr)
	if out!=0 {t.Fatalf("released dependency: %d",out)}
	retirement,out:=candidate.PublishV1()
	if out!=0 {t.Fatalf("released dependency publication: %d",out)}
	cxEqual(t,"explicit retirement receipt",retirement,HeaderCandidatePublication148V1{Changed:true,Version:version+1,Added:[][32]byte{},Retired:[][32]byte{first,p.Hash,r.Hash}})
	freshView:=r.View;freshView.Version=retirement.Version
	_,d=o.LookupContextV1(freshView,p.Hash);cxDecision(t,"explicit retirement removes derived context",d,2,0,0,nil)
	// C1 planned removal and C1 lease capacity preserve their exact reason after provisional C2 rollback.
	for _,reason:=range []uint8{10,12} {
		cl:=hcLim();cl.MaxLeases=1
		o,v,s=cxNew(t,cxLimits(),cl,genesis);parent:=cxSeed(t,o,v,genesis,s)
		p,_=cxPublish(t,o,cxInput(v,cxMine(parent.Hash,1,cxTarget(255)),cxProof(parent,HeaderContextCanonical148V1),s))
		var pending *HeaderCandidatePrepared148V1;var c1lease *HeaderCandidateLease148V1
		if reason==10 {pending,out=o.PrepareV1(hcTr(o,nil,p.Hash));if out!=0{t.Fatal(out)}}else{c1lease,out=o.AcquireDependencyV1(p.Hash);if out!=0{t.Fatal(out)}}
		before=cxState(o);next,d=o.PinContextV1(p.View,p.Hash);cxDecision(t,"C1 pin refusal",d,5,0,reason,nil)
		if next!=nil{t.Fatal("C1 refused pin handle")};cxEqual(t,"C1 pin refusal unchanged",cxState(o),before)
		if pending!=nil{pending.AbortV1()};if c1lease!=nil{c1lease.ReleaseV1()}
		lease,d=o.PinContextV1(p.View,p.Hash);cxDecision(t,"pin next operation",d,0,0,0,nil);lease.ReleaseV1()
	}
	for _,limit:=range []uint64{2530,2531} {
		l=cxLimits();l.MaxBytes=limit
		o,v,s=cxNew(t,l,hcLim(),genesis);root:=cxSeed(t,o,v,genesis,s)
		p,_=cxPublish(t,o,cxInput(v,cxMine(root.Hash,1,cxTarget(255)),cxProof(root,HeaderContextCanonical148V1),s))
		root,d=o.RebindContextV1(p.View,*cxProof(root,HeaderContextCanonical148V1),s);cxDecision(t,"fresh nonvictim",d,0,0,0,nil)
		h,d=o.PrepareContextV1(cxInput(p.View,cxMine(p.Hash,2,cxTarget(255)),cxProof(p,HeaderContextAdmitted148V1),s));cxDecision(t,"staged bytes",d,0,0,0,nil)
		lease,d=o.PinContextV1(p.View,root.Hash)
		out:=uint8(5);if limit==2531 {out=0};cxDecision(t,"STAGED_BYTES",d,out,0,0,nil)
		if limit==2530 && lease!=nil {t.Fatal("staged bytes consumed")}
		h.AbortV1();if lease!=nil {lease.ReleaseV1()};cxClean(t,o,false)
		cxEqual(t,"staged pin counters released",o.context.bytes,uint64(1725))
	}
	cxConcurrentPins(t)
	// More than one eligible victim proves the exact ascending-hash choice.
	l=cxLimits();l.MaxRecords=3
	o,v,s=cxNew(t,l,hcLim(),genesis);root:=cxSeed(t,o,v,genesis,s)
	a,_:=cxPublish(t,o,cxInput(v,cxMine(root.Hash,1,cxTarget(255)),cxProof(root,HeaderContextCanonical148V1),s))
	root,d=o.RebindContextV1(a.View,*cxProof(root,HeaderContextCanonical148V1),s);cxDecision(t,"victim parent fresh",d,0,0,0,nil)
	b,_:=cxPublish(t,o,cxInput(root.View,cxMine(root.Hash,2,cxTarget(255)),cxProof(root,HeaderContextCanonical148V1),s))
	for _,entry:=range []*HeaderContextRecord148V1{&root,&a} {
		kind:=HeaderContextAdmitted148V1;if entry.Hash==root.Hash{kind=HeaderContextCanonical148V1}
		*entry,d=o.RebindContextV1(b.View,*cxProof(*entry,kind),s);cxDecision(t,"victim fresh records",d,0,0,0,nil)
	}
	in=cxInput(b.View,cxMine(root.Hash,3,cxTarget(255)),cxProof(root,HeaderContextCanonical148V1),s)
	h,d=o.PrepareContextV1(in);cxDecision(t,"multiple victim choices",d,0,0,0,nil)
	keys:=[][32]byte{root.Hash,a.Hash,b.Hash};slices.SortFunc(keys,func(a,b [32]byte)int{return bytes.Compare(a[:],b[:])})
	cxEqual(t,"ascending reserved victim",h.reservation.victims,keys[:1])
	oldVersion:=o.VersionV1();h.AbortV1();cxClean(t,o,false)
	for _,hash:=range keys {_,d=o.LookupContextV1(b.View,hash);cxDecision(t,"abort evicted nothing",d,0,0,0,nil)}
	r,_=cxPublish(t,o,in)
	_,d=o.LookupContextV1(r.View,keys[0]);cxDecision(t,"exact victim eviction",d,2,0,0,nil)
	if o.VersionV1()!=oldVersion+1 || len(o.recs)!=3 {t.Fatal("cache victim altered C1 membership/version")}
}

func cxConcurrentPins(t *testing.T) {
	o,p,s:=cxWarm(t,[]uint64{0,1})
	genesis:=s.raws[p.View.Genesis]
	a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:genesis,Hash:p.View.Genesis,Work:big.NewInt(1),Provenance:[32]byte{9}}
	_,d:=o.RebindContextV1(p.View,a,s);cxDecision(t,"concurrent canonical rebind",d,0,0,0,nil)
	entered,proceed:=make(chan struct{}),make(chan struct{})
	var once sync.Once
	var resumed sync.Once
	resume:=func(){resumed.Do(func(){close(proceed)})}
	t.Cleanup(func(){resume();o.CloseV1()})
	s.read=func(hash [32]byte,dst *[148]byte)(HeaderContextRead148V1,error){
		once.Do(func(){close(entered);select {case <-proceed:case <-time.After(5*time.Second):t.Error("source point-read coordination timeout")}})
		*dst=s.raws[hash]
		return HeaderContextPresent148V1,nil
	}
	in:=cxCold(p.View,cxMine(p.Hash,2,cxTarget(255)),a,1,s)
	type prepared struct{handle *HeaderContextPrepared148V1;decision HeaderContextDecision148V1}
	done:=make(chan prepared,1)
	go func(){h,result:=o.PrepareContextV1(in);done<-prepared{h,result}}()
	select {case <-entered:case <-time.After(5*time.Second):t.Fatal("cold reservation did not reach first read")}
	before:=cxState(o)
	lease,d:=o.PinContextV1(p.View,p.Hash);cxDecision(t,"concurrent admitted pin",d,0,0,0,nil)
	copied,d:=o.LookupContextV1(p.View,p.Hash);cxDecision(t,"concurrent lookup",d,0,0,0,nil);cxEqual(t,"concurrent exact record",copied,p)
	lease.ReleaseV1();lease.ReleaseV1();cxEqual(t,"concurrent charge rollback",cxState(o),before)
	other,d:=o.PrepareContextV1(in);cxDecision(t,"concurrent single mutation",d,5,0,0,nil);if other!=nil{t.Fatal("concurrent reservation accepted")}
	resume()
	select {case result:=<-done:cxDecision(t,"first invocation survives pins",result.decision,0,0,0,nil);result.handle.AbortV1();case <-time.After(5*time.Second):t.Fatal("concurrent preparation did not finish")}
	cxClean(t,o,false)
}

func cxWaitConsumed(t *testing.T,h *HeaderCandidatePrepared148V1) {
	t.Helper()
	deadline:=time.NewTimer(5*time.Second);defer deadline.Stop()
	for {
		if h.owner.mu.TryLock() {
			consumed:=h.consumed
			h.owner.mu.Unlock()
			if consumed {return}
		}
		select {case <-deadline.C:t.Fatal("publication did not reach guarded terminal wait");return;default:}
		time.Sleep(time.Millisecond)
	}
}

func TestHeaderContext148Publication(t *testing.T) {
	o,p,s:=cxWarm(t,[]uint64{0})
	in:=cxInput(p.View,cxMine(p.Hash,1,cxTarget(255)),cxProof(p,HeaderContextCanonical148V1),s)
	h,d:=o.PrepareContextV1(in);cxDecision(t,"prepared",d,0,0,0,nil)
	_,ok:=o.LookupV1(cxHash(in.Raw));if ok {t.Fatal("prepared child admitted")}
	_,d=o.LookupContextV1(p.View,cxHash(in.Raw));cxDecision(t,"prepared context absent",d,2,0,0,nil)
	current,release:=o.ProtectV1(p.View.Version);if !current{t.Fatal("guard stale")}
	atomicOwner:=o
	t.Cleanup(func(){release();atomicOwner.CloseV1()})
	called,proceed:=make(chan struct{}),make(chan struct{})
	var resumed sync.Once
	resume:=func(){resumed.Do(func(){close(proceed)})}
	t.Cleanup(resume)
	s.current=func()(bool,error){
		close(called)
		if !o.mu.TryLock(){t.Error("source called under mu");return false,nil}
		o.mu.Unlock()
		select {case <-proceed:return true,nil;case <-time.After(5*time.Second):t.Error("source coordination timeout");return false,nil}
	}
	type result struct{record HeaderContextRecord148V1;pub HeaderCandidatePublication148V1;decision HeaderContextDecision148V1}
	done:=make(chan result,1)
	go func(){r,pub,d:=h.PublishV1();done<-result{r,pub,d}}()
	select {case <-called:case <-time.After(5*time.Second):t.Fatal("publication did not call protected source")}
	resume();cxWaitConsumed(t,h.candidate)
	if out:=h.candidate.AbortV1();out!=15 {t.Fatalf("second C1 terminal: %d",out)}
	// The actual C1 method returns its own outcome domain.
	if o.context.active==nil || o.context.scratch!=5503 {t.Fatal("Consumed observer released in-flight staged reservation")}
	select {case <-done:t.Fatal("PUBLISH_GUARD completed before guard release");default:}
	release()
	var got result
	select {case got=<-done:case <-time.After(5*time.Second):t.Fatal("PUBLISH_GUARD self-held guard")}
	cxDecision(t,"atomic publish",got.decision,0,0,0,nil)
	cxEqual(t,"RECEIPT_EFFECTS",got.pub,HeaderCandidatePublication148V1{Changed:true,Version:3,Added:[][32]byte{cxHash(in.Raw)},Retired:[][32]byte{}})
	cached,d:=o.LookupContextV1(got.record.View,got.record.Hash);cxDecision(t,"ATOMIC_CONTEXT",d,0,0,0,nil);cxEqual(t,"same committed context",cached,got.record)
	s.current=nil
	grandchild:=cxMine(got.record.Hash,2,cxTarget(255));cxPublish(t,o,cxInput(got.record.View,grandchild,cxProof(got.record,HeaderContextAdmitted148V1),s))
	// A cache-only eviction and identical C1 duplicate restore context without advancing Version.
	l:=cxLimits();l.MaxRecords=1;genesis:=p.Raw
	o,v,s:=cxNew(t,l,hcLim(),genesis);p=cxSeed(t,o,v,genesis,s)
	r,pub:=cxPublish(t,o,cxInput(v,in.Raw,cxProof(p,HeaderContextCanonical148V1),s))
	p=cxSeed(t,o,r.View,genesis,s)
	if _,ok=o.LookupV1(r.Hash);!ok {t.Fatal("cache eviction retired admitted header")}
	duplicate,receipt:=cxPublish(t,o,cxInput(p.View,in.Raw,cxProof(p,HeaderContextCanonical148V1),s))
	cxEqual(t,"duplicate unchanged receipt",receipt,HeaderCandidatePublication148V1{Version:pub.Version,Added:[][32]byte{},Retired:[][32]byte{}})
	cxEqual(t,"duplicate complete context",duplicate,r)
	// A real admitted anchor and an already admitted suffix are consumed without inventing External.
	o,p,s=cxWarm(t,[]uint64{0,1,2})
	var parentHash [32]byte;copy(parentHash[:],p.Raw[4:36]);parent,_:=o.LookupV1(parentHash)
	a:=HeaderContextAnchor148V1{Kind:HeaderContextAdmitted148V1,Raw:parent.Raw,Hash:parent.Hash,Height:parent.Height,Work:parent.Work,Provenance:parent.Provenance}
	child:=cxMine(p.Hash,3,cxTarget(255));r,receipt=cxPublish(t,o,cxCold(p.View,child,a,1,s))
	cxEqual(t,"admitted suffix omitted",receipt.Added,[][32]byte{r.Hash})
	c1,_:=o.LookupV1(r.Hash);if c1.External{t.Fatal("admitted anchor manufactured External")}
	// Actual C1 capacity reclamation is projected into context retirement and the unchanged receipt.
	genesis=cxMine([32]byte{},0,cxTarget(255));cl:=hcLim();cl.MaxHeaders=1
	l=cxLimits();l.MaxRecords=2
	o,v,s=cxNew(t,l,cl,genesis);p=cxSeed(t,o,v,genesis,s)
	firstRaw:=cxMine(p.Hash,1,cxTarget(255))
	for nonce:=uint64(0);;nonce++ {binary.LittleEndian.PutUint64(firstRaw[140:],nonce);hash:=cxHash(firstRaw);if bytes.Compare(hash[:],p.Hash[:])<0{break}}
	first,_:=cxPublish(t,o,cxInput(v,firstRaw,cxProof(p,HeaderContextCanonical148V1),s))
	p,d=o.RebindContextV1(first.View,*cxProof(p,HeaderContextCanonical148V1),s);cxDecision(t,"fresh canonical parent",d,0,0,0,nil)
	replacementRaw:=cxMine(p.Hash,2,cxTarget(255))
	for nonce:=uint64(0);;nonce++ {binary.LittleEndian.PutUint64(replacementRaw[140:],nonce);hash:=cxHash(replacementRaw);if bytes.Compare(hash[:],first.Hash[:])<0{break}}
	h,d=o.PrepareContextV1(cxInput(p.View,replacementRaw,cxProof(p,HeaderContextCanonical148V1),s))
	cxDecision(t,"overlap prepared",d,0,0,0,nil)
	cxEqual(t,"overlap reserved C2 victim",h.reservation.victims,[][32]byte{first.Hash})
	cxEqual(t,"overlap actual C1 retirement plan",h.candidate.plan.retired,[][32]byte{first.Hash})
	r,receipt,d=h.PublishV1();cxDecision(t,"overlap committed",d,0,0,0,nil);cxClean(t,o,false)
	cxEqual(t,"independent retirement no second charge removal",o.context.bytes,uint64(1725))
	cxEqual(t,"overlap retained record count",len(o.context.records),2)
	cxEqual(t,"RECEIPT_EFFECTS actual Retired",receipt,HeaderCandidatePublication148V1{Changed:true,Version:4,Added:[][32]byte{r.Hash},Retired:[][32]byte{first.Hash}})
	_,d=o.LookupContextV1(r.View,first.Hash);cxDecision(t,"retired derived record removed",d,2,0,0,nil)
	if _,ok=o.LookupV1(first.Hash);ok{t.Fatal("receipt retirement not actual C1 membership")}
}

func TestHeaderContext148Lifecycle(t *testing.T) {
	o,p,s:=cxWarm(t,[]uint64{0,1})
	old:=p
	c1,_:=o.LookupV1(p.Hash);c1.Provenance=[32]byte{10}
	tr:=hcTr(o,[]HeaderCandidateRecord148V1{c1});tr.NewSource=[32]byte{2}
	pub,out:=hcPublish(t,o,tr);if out!=0{t.Fatal(out)}
	v:=p.View;v.Version=pub.Version;v.Source=[32]byte{2};v.Authority=[32]byte{11}
	for _,view:=range []HeaderContextView148V1{p.View,v} {
		r,d:=o.LookupContextV1(view,p.Hash);cxDecision(t,"old stored View",d,3,0,0,nil);cxEqual(t,"stale record zero",r,HeaderContextRecord148V1{})
	}
	staleLease,d:=o.PinContextV1(v,p.Hash);cxDecision(t,"pin old stored View",d,3,0,0,nil);if staleLease!=nil{t.Fatal("stale pin lease")}
	proof:=*cxProof(p,HeaderContextAdmitted148V1);proof.Provenance=[32]byte{10}
	before:=cxState(o)
	r,d:=o.RebindContextV1(v,proof,nil);cxDecision(t,"REBIND_PROOF",d,2,0,0,nil);cxEqual(t,"unproved zero",r,HeaderContextRecord148V1{});cxEqual(t,"unproved unchanged",cxState(o),before)
	for _,tc:=range []struct{name string;change func(*HeaderContextView148V1,*HeaderContextAnchor148V1);out uint8}{
		{"incarnation",func(v *HeaderContextView148V1,_ *HeaderContextAnchor148V1){v.Incarnation++},3},
		{"network",func(v *HeaderContextView148V1,_ *HeaderContextAnchor148V1){v.Network=[32]byte{1}},4},
		{"genesis",func(v *HeaderContextView148V1,_ *HeaderContextAnchor148V1){v.Genesis=[32]byte{1}},4},
		{"source",func(v *HeaderContextView148V1,_ *HeaderContextAnchor148V1){v.Source=[32]byte{1}},3},
		{"work",func(_ *HeaderContextView148V1,a *HeaderContextAnchor148V1){a.Work=big.NewInt(3)},4},
		{"height",func(_ *HeaderContextView148V1,a *HeaderContextAnchor148V1){a.Height++},4},
		{"provenance",func(_ *HeaderContextView148V1,a *HeaderContextAnchor148V1){a.Provenance=[32]byte{9}},4},
		{"canonical-present",func(_ *HeaderContextView148V1,a *HeaderContextAnchor148V1){a.Kind=HeaderContextCanonical148V1},4},
	} {
		vv,aa:=v,proof;tc.change(&vv,&aa);r,d=o.RebindContextV1(vv,aa,s);cxDecision(t,tc.name,d,tc.out,0,0,nil);cxEqual(t,"rebind failure zero",r,HeaderContextRecord148V1{});cxEqual(t,"rebind failure unchanged",cxState(o),before)
	}
	r,d=o.RebindContextV1(v,proof,s);cxDecision(t,"rebound",d,0,0,0,nil)
	want:=old;want.View,want.Provenance=v,[32]byte{10}
	cxEqual(t,"REBIND_FIELDS full",r,want);cxEqual(t,"rebind no version",o.VersionV1(),pub.Version)
	child:=cxMine(r.Hash,2,cxTarget(255));cxPublish(t,o,cxInput(v,child,cxProof(r,HeaderContextAdmitted148V1),s))
	for _,terminal:=range []string{"Abort","Unknown","Close"} {
		t.Run(terminal,func(t *testing.T){
			o,p,s:=cxWarm(t,[]uint64{0,1})
			lease,d:=o.PinContextV1(p.View,p.Hash);cxDecision(t,"explicit pin",d,0,0,0,nil)
			in:=cxInput(p.View,cxMine(p.Hash,2,cxTarget(255)),cxProof(p,HeaderContextAdmitted148V1),s)
			h,d:=o.PrepareContextV1(in);cxDecision(t,"terminal prepare",d,0,0,0,nil)
			version:=o.VersionV1()
			switch terminal {
			case "Abort":
				if result := h.candidate.AbortV1(); result != 0 {
					t.Fatal(result)
				}
			case "Unknown":
				if result := h.candidate.UnknownV1(); result != 0 {
					t.Fatal(result)
				}
			case "Close":
				o.CloseV1()
			}
			calls := s.calls
			r, pub, d := h.PublishV1()
			outcome, candidate := uint8(8), uint8(0)
			if terminal == "Close" {
				outcome, candidate = 2, 1
			}
			cxDecision(t, "first wrapper terminal", d, outcome, 0, candidate, nil)
			cxEqual(t, "terminal zero record", r, HeaderContextRecord148V1{})
			cxEqual(t, "terminal zero receipt", pub, HeaderCandidatePublication148V1{})
			cxDecision(t, "repeated terminal consumed", h.AbortV1(), 8, 0, 0, nil)
			cxEqual(t, "consumed no callback", s.calls, calls)
			cxClean(t, o, terminal == "Unknown")
			if h.reservation.record.Work != nil || h.reservation.record.LastClampedTimestamp != nil || h.reservation.victims != nil || h.reservation.source != nil {
				t.Fatal("terminal retained staged payload/capability")
			}
			if terminal == "Close" {
				if len(o.context.records) != 0 || o.context.pins != 0 || o.context.bytes != 512 || o.prepared == nil || o.leases != 1 {
					t.Fatal("CLEANUP_CLOSE state")
				}
			} else if o.context.pins != 1 || o.leases != 1 {
				t.Fatal("terminal consumed an independent explicit lease")
			}
			lease.ReleaseV1()
			lease.ReleaseV1()
			switch terminal {
			case "Abort":
				cxEqual(t, "abort version", o.VersionV1(), version)
				next, d := o.PrepareContextV1(in)
				cxDecision(t, "CLEANUP_ABORT next", d, 0, 0, 0, nil)
				next.AbortV1()
			case "Unknown":
				cxEqual(t, "unknown version", o.VersionV1(), version+1)
				cxRefuse(t, "CLEANUP_UNKNOWN", o, in, 2, 0, 2, nil)
			case "Close":
				cxEqual(t, "late C1 release preserves old contract", o.leases, uint64(1))
				cxRefuse(t, "closed first", o, in, 2, 0, 1, nil)
			}
		})
	}
	// Real C1 contention is distinct from C2 reservation contention.
	o,p,s=cxWarm(t,[]uint64{0})
	busy,out:=o.PrepareV1(hcTr(o,nil));if out!=0{t.Fatal(out)}
	in:=cxInput(p.View,cxMine(p.Hash,1,cxTarget(255)),cxProof(p,HeaderContextCanonical148V1),s)
	cxRefuse(t,"actual C1 Busy",o,in,5,0,4,nil);busy.AbortV1()
	h,d:=o.PrepareContextV1(in);cxDecision(t,"Busy next",d,0,0,0,nil);h.AbortV1()
	genesis:=p.Raw;cl:=hcLim();cl.MaxHeaders=1
	o,v,s=cxNew(t,cxLimits(),cl,genesis);p=cxSeed(t,o,v,genesis,s)
	p,_=cxPublish(t,o,cxInput(v,cxMine(p.Hash,1,cxTarget(255)),cxProof(p,HeaderContextCanonical148V1),s))
	cxRefuse(t,"actual C1 Capacity",o,cxInput(p.View,cxMine(p.Hash,2,cxTarget(255)),cxProof(p,HeaderContextAdmitted148V1),s),5,0,12,nil)
	// Constructor-not-established is an actual C1 gate and invokes no capability method.
	o,err:=NewHeaderCandidateContext148V1(hcLim(),cxLimits(),8,[32]byte{91},cxHash(genesis));if err!=nil{t.Fatal(err)}
	_,d=o.PrepareContextV1(HeaderContextInput148V1{Source:s});cxDecision(t,"NotEstablished before shape",d,2,0,3,nil)
	// A contradictory C1 producer's supplied cumulative work must remain an actual Conflict.
	o,v,s=cxNew(t,cxLimits(),hcLim(),genesis);p=cxSeed(t,o,v,genesis,s)
	child=cxMine(p.Hash,1,cxTarget(255))
	conflict:=HeaderCandidateRecord148V1{Raw:child,Hash:cxHash(child),Parent:p.Hash,Height:1,Work:big.NewInt(3),Provenance:[32]byte{9},External:true}
	pub,out=hcPublish(t,o,hcTr(o,[]HeaderCandidateRecord148V1{conflict}));if out!=0{t.Fatal(out)}
	v.Version=pub.Version;p,d=o.RebindContextV1(v,*cxProof(p,HeaderContextCanonical148V1),s);cxDecision(t,"conflict parent proof",d,0,0,0,nil)
	cxRefuse(t,"actual C1 Conflict",o,cxInput(v,child,cxProof(p,HeaderContextCanonical148V1),s),4,0,7,nil)
	for _,kind:=range []string{"source-only","provenance-only"} {
		o, p, s = cxWarm(t, []uint64{0, 1})
		expected := p
		c1, _ := o.LookupV1(p.Hash)
		tr = hcTr(o, nil)
		if kind == "source-only" {
			tr.NewSource = [32]byte{2}
		} else {
			c1.Provenance = [32]byte{10}
			tr.Additions = []HeaderCandidateRecord148V1{c1}
			expected.Provenance = c1.Provenance
		}
		pub, out = hcPublish(t, o, tr)
		if out != 0 {
			t.Fatal(out)
		}
		cxEqual(t, kind+" preserves complete qualified evidence", o.context.records[p.Hash], expected)
		fresh := p.View
		fresh.Version = pub.Version
		if kind == "source-only" {
			fresh.Source = [32]byte{2}
		}
		_, d = o.LookupContextV1(fresh, p.Hash)
		cxDecision(t, kind+" requires rebind", d, 3, 0, 0, nil)
	}
	o,p,s=cxWarm(t,[]uint64{0,1});child=cxMine(p.Hash,2,cxTarget(255))
	direct:=HeaderCandidateRecord148V1{Raw:child,Hash:cxHash(child),Parent:p.Hash,Height:2,Work:big.NewInt(3),Provenance:[32]byte{9}}
	pub,out=hcPublish(t,o,hcTr(o,[]HeaderCandidateRecord148V1{direct}));if out!=0{t.Fatal(out)}
	v=p.View;v.Version=pub.Version
	_,d=o.LookupContextV1(v,direct.Hash);cxDecision(t,"ordinary C1 never fabricates context",d,2,0,0,nil)
	previous:=p.View
	o.CloseV1()
	newOwner,err:=NewHeaderCandidateContext148V1(hcLim(),cxLimits(),8,previous.Network,previous.Genesis);if err!=nil{t.Fatal(err)}
	if _,out=newOwner.EstablishV1(previous.Source,nil);out!=0{t.Fatal(out)}
	fresh:=previous;fresh.Incarnation=8;fresh.Version=2
	_,d=newOwner.LookupContextV1(fresh,p.Hash);cxDecision(t,"restart empty",d,2,0,0,nil)
	_,d=newOwner.LookupContextV1(previous,p.Hash);cxDecision(t,"restart old incarnation",d,3,0,0,nil)
	absenceSource:=&cxSource{}
	absenceBefore:=cxState(newOwner)
	absent,d:=newOwner.RebindContextV1(fresh,*cxProof(p,HeaderContextCanonical148V1),absenceSource)
	cxDecision(t,"rebind cache miss",d,2,0,0,nil)
	cxEqual(t,"rebind cache miss zero",absent,HeaderContextRecord148V1{})
	cxEqual(t,"rebind cache miss unchanged",cxState(newOwner),absenceBefore)
	cxEqual(t,"rebind absence before Current",absenceSource.calls,0)
	cxEqual(t,"rebind never materializes",len(absenceSource.reads),0)
	cxClean(t,newOwner,false)
	// This callback consumes the actual C1 handle after the wrapper passed its own terminal gate.
	o,p,s=cxWarm(t,[]uint64{0})
	in=cxInput(p.View,cxMine(p.Hash,1,cxTarget(255)),cxProof(p,HeaderContextCanonical148V1),s)
	retainedBefore:=cxState(o)
	h,d=o.PrepareContextV1(in);cxDecision(t,"callback-consume prepare",d,0,0,0,nil)
	s.current=func()(bool,error){if out:=h.candidate.AbortV1();out!=0{t.Errorf("callback C1 Abort: %d",out)};return true,nil}
	r,receipt,d:=h.PublishV1()
	cxDecision(t,"actual C1 Consumed mapping",d,8,0,15,nil)
	cxEqual(t,"actual Consumed zero record",r,HeaderContextRecord148V1{})
	cxEqual(t,"actual Consumed zero receipt",receipt,HeaderCandidatePublication148V1{})
	cxEqual(t,"actual Consumed unchanged retained state",cxState(o),retainedBefore)
	cxClean(t,o,false)
	s.current=nil
	next,d:=o.PrepareContextV1(in);cxDecision(t,"actual Consumed next legal prepare",d,0,0,0,nil);next.AbortV1()
}

func TestHeaderContext148Aliasing(t *testing.T) {
	o, p, s := cxWarm(t, []uint64{10})
	proof := cxProof(p, HeaderContextCanonical148V1)
	in := cxInput(p.View, cxMine(p.Hash, 20, cxTarget(255)), proof, s)
	originalRaw := in.Raw
	h, d := o.PrepareContextV1(in)
	cxDecision(t, "alias prepare", d, 0, 0, 0, nil)
	proof.Work.SetInt64(400)
	in.Tip.Work.SetInt64(500)
	p.Work.SetInt64(600)
	p.LastClampedTimestamp.SetInt64(700)
	p.RawTimestamps[0] = 800
	in.Raw[0] ^= 1
	r, pub, d := h.PublishV1()
	cxDecision(t, "ALIAS_INPUT", d, 0, 0, 0, nil)
	cxEqual(t, "ALIAS_INPUT raw", r.Raw, originalRaw)
	if r.Work.Cmp(big.NewInt(2)) != 0 || r.LastClampedTimestamp.Cmp(big.NewInt(20)) != 0 || r.RawTimestamps != ([11]uint64{20, 10}) {
		t.Fatal("ALIAS_INPUT mutated pending context")
	}
	work, clamp := new(big.Int).Set(r.Work), new(big.Int).Set(r.LastClampedTimestamp)
	view, hash := r.View, r.Hash
	r.Work.SetInt64(900)
	r.LastClampedTimestamp.SetInt64(1000)
	r.RawTimestamps[0] = 1100
	stored, d := o.LookupContextV1(view, hash)
	cxDecision(t, "alias lookup", d, 0, 0, 0, nil)
	cxEqual(t, "ALIAS_RETURN work", stored.Work, work)
	cxEqual(t, "ALIAS_RETURN clamp", stored.LastClampedTimestamp, clamp)
	cxEqual(t, "ALIAS_RETURN raw history", stored.RawTimestamps, [11]uint64{20, 10})
	c1, _ := o.LookupV1(hash)
	cxEqual(t, "C1 independent", c1.Work, work)
	cxEqual(t, "actual version", stored.View.Version, pub.Version)
	for _, timestamp := range []uint64{15, 16} {
		in = cxInput(view, cxMine(hash, timestamp, cxTarget(255)), cxProof(stored, HeaderContextAdmitted148V1), s)
		child, _ := cxPublish(t, o, in)
		child.Work.SetInt64(1200)
		child.LastClampedTimestamp.SetInt64(1300)
		// Refresh the same admitted parent explicitly after its sibling advanced the version.
		fresh := view
		fresh.Version = o.VersionV1()
		stored, d = o.RebindContextV1(fresh, *cxProof(stored, HeaderContextAdmitted148V1), s)
		cxDecision(t, "sibling parent rebind", d, 0, 0, 0, nil)
		cxEqual(t, "ALIAS_SIBLING parent work", stored.Work, work)
		cxEqual(t, "ALIAS_SIBLING parent clamp", stored.LastClampedTimestamp, clamp)
		view = fresh
	}
	genesis := cxMine([32]byte{}, 0, cxTarget(255))
	o, v, s := cxNew(t, cxLimits(), hcLim(), genesis)
	a := HeaderContextAnchor148V1{Kind: HeaderContextCanonical148V1, Raw: genesis, Hash: cxHash(genesis), Work: big.NewInt(1), Provenance: [32]byte{9}}
	in = cxCold(v, cxMine(a.Hash, 1, cxTarget(255)), a, 0, s)
	s.read = func(_ [32]byte, dst *[148]byte) (HeaderContextRead148V1, error) {
		*dst = genesis
		a.Work.SetInt64(999)
		in.Tip.Work.SetInt64(1000)
		return HeaderContextPresent148V1, nil
	}
	r, _ = cxPublish(t, o, in)
	cxEqual(t, "ALIAS_INPUT cold reservation copy", r.Work, big.NewInt(2))
	cxEqual(t, "caller reused anchor remains caller owned", a.Work, big.NewInt(999))
}

func TestHeaderContext148ProofShapes(t *testing.T) {
	for _,owner:=range []string{"warm","cold","rebind"} {
		for _,tc:=range []struct{name string;mutate func(*HeaderContextAnchor148V1);out uint8}{
			{"zero-kind",func(a *HeaderContextAnchor148V1){a.Kind=0},4},
			{"unknown-kind",func(a *HeaderContextAnchor148V1){a.Kind=4},4},
			{"nil-work",func(a *HeaderContextAnchor148V1){a.Work=nil},4},
			{"zero-work",func(a *HeaderContextAnchor148V1){a.Work=big.NewInt(0)},4},
			{"negative-work",func(a *HeaderContextAnchor148V1){a.Work=big.NewInt(-1)},4},
			{"large-work",func(a *HeaderContextAnchor148V1){a.Work=new(big.Int).Lsh(big.NewInt(1),512)},5},
			{"zero-provenance",func(a *HeaderContextAnchor148V1){a.Provenance=[32]byte{}},4},
			{"hash",func(a *HeaderContextAnchor148V1){a.Hash=[32]byte{42}},4},
			{"target",func(a *HeaderContextAnchor148V1){clear(a.Raw[76:108]);a.Hash=cxHash(a.Raw)},4},
			{"pow",func(a *HeaderContextAnchor148V1){a.Raw=cxBadPoW(a.Raw,[32]byte{1});a.Hash=cxHash(a.Raw)},4},
			{"admitted-absent",func(a *HeaderContextAnchor148V1){a.Kind=HeaderContextAdmitted148V1},4},
		} {
			t.Run(owner+"-"+tc.name,func(t *testing.T){
				o,p,s:=cxWarm(t,[]uint64{0})
				a:=cxProof(p,HeaderContextCanonical148V1)
				in:=cxInput(p.View,cxMine(p.Hash,1,cxTarget(255)),a,s)
				tc.mutate(a)
				before:=cxState(o)
				if owner=="rebind" {
					r,d:=o.RebindContextV1(p.View,*a,s)
					cxDecision(t,"proof closed shape",d,tc.out,0,0,nil)
					cxEqual(t,"proof zero",r,HeaderContextRecord148V1{})
					cxEqual(t,"proof unchanged",cxState(o),before)
					cxClean(t,o,false)
				}else{
					if owner=="cold" {in.WarmParent=nil;in.ColdParent=&HeaderContextCold148V1{Anchor:*a}}
					cxRefuse(t,"proof closed shape",o,in,tc.out,0,0,nil)
				}
			})
		}
	}
	for _,kind:=range []HeaderContextAnchorKind148V1{HeaderContextCanonical148V1,HeaderContextAcceptedTarget148V1} {
		o,p,s:=cxWarm(t,[]uint64{0})
		a:=cxProof(p,kind)
		r,d:=o.RebindContextV1(p.View,*a,s);cxDecision(t,"positive external rebind",d,0,0,0,nil);cxEqual(t,"rebind complete positive",r,p)
		h,d:=o.PrepareContextV1(cxInput(p.View,cxMine(p.Hash,1,cxTarget(255)),a,s));cxDecision(t,"positive warm kind",d,0,0,0,nil);h.AbortV1()
	}
	for _,owner:=range []string{"warm","cold","rebind"} {
		t.Run(owner+"-wrong-source-height",func(t *testing.T){
			o,p,s:=cxWarm(t,[]uint64{0})
			a:=cxProof(p,HeaderContextCanonical148V1);a.Height=1
			in:=cxInput(p.View,cxMine(p.Hash,1,cxTarget(255)),a,s)
			in.Tip.Hash=cxHash(cxMine(p.Hash,2,cxTarget(255)));in.Tip.Work=big.NewInt(2)
			if owner=="rebind"{r,d:=o.RebindContextV1(p.View,*a,s);cxDecision(t,"wrong exact height",d,4,0,0,nil);cxEqual(t,"height zero output",r,HeaderContextRecord148V1{})}else{
				if owner=="cold"{in.WarmParent=nil;in.ColdParent=&HeaderContextCold148V1{Anchor:*a}}
				cxRefuse(t,"wrong exact height",o,in,4,0,0,nil)
			}
		})
		for _,kind:=range []HeaderContextAnchorKind148V1{HeaderContextCanonical148V1,HeaderContextAcceptedTarget148V1} {
			o,p,s:=cxWarm(t,[]uint64{0,1});a:=cxProof(p,kind)
			in:=cxInput(p.View,cxMine(p.Hash,2,cxTarget(255)),a,s)
			if owner=="rebind"{_,d:=o.RebindContextV1(p.View,*a,s);cxDecision(t,"external kind on admitted hash",d,4,0,0,nil)}else{
				if owner=="cold"{in.WarmParent=nil;in.ColdParent=&HeaderContextCold148V1{Anchor:*a}}
				cxRefuse(t,"external kind on admitted hash",o,in,4,0,0,nil)
			}
		}
	}
	for _,owner:=range []string{"lookup","pin","seed","rebind"} {
		for _,tc:=range []struct{name string;mutate func(*HeaderContextView148V1);out uint8}{
			{"incarnation-zero",func(v *HeaderContextView148V1){v.Incarnation=0},4},
			{"incarnation-stale",func(v *HeaderContextView148V1){v.Incarnation++},3},
			{"version-zero",func(v *HeaderContextView148V1){v.Version=0},4},
			{"version-stale",func(v *HeaderContextView148V1){v.Version++},3},
			{"source-zero",func(v *HeaderContextView148V1){v.Source=[32]byte{}},4},
			{"source-stale",func(v *HeaderContextView148V1){v.Source=[32]byte{2}},3},
			{"authority-zero",func(v *HeaderContextView148V1){v.Authority=[32]byte{}},4},
			{"network",func(v *HeaderContextView148V1){v.Network=[32]byte{2}},4},
			{"genesis",func(v *HeaderContextView148V1){v.Genesis=[32]byte{2}},4},
		} {
			t.Run(owner+"-"+tc.name,func(t *testing.T){
				o,p,s:=cxWarm(t,[]uint64{0});v:=p.View;tc.mutate(&v);before:=cxState(o)
				var d HeaderContextDecision148V1
				switch owner {
				case "lookup":r,result:=o.LookupContextV1(v,p.Hash);d=result;cxEqual(t,"bad view lookup zero",r,HeaderContextRecord148V1{})
				case "pin":lease,result:=o.PinContextV1(v,p.Hash);d=result;if lease!=nil{t.Fatal("bad view pin")}
				case "seed":d=o.SeedGenesisContextV1(v,p.Raw,[32]byte{9},s)
				case "rebind":r,result:=o.RebindContextV1(v,*cxProof(p,HeaderContextCanonical148V1),s);d=result;cxEqual(t,"bad view rebind zero",r,HeaderContextRecord148V1{})
				}
				cxDecision(t,"view domain",d,tc.out,0,0,nil);cxEqual(t,"view unchanged",cxState(o),before)
			})
		}
	}
}

func TestHeaderContext148SourceBinding(t *testing.T) {
	for _,advance:=range []string{"none","source","close"} {
		raws,s:=cxChain(0,2,0,1,cxTarget(255),false)
		o,v,_:=cxNew(t,cxLimits(),hcLim(),raws[0])
		check:=func(){
			if !o.mu.TryLock(){t.Fatal("source callback under candidate mutex")}
			guards:=o.guards;o.mu.Unlock()
			if guards!=0{t.Fatal("source callback under invocation C1 guard")}
		}
		s.current=func()(bool,error){check();return true,nil}
		e1:=errors.New("observed header error")
		s.read=func(hash [32]byte,dst *[148]byte)(HeaderContextRead148V1,error){
			check();*dst=s.raws[hash]
			switch advance {
			case "source":tr:=hcTr(o,nil);tr.NewSource=[32]byte{2};_,out:=hcPublish(t,o,tr);if out!=0{t.Fatal(out)}
			case "close":o.CloseV1()
			}
			if advance!="none"{return HeaderContextReadInconsistent148V1,e1}
			return HeaderContextPresent148V1,nil
		}
		a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:raws[0],Hash:cxHash(raws[0]),Work:big.NewInt(1),Provenance:[32]byte{9}}
		in:=cxCold(v,cxMine(cxHash(raws[1]),2,cxTarget(255)),a,1,s)
		if advance=="none"{cxPublish(t,o,in);continue}
		h,d:=o.PrepareContextV1(in);if h!=nil{t.Fatal("changed source produced a handle")}
		out,candidate:=uint8(3),uint8(0);if advance=="close"{out,candidate=2,1}
		cxDecision(t,"independent owner freshness wins status",d,out,0,candidate,e1)
		cxEqual(t,"stop on first observed change",len(s.reads),1);cxClean(t,o,false)
		if advance=="source"{cxEqual(t,"independent source progress preserved",o.VersionV1(),uint64(3))}
	}
	for failAt:=1;failAt<=8;failAt++ {
		raws,s:=cxChain(0,8,0,1,cxTarget(255),false);o,v,_:=cxNew(t,cxLimits(),hcLim(),raws[0])
		a:=HeaderContextAnchor148V1{Kind:HeaderContextCanonical148V1,Raw:raws[5],Hash:cxHash(raws[5]),Height:5,Work:big.NewInt(6),Provenance:[32]byte{9}}
		cause:=fmt.Errorf("point failure %d",failAt)
		s.read=func(hash [32]byte,dst *[148]byte)(HeaderContextRead148V1,error){*dst=s.raws[hash];if len(s.reads)==failAt{return HeaderContextPresent148V1,cause};return HeaderContextPresent148V1,nil}
		cxRefuse(t,"unreadable prefix/suffix",o,cxCold(v,cxMine(cxHash(raws[7]),8,cxTarget(255)),a,2,s),2,0,0,cause)
		var expected [][32]byte;for i:=7;i>=8-failAt;i--{expected=append(expected,cxHash(raws[i]))}
		cxEqual(t,"exact stop at first failed point",s.reads,expected)
	}
}
