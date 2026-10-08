//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"testing"
)

func tipCensus(t *testing.T, evidence fixtureTipEvidence, opens, gets, closes, faults uint32) {
	t.Helper()
	if evidence != (fixtureTipEvidence{opens, gets, closes, opens, faults}) {
		t.Fatalf("actual endpoint cursor census=%+v, want %d/%d/%d/fault%d", evidence, opens, gets, closes, faults)
	}
}

func TestCanonicalTipV1Native(t *testing.T) {
	for _, row := range []struct { name string; run func(*testing.T) }{
		{"T09 native constant counts", tipNativeCounts},
		{"T06 T10 T26 zero-call requests", tipNativeRequests},
		{"T08 getter-free existing domains", tipNativeCoexist},
		{"T11 T12 T13 T26 source representations", tipNativeSource},
		{"T03 foreign malformed value", tipNativeForeign},
		{"T14 native open get shapes", tipNativeShapes},
		{"T14 T18 native partitions phases", tipNativePartitions},
		{"T16 T17 T20 complete raw candidate drift", tipNativeDrift},
		{"T19 complete OLD NEW neither both", tipNativeTruth},
		{"T21 query after false T22 first error", tipNativeFoldOrder},
		{"T23 first callback result and panic", tipNativeCallbacks},
		{"T24 actual endpoint cleanup", tipNativeCleanup},
		{"T25 in-flight drain and single acquisition", tipNativeConcurrency},
	} { t.Run(row.name,row.run) }
}

func tipNativeRequests(t *testing.T) {
	for _, present := range []bool{false,true} {
		store,_,_:=consultedStore(t)
		if present {tipSeed(t,store,tipRow(7,37,[32]byte{0x44},[40]byte{39:1}))}
		var reader *Reader;var cell *canonicalTipCell
		evidence,err:=fixtureTipCursor(store,1,1,1,0,func(){
			tipRequest(t,nil,0,"Reader is not active")
			mustEnvironment(t,store.View(func(r *Reader)error{reader=r;copyReader:=newReader(r.txn,r.dbis);copyReader.self=r;copyReader.active.Store(true);tipRequest(t,copyReader,0,"Reader is not active");tipRequest(t,r,0,"invalid prefix-page prefix");point,failure:=r.CanonicalTipV1(7);mustEnvironment(t,failure);if present {tipRequirePoint(t,point,37,[32]byte{0x44})}else if point!=nil{t.Fatal("empty request control acquired point")};cell=r.tip;tipRequest(t,r,7,"canonical tip already acquired");tipRequest(t,r,8,"canonical tip already acquired");tipRequest(t,r,0,"invalid prefix-page prefix");if r.failure!=nil||!r.usable(){t.Fatal("request changed source status")};return nil}))
			tipRequest(t,reader,0,"Reader is not active")
		})
		mustEnvironment(t,err);tipCensus(t,evidence,1,2,1,0);tipRetired(t,reader,cell)
	}
}

func tipNativeCoexist(t *testing.T) {
	for _, acquire := range []bool{false,true} {
		store,_,_:=consultedStore(t);window:=CanonicalContextWindowV1{7,0,1};rows:=contextSeed(t,store,window);obsolete:=tipRow(9,0,[32]byte{0x31},[40]byte{39:1});tipSeed(t,store,obsolete)
		batch:=Batch{Mutations:[]Mutation{consultedCounter(t,900)},Consulted:[]ConsultedRow{{DBI:canonicalForwardDBILiteral,Key:canonicalForwardKeyLiteral(8,9)}},ContextConsulted:&window,LargeConsulted:[]LargeImageSelectorV1{{Kind:LargeImageBlockBodyV1,Hash:[32]byte{0x42}}}}
		var truth CommitTruth;var stage UpdateStage;var result error
		evidence,err:=fixtureTipCursor(store,1,1,1,0,func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){if acquire{_,failure:=r.CanonicalTipV1(7);if failure!=nil{return Batch{},failure}};page,pageErr:=r.ObsoleteGenerationPageV1(9,2,nil,1440);if pageErr!=nil{return Batch{},pageErr};batch.ObsoleteConsulted=[]ObsoletePageWitnessV1{page.Witness};return batch,nil})})
		mustEnvironment(t,err);mustEnvironment(t,result);queries:=uint32(0);if acquire{queries=3};tipCensus(t,evidence,queries,queries*2,queries,0);tipOutcome(t,store,truth,stage,result,2,3,"OPEN");contextImages(t,store,rows);obsoleteRawImage(t,store,2,obsolete.Key,obsolete.Literal)
	}
}

func tipNativeCounts(t *testing.T) {
	for _, generation := range []uint64{7,^uint64(0)} {
		for _, count := range []int{1,257} {
			for _, successor := range []bool{false,true} {
				if generation==^uint64(0) && successor { continue }
				store,_,_:=consultedStore(t)
				rows:=make([]Mutation,count)
				for i:=range rows { hash:=[32]byte{byte(i),byte(i>>8),0x44}; rows[i]=tipRow(generation,uint64(i*2),hash,[40]byte{39:1}) }
				tipSeed(t,store,rows...)
				if successor {tipSeed(t,store,tipRow(8,99,[32]byte{0x55},[40]byte{39:1}))}
				var selected SelectedDamageEvidence
				reservations, reservationErr := NewOperationReservationOwner(154611151)
				mustEnvironment(t, reservationErr)
				evidence,err:=fixtureTipCursor(store,1,1,1,0,func(){
					var fixtureErr error
					selected,fixtureErr=FixtureSelectedDamage(store,reservations,SelectedDamageProbeOnly,2,rows[count-1].Key,func(){tipRequirePoint(t,tipRead(t,store,generation),uint64((count-1)*2),[32]byte{byte(count-1),byte((count-1)>>8),0x44})})
					mustEnvironment(t,fixtureErr)
				})
				mustEnvironment(t,err)
				gets:=uint32(2);if generation==^uint64(0){gets=1};tipCensus(t,evidence,1,gets,1,0)
				if selected.OldGets!=([8]uint64{}) || selected.ReadGets!=0 || selected.BeginWrite!=0 || selected.Commits!=0 || selected.Faults!=0 {t.Fatalf("endpoint used point/header/owner path %+v",selected)}
				for _,crossed:=range []bool{false,true}{
					var truth CommitTruth;var stage UpdateStage;var result error
					evidence,err=fixtureTipCursor(store,1,1,1,0,func(){
						run:=func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){_,getErr:=r.CanonicalTipV1(generation);return Batch{Mutations:[]Mutation{consultedCounter(t,900+uint64(boolByte(crossed)))}},getErr})}
						if crossed {_,fixtureErr:=fixtureLargeFault(store,12,2,rows[count-1].Key,run);mustEnvironment(t,fixtureErr)} else {run()}
					})
					mustEnvironment(t,err);queries:=uint32(3);if crossed{queries=4};tipCensus(t,evidence,queries,queries*gets,queries,0)
					if crossed {tipCommit(t,result,2,nil);tipOutcome(t,store,truth,stage,result,2,3,"CLOSED")} else {mustEnvironment(t,result);tipOutcome(t,store,truth,stage,result,2,3,"OPEN")}
				}
			}
		}
	}
}

func boolByte(value bool) byte { if value {return 1};return 0 }

func tipNativeSource(t *testing.T) {
	base:=tipRow(7,37,[32]byte{0x44},[40]byte{39:1})
	for _,row:=range []struct{name string;key,value []byte;diagnostic string}{
		{"key15",append(bytes.Clone(base.Key[:8]),[]byte{0,0,0,0,0,1,0}...),base.Literal,"stored key outside SchemaV2 prefix-page domain"},
		{"key17",append(bytes.Clone(base.Key),0),base.Literal,"stored key outside SchemaV2 prefix-page domain"},
		{"height over",canonicalForwardKeyLiteral(7,0x100000000),base.Literal,"canonical tip height outside domain"},
		{"height max",canonicalForwardKeyLiteral(7,^uint64(0)),base.Literal,"canonical tip height outside domain"},
		{"width0",base.Key,nil,"stored value width outside SchemaV2 bound"},
		{"width103",base.Key,base.Literal[:103],"stored value width outside SchemaV2 bound"},
		{"width105",base.Key,append(bytes.Clone(base.Literal),0),"stored value width outside SchemaV2 bound"},
		{"work0",base.Key,canonicalForwardValueLiteral([32]byte{0x44},[40]byte{}),"canonical tip work outside domain"},
		{"work upper plus1",base.Key,canonicalForwardValueLiteral([32]byte{0x44},[40]byte{3:1,39:1}),"canonical tip work outside domain"},
		{"work high prefix",base.Key,canonicalForwardValueLiteral([32]byte{0x44},[40]byte{0:1}),"canonical tip work outside domain"},
		{"work byte3 two",base.Key,canonicalForwardValueLiteral([32]byte{0x44},[40]byte{3:2}),"canonical tip work outside domain"},
		{"height before width",canonicalForwardKeyLiteral(7,0x100000000),nil,"canonical tip height outside domain"},
		{"width before work",base.Key,make([]byte,103),"stored value width outside SchemaV2 bound"},
	}{t.Run(row.name,func(t *testing.T){
		store,_,_:=consultedStore(t);tipSeed(t,store,tipRow(7,1,[32]byte{0x11},[40]byte{39:1}))
		mustEnvironment(t,fixtureSeedPrefixRawRow(store,canonicalForwardDBILiteral,row.key,row.value))
		var reader *Reader;var source error;var truth CommitTruth;var stage UpdateStage;var result error
		evidence,err:=fixtureTipCursor(store,1,1,1,0,func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){reader=r;point,failure:=r.CanonicalTipV1(7);source=failure;if point!=nil{t.Fatal("greatest malformed source skipped or exposed")};tipRequest(t,r,0,"Reader is not active");return Batch{},nil})})
		mustEnvironment(t,err);tipCensus(t,evidence,1,2,1,0)
		if tipError(t,source,"prefix-page","Integrity",-30793,row.diagnostic,true).Cause!=nil || !sameError(reader.failure,source) || !sameError(result,source){t.Fatal("source representation error not recorded exactly")}
		tipRetired(t,reader,nil);tipOutcome(t,store,truth,stage,result,1,1,"CLOSED")
	})}
}

func tipNativeForeign(t *testing.T) {
	for _,generation:=range []uint64{1,8} {
		store,_,_:=consultedStore(t)
		mustEnvironment(t,fixtureSeedPrefixRawRow(store,canonicalForwardDBILiteral,canonicalForwardKeyLiteral(generation,99),[]byte{0xff}))
		evidence,err:=fixtureTipCursor(store,1,1,1,0,func(){if tipRead(t,store,7)!=nil{t.Fatal("foreign malformed value supplied endpoint")}})
		mustEnvironment(t,err);tipCensus(t,evidence,1,2,1,0)
		mustEnvironment(t,fixtureSeedPrefixRawRow(store,canonicalForwardDBILiteral,canonicalForwardKeyLiteral(7,37),canonicalForwardValueLiteral([32]byte{0x44},[40]byte{39:1})))
		tipRequirePoint(t,tipRead(t,store,7),37,[32]byte{0x44})
	}
}

func tipNativeShapes(t *testing.T) {
	for _,row:=range []struct{name string;mode,get uint32;class string;code int;diagnostic string;closes,gets uint32;cause bool}{
		{"open success null",2,0,"LocalInvariant",-30779,"mdbx_cursor_open returned invalid result shape",0,0,false},
		{"open error null",3,0,"IO",5,"error 5",0,0,false},
		{"open error real",4,0,"LocalInvariant",-30779,"mdbx_cursor_open returned invalid result shape",1,0,true},
		{"key null",5,2,"LocalInvariant",-30779,"mdbx_cursor_get returned invalid result shape",1,2,false},
		{"key zero",6,2,"LocalInvariant",-30779,"mdbx_cursor_get returned invalid result shape",1,2,false},
		{"key78",8,2,"LocalInvariant",-30779,"mdbx_cursor_get returned invalid result shape",1,2,false},
		{"seek below",9,1,"LocalInvariant",-30779,"mdbx_cursor_get returned invalid result shape",1,1,false},
		{"predecessor above",9,2,"LocalInvariant",-30779,"mdbx_cursor_get returned invalid result shape",1,2,false},
		{"value null before width",10,2,"LocalInvariant",-30779,"mdbx_cursor_get returned invalid result shape",1,2,false},
		{"EIO SET_RANGE",11,1,"IO",5,"error 5",1,1,false},
		{"EIO PREV",11,2,"IO",5,"error 5",1,2,false},
		{"RESULT_TRUE",12,2,"Transaction",-1,"error -1",1,2,false},
	}{t.Run(row.name,func(t *testing.T){
		store,_,_:=consultedStore(t);tipSeed(t,store,tipRow(7,37,[32]byte{0x44},[40]byte{39:1}),tipRow(8,99,[32]byte{0x55},[40]byte{39:1}))
		if row.mode==10{mustEnvironment(t,fixtureSeedPrefixRawRow(store,canonicalForwardDBILiteral,canonicalForwardKeyLiteral(7,37),make([]byte,103)))}
		var reader *Reader;var source error;var truth CommitTruth;var stage UpdateStage;var result error
		evidence,err:=fixtureTipCursor(store,row.mode,1,row.get,0,func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){reader=r;point,failure:=r.CanonicalTipV1(7);source=failure;if point!=nil{t.Fatal("native fault exposed point")};return Batch{},failure})})
		mustEnvironment(t,err);tipCensus(t,evidence,1,row.gets,row.closes,1)
		engine:=tipError(t,source,"prefix-page",row.class,row.code,row.diagnostic,false)
		if row.cause{cause:=tipError(t,engine.Cause,"prefix-page","IO",5,"error 5",false);if cause.Cause!=nil{t.Fatal("native Cause acquired nested error")}}else if engine.Cause!=nil{t.Fatal("native source acquired Cause")}
		if !sameError(reader.failure,source)||!sameError(result,source){t.Fatal("native source identity lost")};tipRetired(t,reader,nil);tipOutcome(t,store,truth,stage,result,1,1,"CLOSED")
	})}
	for _,get:=range []uint32{1,2}{
		store,_,_:=consultedStore(t);tipSeed(t,store,tipRow(7,37,[32]byte{0x44},[40]byte{39:1}))
		evidence,err:=fixtureTipCursor(store,11,1,get,0,func(){_,_,result:=store.Update(func(r *Reader)(Batch,error){_,failure:=r.CanonicalTipV1(7);return Batch{},failure});tipError(t,result,"prefix-page","IO",5,"error 5",false)})
		mustEnvironment(t,err);tipCensus(t,evidence,1,get,1,1)
	}
	store,_,_:=consultedStore(t);tipSeed(t,store,tipRow(^uint64(0),37,[32]byte{0x44},[40]byte{39:1}))
	evidence,err:=fixtureTipCursor(store,11,1,1,0,func(){_,_,result:=store.Update(func(r *Reader)(Batch,error){_,failure:=r.CanonicalTipV1(^uint64(0));return Batch{},failure});tipError(t,result,"prefix-page","IO",5,"error 5",false)})
	mustEnvironment(t,err);tipCensus(t,evidence,1,1,1,1)
	store,_,_=consultedStore(t);tipSeed(t,store,tipRow(7,37,[32]byte{0x44},[40]byte{39:1}),tipRow(8,99,[32]byte{0x55},[40]byte{39:1}))
	evidence,err=fixtureTipCursor(store,7,1,1,0,func(){tipRequirePoint(t,tipRead(t,store,7),37,[32]byte{0x44})});mustEnvironment(t,err);tipCensus(t,evidence,1,2,1,1)
}

func tipNativePartitions(t *testing.T) {
	// Inputs may use existing constants; expected classes/reopen bits/diagnostics
	// remain independently literal through the existing pinned diagnostic table.
	for _,row:=range []struct{code int;class string;reopen bool}{
		{codeBadValSize,"InvalidInput",false},{22,"InvalidInput",false},
		{codePageNotFound,"Integrity",true},{codeCorrupted,"Integrity",true},{codePanic,"Integrity",true},{codeVersionMismatch,"Integrity",true},{codeInvalid,"Integrity",true},{codeWannaRecovery,"Integrity",true},{codeDuplicatedLock,"Integrity",true},{codeCursorFull,"Integrity",true},
		{codeMapFull,"Capacity",false},{codeUnableExtendMapsize,"Capacity",true},{codeENOMEM,"Capacity",false},{28,"Capacity",false},{codeEDQUOT,"Capacity",false},{codeTooLarge,"Capacity",false},
		{codeReadersFull,"Concurrency",false},{codeBusy,"Concurrency",false},{codeLaggardReader,"Concurrency",false},{codeEDeadlock,"Concurrency",false},
		{codeTxnFull,"Transaction",false},{-1,"Transaction",false},
		{codeBadRSlot,"LocalInvariant",false},{codePageFull,"LocalInvariant",false},{codeBadDBI,"LocalInvariant",false},{codeDBsFull,"LocalInvariant",false},{codeMultiValue,"LocalInvariant",false},{codeKeyMismatch,"LocalInvariant",false},{codeBadTxn,"LocalInvariant",false},{codeThreadMismatch,"LocalInvariant",true},{codeTxnOverlapping,"LocalInvariant",false},{codeOusted,"LocalInvariant",false},{codeMVCCRetarded,"LocalInvariant",false},{codeProblem,"LocalInvariant",false},{codeBacklogDepleted,"LocalInvariant",false},{codeDanglingDBI,"LocalInvariant",false},{codeBadSignature,"LocalInvariant",true},{codeIncompatible,"LocalInvariant",false},
		{codeENOFile,"IO",false},{5,"IO",false},{codeEROFS,"IO",false},{codeENODEV,"IO",false},{codeESTALE,"IO",false},{codeEREMOTE,"IO",false},{codeEAccess,"IO",false},{codeEPerm,"IO",false},{codeEIntr,"IO",false},{codeEExist,"IO",false},{-31999,"LocalInvariant",false},{999,"IO",false},
	}{for _, query := range []uint32{1,2,3,4} {t.Run(fmt.Sprintf("%d/q%d",row.code,query),func(t *testing.T){
		store,_,_:=consultedStore(t);var source error;var reader *Reader;var truth CommitTruth;var stage UpdateStage;var result error
		run := func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){reader=r;point,failure:=r.CanonicalTipV1(7);source=failure;if point!=nil{t.Fatal("raw native code supplied empty/point")};if query==1{return Batch{},nil};return Batch{Mutations:[]Mutation{consultedCounter(t,900)}},failure})}
		evidence,err:=fixtureTipCursor(store,14,query,1,row.code,func(){if query==4{_,fixtureErr:=fixtureLargeFault(store,12,0,consultedCounter(t,900).Key,run);mustEnvironment(t,fixtureErr)}else{run()}})
		mustEnvironment(t,err);tipCensus(t,evidence,query,(query-1)*2+1,query,1)
		fault, operation, wantStage := result,"update",uint8(1)
		if query==1{fault,operation=source,"prefix-page";if !sameError(source,result)||!sameError(source,reader.failure){t.Fatal("native partition/source identity lost")}}
		if query==3{wantStage=2};if query==4{wantStage=3;var commit *CommitError;if !errors.As(result,&commit)||commit==nil{t.Fatal("crossed native partition lost CommitError")};fault=commit.ReadbackCause;if fault==nil{t.Fatal("crossed native partition lost readback cause")};tipCommit(t,result,3,fault)}
		if tipError(t,fault,operation,row.class,row.code,expectedNativeDiagnostic(row.code),row.reopen).Cause!=nil{t.Fatal("native partition manufactured Cause")};tipRetired(t,reader,nil);tipOutcome(t,store,truth,stage,result,map[bool]uint8{false:1,true:3}[query==4],wantStage,"CLOSED")
	})}}
	for _,query:=range []uint32{2,3}{for _,mode:=range []uint32{3,5,11,12}{
		store,_,_:=consultedStore(t);tipSeed(t,store,tipRow(7,37,[32]byte{0x44},[40]byte{39:1}),tipRow(8,99,[32]byte{0x55},[40]byte{39:1}))
		var truth CommitTruth;var stage UpdateStage;var result error
		evidence,err:=fixtureTipCursor(store,mode,query,1,0,func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){_,failure:=r.CanonicalTipV1(7);return Batch{Mutations:[]Mutation{consultedCounter(t,900)}},failure})})
		mustEnvironment(t,err);wantStage:=uint8(1);if query==3{wantStage=2};tipOutcome(t,store,truth,stage,result,1,wantStage,"CLOSED")
		class,code,diagnostic:="IO",5,"error 5";if mode==5{class,code,diagnostic="LocalInvariant",-30779,"mdbx_cursor_get returned invalid result shape"};if mode==12{class,code,diagnostic="Transaction",-1,"error -1"};tipError(t,result,"update",class,code,diagnostic,false)
		gets:=(query-1)*2+1;closes:=query;if mode==3{gets--;closes--};tipCensus(t,evidence,query,gets,closes,1)
	}}
}

func tipCommit(t *testing.T, result error, truth uint8, secondary error) *CommitError {
	t.Helper()
	commit,ok:=result.(*CommitError)
	if !ok||commit==nil||uint8(commit.Truth)!=truth||!sameError(commit.ReadbackCause,secondary){t.Fatalf("complete CommitError=%#v",result)}
	if tipError(t,commit.Cause,"update","Capacity",28,"error 28",false).Cause!=nil{t.Fatal("commit provenance acquired Cause")}
	return commit
}

func tipNativeDrift(t *testing.T) {
	for _,phase:=range []uint32{14,13,3}{for _,kind:=range []string{"empty-to-present","present-to-empty","tip-plus-two","key15","key17","width0","width103","width105","work0","32","63","103"}{
		t.Run(fmt.Sprintf("phase%d/%s",phase,kind),func(t *testing.T){
			store,path,cfg:=consultedStore(t);row:=tipRow(7,37,[32]byte{0x44},[40]byte{39:2});if kind!="empty-to-present"{tipSeed(t,store,row)}
			key,value,present:=bytes.Clone(row.Key),bytes.Clone(row.Literal),true
			switch kind{case "present-to-empty":present=false;value=nil;case "tip-plus-two":key=canonicalForwardKeyLiteral(7,39);case "key15":key=append(bytes.Clone(key[:8]),[]byte{0,0,0,0,0,1,0}...);case "key17":key=append(key,0);case "width0":value=[]byte{};case "width103":value=value[:103];case "width105":value=append(value,0);case "work0":clear(value[64:]);default:if kind!="empty-to-present"{var at int;_,scanErr:=fmt.Sscan(kind,&at);mustEnvironment(t,scanErr);value[at]^=1}}
			var truth CommitTruth;var stage UpdateStage;var result error;var reader *Reader;var cell *canonicalTipCell;var native fixtureLargeEvidence
			evidence,err:=fixtureTipCursor(store,1,1,1,0,func(){mustEnvironment(t,fixtureTipDrift(key,value,present));var fixtureErr error;native,fixtureErr=fixtureLargeFault(store,phase,2,key,func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){reader=r;_,failure:=r.CanonicalTipV1(7);cell=r.tip;return Batch{Mutations:[]Mutation{consultedCounter(t,900)}},failure})});mustEnvironment(t,fixtureErr)})
			mustEnvironment(t,err);queries,wantStage:=uint32(2),uint8(1);diagnostic:="OLD/write snapshot mismatch"
			if phase==13{queries,wantStage,diagnostic=3,2,"final update image mismatch"};if phase==3{queries,wantStage=4,3}
			tipCensus(t,evidence,queries,queries*2,queries,0);tipRetired(t,reader,cell)
			if phase==3{tipCommit(t,result,3,nil);tipOutcome(t,store,truth,stage,result,3,3,"CLOSED")}else{tipError(t,result,"update","StateMismatch",-30779,diagnostic,false);tipOutcome(t,store,truth,stage,result,1,wantStage,"CLOSED")}
			if native.drift!=1 || native.commits!=uint32(boolByte(phase==3)){t.Fatalf("actual phase drift site %+v",native)}
			reopened,openErr:=Open(path,cfg);consultedTrack(t,reopened,openErr)
			if phase==13{obsoleteRawImage(t,reopened,2,row.Key,row.Literal);if !bytes.Equal(key,row.Key){obsoleteRawImage(t,reopened,2,key,nil)}}else{obsoleteRawImage(t,reopened,2,key,value)}
			counter:=consultedCounter(t,900);want:=[]byte(nil);if phase==3{want=counter.Literal};obsoleteRawImage(t,reopened,0,counter.Key,want)
		})
	}}
}

func tipNativeTruth(t *testing.T) {
	t.Run("T20 endpoint drift rejects otherwise complete OLD",func(t *testing.T){
		store,path,cfg:=consultedStore(t);row:=tipRow(7,37,[32]byte{0x44},[40]byte{39:1});tipSeed(t,store,row);grown:=tipRow(7,39,[32]byte{0x55},[40]byte{39:1});counter:=consultedCounter(t,900)
		var truth CommitTruth;var stage UpdateStage;var result error
		evidence,err:=fixtureTipCursor(store,1,1,1,0,func(){mustEnvironment(t,fixtureTipDrift(grown.Key,grown.Literal,true));_,fixtureErr:=fixtureLargeFault(store,7,0,counter.Key,func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){_,failure:=r.CanonicalTipV1(7);return Batch{Mutations:[]Mutation{counter}},failure})});mustEnvironment(t,fixtureErr)})
		mustEnvironment(t,err);tipCensus(t,evidence,4,8,4,0);tipCommit(t,result,3,nil);tipOutcome(t,store,truth,stage,result,3,3,"CLOSED")
		reopened,openErr:=Open(path,cfg);consultedTrack(t,reopened,openErr);obsoleteRawImage(t,reopened,0,counter.Key,nil);obsoleteRawImage(t,reopened,2,grown.Key,grown.Literal);obsoleteRawImage(t,reopened,2,row.Key,row.Literal)
	})
	for _,mode:=range []uint32{7,12,5}{
		store,_,_:=consultedStore(t);row:=tipRow(7,37,[32]byte{0x44},[40]byte{39:1});tipSeed(t,store,row)
		counter:=consultedCounter(t,900);key:=counter.Key
		var truth CommitTruth;var stage UpdateStage;var result error
		evidence,err:=fixtureTipCursor(store,1,1,1,0,func(){_,fixtureErr:=fixtureLargeFault(store,mode,0,key,func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){_,failure:=r.CanonicalTipV1(7);return Batch{Mutations:[]Mutation{counter}},failure})});mustEnvironment(t,fixtureErr)})
		mustEnvironment(t,err);tipCensus(t,evidence,4,8,4,0);want:=uint8(3);if mode==7{want=1};if mode==12{want=2};tipCommit(t,result,want,nil);tipOutcome(t,store,truth,stage,result,want,3,"CLOSED")
	}
	store,_,_:=consultedStore(t);runtime.LockOSThread();defer runtime.UnlockOSThread()
	mustEnvironment(t,store.View(func(r *Reader)error{
		_,failure:=r.CanonicalTipV1(7);if failure!=nil{return failure}
		old,newImage,err:=updateNativeReadbackScoped(r.txn,r.txn,store.dbis,nil,nil,true,true,largeImageScope{tip:r.tip,maxKey:2022})
		if err!=nil||!old||!newImage{t.Fatalf("complete both-true endpoint fold %v/%v/%v",old,newImage,err)}
		truth,err:=updateNativeReadbackTruth(r.txn,r.txn,store.dbis,nil,nil,largeImageScope{tip:r.tip,maxKey:2022})
		if truth!=1||err!=nil{t.Fatalf("complete both-true OLD-first selection %d/%v",truth,err)}
		return nil
	}))
}

func tipNativeFoldOrder(t *testing.T) {
	for _,which:=range []string{"target","legacy","Large","context","Obsolete"}{
		for _,firstFault:=range []bool{false,true}{t.Run(fmt.Sprintf("%s/firstfault%v",which,firstFault),func(t *testing.T){
			store,_,_:=consultedStore(t);row:=tipRow(7,37,[32]byte{0x44},[40]byte{39:1});tipSeed(t,store,row)
			counter:=consultedCounter(t,900);rank,key:=uint8(0),counter.Key
			batch:=Batch{Mutations:[]Mutation{counter}}
			if which=="legacy"{key=consultedCounter(t,901).Key;mustEnvironment(t,fixtureSeedPrefixRawRow(store,readDBIsLiteral()[0],key,consultedCounter(t,901).Literal));batch.Consulted=[]ConsultedRow{{DBI:readDBIsLiteral()[0],Key:key}}}
			if which=="Large"{rank,key=4,make([]byte,32);mustEnvironment(t,fixtureSeedPrefixRawRow(store,readDBIsLiteral()[4],key,[]byte{0x31}));batch.LargeConsulted=[]LargeImageSelectorV1{{Kind:1}}}
			if which=="context"{window:=CanonicalContextWindowV1{9,0,1};rows:=contextSeed(t,store,window);batch.ContextConsulted=&window;rank,key=2,rows[0].Key}
			if which=="Obsolete"{rank,key=2,canonicalForwardKeyLiteral(9,0);mustEnvironment(t,fixtureSeedPrefixRawRow(store,readDBIsLiteral()[2],key,[]byte{0x31}))}
			var truth CommitTruth;var stage UpdateStage;var result error
			liMode:=uint32(5);if firstFault{liMode=8;if which=="Obsolete"{liMode=29;rank,key=0,counter.Key}}
			evidence,err:=fixtureTipCursor(store,11,4,1,0,func(){_,fixtureErr:=fixtureLargeFault(store,liMode,rank,key,func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){_,failure:=r.CanonicalTipV1(7);if which=="Obsolete"{page,pageErr:=r.ObsoleteGenerationPageV1(9,2,nil,1440);if pageErr!=nil{return Batch{},pageErr};batch.ObsoleteConsulted=[]ObsoletePageWitnessV1{page.Witness}};return batch,failure})});mustEnvironment(t,fixtureErr)})
			mustEnvironment(t,err)
			commit,ok:=result.(*CommitError);if !ok||commit.Truth!=3||truth!=3||stage!=3{t.Fatalf("complete fold result %d/%d/%v",truth,stage,result)}
			tipError(t,commit.Cause,"update","Capacity",28,"error 28",false)
			if firstFault{tipCensus(t,evidence,3,6,3,0);operation:="update";if which=="Large"{operation="get"};tipError(t,commit.ReadbackCause,operation,"IO",5,"error 5",false)}else{tipCensus(t,evidence,4,7,4,1);tipError(t,commit.ReadbackCause,"update","IO",5,"error 5",false)}
			tipOutcome(t,store,truth,stage,result,3,3,"CLOSED")
		})}
	}
}

func tipNativeCallbacks(t *testing.T) {
	for _,mode:=range []string{"ignored","direct","wrapped","joined","distinct","cause","typed-nil","panic"}{
		t.Run(mode,func(t *testing.T){
			store,_,_:=consultedStore(t);var reader *Reader;var source,application,result error;var truth CommitTruth;var stage UpdateStage;var recovered any
			payload:=&struct{value int}{7}
			evidence,err:=fixtureTipCursor(store,11,1,1,0,func(){defer func(){recovered=recover()}();truth,stage,result=store.Update(func(r *Reader)(Batch,error){reader=r;point,failure:=r.CanonicalTipV1(7);source=failure;if point!=nil{t.Fatal("source fault manufactured point")};switch mode{case "direct":application=failure;case "wrapped":application=fmt.Errorf("wrapped: %w",failure);case "joined":application=errors.Join(errors.New("first"),failure);case "distinct":application=errors.New("distinct");case "cause":application=&EngineError{Operation:"get",Class:"IO",Code:5,Diagnostic:"error 5",Cause:failure};case "typed-nil":application=(*CommitError)(nil);case "panic":panic(payload)};return Batch{},application})});mustEnvironment(t,err);tipCensus(t,evidence,1,1,1,1)
			if mode=="panic"{if recovered!=payload||result!=nil{t.Fatal("source fault replaced original panic")};result=store.terminal;truth,stage=1,1}else if recovered!=nil{t.Fatalf("unexpected panic %v",recovered)}
			if application==nil||mode=="direct"{if !sameError(result,source){t.Fatal("direct source dedup identity lost")}}else{parts,ok:=result.(interface{Unwrap()[]error});if !ok||len(parts.Unwrap())!=2||!sameError(parts.Unwrap()[0],application)||!sameError(parts.Unwrap()[1],source){t.Fatal("application then recorded source order lost")}}
			tipError(t,source,"prefix-page","IO",5,"error 5",false);if !sameError(reader.failure,source){t.Fatal("first source identity overwritten")};tipRetired(t,reader,nil);tipOutcome(t,store,truth,stage,result,1,1,"CLOSED")
		})
	}
}

func tipNativeCleanup(t *testing.T) {
	for _,kind:=range []string{"application","software"}{for _,mode:=range []uint32{9,10}{
		store,_,_:=consultedStore(t);var application,result error;var reader *Reader;var cell *canonicalTipCell;var truth CommitTruth;var stage UpdateStage
		evidence,err:=fixtureTipCursor(store,1,1,1,0,func(){_,fixtureErr:=fixtureLargeFault(store,mode,2,canonicalForwardKeyLiteral(7,37),func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){reader=r;_,failure:=r.CanonicalTipV1(7);mustEnvironment(t,failure);cell=r.tip;application=errors.New("application result");if kind=="software"{_,application=r.CanonicalTipV1(0);tipError(t,application,"prefix-page","InvalidInput",22,"invalid prefix-page prefix",false)};return Batch{},application})});mustEnvironment(t,fixtureErr)})
		mustEnvironment(t,err);tipCensus(t,evidence,1,2,1,0);state:="CLOSED"
		if mode==9{parts,ok:=result.(interface{Unwrap()[]error});if !ok||len(parts.Unwrap())!=2||!sameError(parts.Unwrap()[0],application){t.Fatal("consumed abort lost application/software first")};tipError(t,parts.Unwrap()[1],"abort","IO",5,"error 5",false)}else{state="POISONED_THREAD";abort:=tipError(t,result,"abort","LocalInvariant",-30416,expectedNativeDiagnostic(-30416),true);if !sameError(abort.Cause,application){t.Fatal("retained abort lost application/software Cause")}}
		tipRetired(t,reader,cell);tipOutcome(t,store,truth,stage,result,1,1,state);mustEnvironment(t,fixtureLargeRelease(store))
	}}
	for _,mode:=range []uint32{9,10,11,15,16,19}{
		store,_,_:=consultedStore(t);row:=tipRow(7,37,[32]byte{0x44},[40]byte{39:1});tipSeed(t,store,row)
		var reader *Reader;var cell *canonicalTipCell;var truth CommitTruth;var stage UpdateStage;var result error
		evidence,err:=fixtureTipCursor(store,1,1,1,0,func(){_,fixtureErr:=fixtureLargeFault(store,mode,2,row.Key,func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){reader=r;_,failure:=r.CanonicalTipV1(7);cell=r.tip;return Batch{Mutations:[]Mutation{consultedCounter(t,900)}},failure})});mustEnvironment(t,fixtureErr)})
		mustEnvironment(t,err);queries:=uint32(4);if mode==9||mode==10||mode==11{queries=4};tipCensus(t,evidence,queries,queries*2,queries,0)
		want:=uint8(2);if mode==19{want=1};state:="CLOSED";if mode==10||mode==15||mode==19{state="POISONED_THREAD"};if mode==11{state="CLOSE_BLOCKED"}
		var commit *CommitError;if !errors.As(result,&commit)||commit==nil||uint8(commit.Truth)!=want{t.Fatal("cleanup lost commit truth")}
		if mode==11{closeErr:=tipError(t,result,"close","Concurrency",-30778,expectedNativeDiagnostic(-30778),false);if closeErr.Cause!=commit{t.Fatal("close BUSY lost exact commit cause")}}else{code,class:=5,"IO";if mode==10||mode==15||mode==19{code,class=-30416,"LocalInvariant"};tipError(t,commit.ReadbackCause,"abort",class,code,expectedNativeDiagnostic(code),code==-30416)}
		if mode==10||mode==15||mode==19{if store.env==nil||store.writer==nil||store.txn==nil||store.config!=(ConfigV1{})||store.dbis!=(Store{}).dbis{t.Fatal("retained transaction owner lost")}}
		if mode==10&&store.txn!=reader.txn || (mode==15||mode==19)&&store.txn==reader.txn {t.Fatal("retained readback owner or OLD fallback changed")}
		tipRetired(t,reader,cell);tipOutcome(t,store,truth,stage,result,want,3,state);mustEnvironment(t,fixtureLargeRelease(store))
	}
	for _,mode:=range []uint32{9,10,24}{
		store,_,_:=consultedStore(t);var source,result error;var truth CommitTruth;var stage UpdateStage;var reader *Reader
		evidence,err:=fixtureTipCursor(store,11,1,1,0,func(){_,fixtureErr:=fixtureLargeFault(store,mode,2,canonicalForwardKeyLiteral(7,37),func(){truth,stage,result=store.Update(func(r *Reader)(Batch,error){reader=r;_,source=r.CanonicalTipV1(7);return Batch{},nil})});mustEnvironment(t,fixtureErr)})
		mustEnvironment(t,err);tipCensus(t,evidence,1,1,1,1);state:="CLOSED"
		if mode==9{parts,ok:=result.(interface{Unwrap()[]error});if !ok||len(parts.Unwrap())!=2||!sameError(parts.Unwrap()[0],source){t.Fatal("consumed abort lost source first")};tipError(t,parts.Unwrap()[1],"abort","IO",5,"error 5",false)}
		if mode==10{state="POISONED_THREAD";abort:=tipError(t,result,"abort","LocalInvariant",-30416,expectedNativeDiagnostic(-30416),true);if !sameError(abort.Cause,source)||store.txn!=reader.txn{t.Fatal("retained abort lost source cause or exact OLD owner")}}
		if mode==24{state="CLOSE_BLOCKED";closeErr:=tipError(t,result,"close","Concurrency",-30778,expectedNativeDiagnostic(-30778),false);if !sameError(closeErr.Cause,source){t.Fatal("retained close lost source cause")}}
		tipRetired(t,reader,nil);tipOutcome(t,store,truth,stage,result,1,1,state);mustEnvironment(t,fixtureLargeRelease(store))
	}
	for _,releaseFault:=range []bool{false,true}{
		store,_,_:=consultedStore(t);var source,result error;var truth CommitTruth;var stage UpdateStage;var reader *Reader
		evidence,err:=fixtureTipCursor(store,11,1,1,0,func(){mustEnvironment(t,fixtureTipCloseFault());truth,stage,result=store.Update(func(r *Reader)(Batch,error){reader=r;_,source=r.CanonicalTipV1(7);if releaseFault{mustEnvironment(t,fixtureTipWriterReleaseFault(store))};return Batch{},nil})})
		mustEnvironment(t,err);tipCensus(t,evidence,1,1,1,1)
		if releaseFault{parts,ok:=result.(interface{Unwrap()[]error});if !ok||len(parts.Unwrap())!=2{t.Fatal("close then release order lost")};release:=tipError(t,parts.Unwrap()[1],"close","IO",9,"release Rubin writer lock",false);if !errors.Is(release.Cause,syscall.EBADF){t.Fatal("actual release Cause lost EBADF")};result=parts.Unwrap()[0]}
		parts,ok:=result.(interface{Unwrap()[]error});if !ok||len(parts.Unwrap())!=2||!sameError(parts.Unwrap()[0],source){t.Fatal("source then consumed close order lost")};if tipError(t,parts.Unwrap()[1],"close","IO",5,"error 5",false).Cause!=nil{t.Fatal("consumed close manufactured Cause")}
		tipRetired(t,reader,nil);tipOutcome(t,store,truth,stage,store.terminal,1,1,"CLOSED")
	}
}

func tipNativeConcurrency(t *testing.T) {
	store,_,_:=consultedStore(t);row:=tipRow(7,37,[32]byte{0x44},[40]byte{39:1});tipSeed(t,store,row)
	var saved *Reader;var cell *canonicalTipCell
	evidence,err:=fixtureTipCursor(store,13,1,2,0,func(){
		finished:=make(chan struct{});var truth CommitTruth;var stage UpdateStage;var result error
		first:=make(chan error,1);queued:=make(chan error,1)
		go func(){defer close(finished);truth,stage,result=store.Update(func(r *Reader)(Batch,error){saved=r;go func(){point,getErr:=r.CanonicalTipV1(7);if getErr==nil&&(point==nil||point.Height!=37){getErr=errors.New("in-flight scalar drift")};first<-getErr}();fixtureTipWait();go func(){_,getErr:=r.CanonicalTipV1(7);queued<-getErr}();go func(){for r.active.Load(){runtime.Gosched()};fixtureTipRelease()}();return Batch{Mutations:[]Mutation{consultedCounter(t,900)}},nil})}()
		<-finished;mustEnvironment(t,<-first);tipError(t,<-queued,"prefix-page","InvalidInput",22,"Reader is not active",false);mustEnvironment(t,result);tipOutcome(t,store,truth,stage,result,2,3,"OPEN");cell=saved.tip
	})
	mustEnvironment(t,err);tipCensus(t,evidence,3,6,3,0);tipRetired(t,saved,cell)
	evidence,err=fixtureTipCursor(store,1,1,1,0,func(){mustEnvironment(t,store.View(func(r *Reader)error{results:=make(chan error,2);for range 2{go func(){point,getErr:=r.CanonicalTipV1(7);if getErr==nil{tipRequirePoint(t,point,37,[32]byte{0x44})};results<-getErr}()};a,b:=<-results,<-results;if a==nil&&b==nil||a!=nil&&b!=nil{t.Fatal("same Reader did not serialize one success")};if a==nil{a=b};tipError(t,a,"prefix-page","InvalidInput",22,"canonical tip already acquired",false);return nil}))})
	mustEnvironment(t,err);tipCensus(t,evidence,1,2,1,0)
	finished:=make(chan struct{})
	go func(){defer close(finished);_,_,_=store.Update(func(r *Reader)(Batch,error){saved=r;_,getErr:=r.CanonicalTipV1(7);mustEnvironment(t,getErr);cell=r.tip;runtime.Goexit();return Batch{},nil})}()
	<-finished;tipRetired(t,saved,cell);largeCommit(t,store,Batch{Mutations:[]Mutation{consultedCounter(t,901)}})
}
