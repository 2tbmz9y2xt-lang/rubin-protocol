//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"testing"
)

// tsfProvider streams public value records; its hooks exercise only the
// explicitly listed provider refusals, accounting observations and unwinds.
type tsfProvider struct {
	block TreeBlockV1
	events []TreeEventV1
	calls [3]int
	before func(TreePositionV1,*Reader,*TreeDeltaSinkV1) error
	after func(TreePositionV1,*Reader,*TreeDeltaSinkV1) error
	custom func(TreePositionV1,*Reader,*TreeDeltaSinkV1) error
	reader *Reader
	sink *TreeDeltaSinkV1
}

func (p *tsfProvider) TreeDeltaV1(pos TreePositionV1,r *Reader,sink *TreeDeltaSinkV1) error {
	p.calls[pos]++
	p.reader,p.sink=r,sink
	if p.custom!=nil{return p.custom(pos,r,sink)}
	if p.before!=nil {if err:=p.before(pos,r,sink);err!=nil{return err}}
	if err:=sink.BeginV1(p.block);err!=nil{return err}
	for _,event:=range p.events {
		if err:=sink.EventV1(event);err!=nil{return err}
		// Changing the caller's local record must not alter the copied record.
		event.Outpoint.Txid=[32]byte{};event.FrameLength=0
	}
	if p.after!=nil {return p.after(pos,r,sink)}
	return nil
}

type tsfScene struct {
	s *Store
	path string
	o *OperationReservationOwner
	op TreeOperationV1
	p []*tsfProvider
}

func tsfCreate(txid [32]byte,offset uint64,n uint32) TreeEventV1 {
	return TreeEventV1{Kind:2,Outpoint:TreeOutpointV1{Txid:txid},FrameOffset:offset,FrameLength:n}
}

func tsfNew(t *testing.T) *tsfScene {
	t.Helper()
	s,path,o:=tsNew(t);tsRoots(t,s,o,1,2)
	p:=[]*tsfProvider{
		{block:TreeBlockV1{TxCount:1,EventCount:1},events:[]TreeEventV1{tsfCreate(tdTxid(0x10),148,11)}},
		{block:TreeBlockV1{TxCount:1,EventCount:1},events:[]TreeEventV1{tsfCreate(tdTxid(0x20),0,12)}},
		{block:TreeBlockV1{TxCount:2,EventCount:2},events:[]TreeEventV1{tsfCreate(tdTxid(0x30),0,11),{Kind:1,Outpoint:TreeOutpointV1{Txid:tdTxid(0x20)},TxIndex:1}}},
	}
	op:=tsOperation(t,p[0]);current:=&op.Primitives[0]
	current.Height,current.Endpoint.Height=10,10
	op.Pair.Mutations[0].Literal=append(op.Pair.Mutations[0].Literal[:148],tdFrame(100,0,nil)...)
	for i:=1;i<3;i++ {
		block:=tdTxid(byte(0xb0+i));height:=uint64(4+i)
		prim:=TreePrimitiveV1{Direction:1,Kind:6,Generation:2,Block:block,Height:height,Source:p[i],Undo:1,Endpoint:tcEndpoint(height,block)}
		op.Primitives=append(op.Primitives,prim)
		frame:=tdFrame(200,0,[]byte{1});if i==2{frame=tdFrame(300,0,nil)}
		treeNativeSeed(t,s,4,block[:],frame)
	}
	return &tsfScene{s:s,path:path,o:o,op:op,p:p}
}

func (s *tsfScene) run(t *testing.T) tsResult { return tsRun(t,s.s,s.o,TreeOperation,s.op) }

func (s *tsfScene) crossed(t *testing.T) tsResult {
	t.Helper();var r tsResult
	evidence,err:=fixtureLargeFault(s.s,12,0,[]byte{9},func(){r=s.run(t)})
	mustEnvironment(t,err)
	if evidence.commits!=1{t.Fatalf("crossing commit count%d",evidence.commits)}
	return r
}

func (s *tsfScene) durable(t *testing.T,newState bool,driftedManifest ...[32]byte) {
	t.Helper()
	s.s=tsReopen(t,s.s,s.path)
	for i,p:=range s.op.Primitives {
		txid,frame:=tdTxid(0x10),tdFrame(100,0,nil)
		if i==1{txid,frame=tdTxid(0x20),tdFrame(200,0,[]byte{1})}
		if i==2{txid,frame=tdTxid(0x30),tdFrame(300,0,nil)}
		var value []byte
		if newState&&i!=1{value=tdFormed(frame,p.Height,1)}
		tsRead(t,s.s,TreeSchemaV1DBIs()[1],tdUTXOKey(p.Generation,txid,0),value)
		manifest:=[]byte(nil);if newState{spent:=uint32(0);if i==2{spent=1};manifest=tdManifest(p.Height,s.p[i].block.Generated,s.p[i].block.TxCount,spent)}
		if slices.Contains(driftedManifest,p.Block){manifest=[]byte{0x7f}}
		tsRead(t,s.s,TreeSchemaV1DBIs()[5],tdManifestKey(p.Block),manifest)
	}
	undo:=[]byte(nil);if newState{undo=tdFormed(tdFrame(200,0,[]byte{1}),5,1)}
	tsRead(t,s.s,TreeSchemaV1DBIs()[5],tdEntryKey(s.op.Primitives[2].Block,tdTxid(0x20),1,0,0),undo)
	current:=s.op.Pair.Mutations[0];body:=[]byte(nil);if newState{body=current.Literal};tsRead(t,s.s,current.DBI,current.Key,body)
	for _,m:=range tsEntry(t).Pair.Mutations{tsRead(t,s.s,m.DBI,m.Key,m.Literal)}
	for _,g:=range []uint64{1,2}{tsRead(t,s.s,TreeSchemaV1DBIs()[0],tsRootKey(g),s.binding(t,g,newState))}
}

func (s *tsfScene) binding(t *testing.T,g uint64,newState bool) []byte {
	t.Helper();if !newState{return tsRootBytes(t,TreeEndpointV1{})}
	entries:=map[string]testTreeEntry{};var endpoint TreeEndpointV1
	for j,p:=range s.op.Primitives{
		if p.Generation!=g{continue};endpoint=p.Endpoint
		body:=s.op.Pair.Mutations[0].Literal;if j==1{body=tdFrame(200,0,[]byte{1})};if j==2{body=tdFrame(300,0,nil)}
		for _,e:=range s.p[j].events{
			key:=tdUTXOKey(g,e.Outpoint.Txid,e.Outpoint.Vout);id:=string(key)
			if e.Kind==1{delete(entries,id);continue}
			coinbase:=byte(0);if e.TxIndex==0{coinbase=1}
			entries[id]=tcEntry(key,tdFormed(body[e.FrameOffset:e.FrameOffset+uint64(e.FrameLength)],p.Height,coinbase))
		}
	}
	values:=make([]testTreeEntry,0,len(entries));for _,e:=range entries{values=append(values,e)}
	slices.SortFunc(values,func(a,b testTreeEntry)int{return bytes.Compare(a.k[:],b.k[:])})
	for _,e:=range values{key:=append(tdUTXOKey(g,[32]byte{},0)[:8],e.k[:]...);tsRead(t,s.s,TreeSchemaV1DBIs()[1],key,e.v)}
	return tcBinding(t,g,endpoint,values...)
}

// Literal P sizes follow each emitted identity in I-SEQ order. tcP is the
// existing test-owned high-water calculator, independent of the production P.
func (s *tsfScene) budgets(t *testing.T) [3]uint64 {
	t.Helper();p:=&tcP{sizes:map[string]uint64{}};var out [3]uint64
	for i,prim:=range s.op.Primitives {
		txid,frame:=tdTxid(0x10),tdFrame(100,0,nil)
		if i==1{txid,frame=tdTxid(0x20),tdFrame(200,0,[]byte{1})}
		if i==2{txid,frame=tdTxid(0x30),tdFrame(300,0,nil)}
		key,value:=tdUTXOKey(prim.Generation,txid,0),tdFormed(frame,prim.Height,1)
		if i!=0{p.put(4,prim.Block[:],0)}
		p.put(1,key,len(value))
		if i==2{
			old:=tdUTXOKey(2,tdTxid(0x20),0);v:=tdFormed(tdFrame(200,0,[]byte{1}),5,1)
			p.put(5,tdEntryKey(prim.Block,tdTxid(0x20),1,0,0),len(v));p.put(1,old,0)
		}
		p.put(5,tdManifestKey(prim.Block),33)
		if i==2{p.put(8,testTreeNodeKey(2,288,[36]byte(tdUTXOKey(2,tdTxid(0x20),0)[8:])),0)}
		p.put(8,testTreeNodeKey(prim.Generation,288,[36]byte(key[8:])),32)
		binding:=tcBinding(t,prim.Generation,prim.Endpoint,tcEntry(key,value))
		p.put(0,tsRootKey(prim.Generation),len(binding));out[i]=p.high
	}
	return out
}

func TestTreeStreamComposedAndExactAccountV1(t *testing.T) {
	for _,crossed:=range []bool{false,true} {
		t.Run(fmt.Sprintf("A2-A4-crossed%v",crossed),func(t *testing.T){
			s:=tsfNew(t);wantP:=s.budgets(t);var sample uint64
			pc:=uint64(len(s.op.Pair.Mutations[0].Key)+len(s.op.Pair.Mutations[0].Literal))
			s.p[2].before=func(pos TreePositionV1,_ *Reader,_ *TreeDeltaSinkV1)error{if pos==1{sample=reservationLive(s.o)};return nil}
			r:=tsResult{};if crossed{r=s.crossed(t)}else{r=s.run(t)}
			r.tuple(t,2,3,-1)
			if sample!=pc+wantP[1]+74_872{t.Fatalf("A4 live%d want PC%d+P%d+74872",sample,pc,wantP[1])}
			if crossed{tcCrossedCause(t,r.err,2,nil);tsConsumed(t,s.s,s.o,2,r.err)}else{mustEnvironment(t,r.err);tsFollowing(t,s.s,s.o)}
			for _,p:=range s.p{want:=1;if crossed{want=2};if p.calls[1]!=1||p.calls[2]!=want-1{t.Fatalf("positions %v",p.calls)}}
			s.durable(t,true)
		})
	}
}

func TestTreeStreamReadbackReservationV1(t *testing.T) {
	for _,short:=range []uint64{1,0} {
		t.Run(fmt.Sprintf("R7-Hr-short%d",short),func(t *testing.T){
			s:=tsfNew(t);budgets:=s.budgets(t)
			pc:=uint64(len(s.op.Pair.Mutations[0].Key)+len(s.op.Pair.Mutations[0].Literal))
			filler:=uint64(402_653_184)-pc-budgets[2]-131_192-288_400-104*2+short
			var r tsResult
			mustEnvironment(t,s.o.WithOperation(TreeOperation,func(a *OperationAccount)error{return a.WithReservation(filler,func()error{
				r=tsInvoke(s.s,a,func(*Reader)(TreeOperationV1,error){return s.op,nil})
				if reservationLive(s.o)!=filler{t.Fatal("R7 leaked past hold exit")};return nil
			})}))
			stage:=UpdateStage(3);if short!=0{stage=2};r.tuple(t,CommitTruth(2-short),stage,-1)
			if short!=0{if r.err!=errOperationReservationCapacity{t.Fatalf("H_r capacity identity %v",r.err)};tsConsumed(t,s.s,s.o,1,r.err)}else{mustEnvironment(t,r.err)}
			s.durable(t,short==0)
		})
	}
	t.Run("R7-P-growth",func(t *testing.T){
		s:=tsfNew(t);pc:=uint64(len(s.op.Pair.Mutations[0].Key)+len(s.op.Pair.Mutations[0].Literal))
		// CURRENT UTXO64 + manifest(33+33) =130; its first node needs78.
		filler:=uint64(402_653_184)-pc-74_872-104-65_560-147_968-207
		var r tsResult
		mustEnvironment(t,s.o.WithOperation(TreeOperation,func(a *OperationAccount)error{return a.WithReservation(filler,func()error{
			r=tsInvoke(s.s,a,func(*Reader)(TreeOperationV1,error){return s.op,nil});if reservationLive(s.o)!=filler{t.Fatal("P refusal release")};return nil
		})}))
		r.tuple(t,1,2,0);if r.err!=errOperationReservationCapacity||s.p[1].calls[1]!=0{t.Fatalf("P refusal %v",r.err)}
		tsConsumed(t,s.s,s.o,1,r.err);s.durable(t,false)
	})
}

func TestTreeStreamDescriptorCapacityV1(t *testing.T) {
	s:=tsfNew(t);s.p[1].block.EventCount=4_294_967_295
	r:=s.run(t);r.tuple(t,1,2,1)
	if r.err!=errOperationReservationCapacity||!IsOperationReservationCapacity(r.err)||s.p[2].calls[1]!=0{t.Fatalf("R5 %v calls%v",r.err,s.p[2].calls)}
	tsConsumed(t,s.s,s.o,1,r.err);s.durable(t,false)
}

func TestTreeStreamBeginFailuresV1(t *testing.T) {
	for _,row:=range []struct{scenario SelectedDamageScenario;class EngineClass;code int}{{SelectedDamageBeginEIO,"IO",5},{SelectedDamageBeginTxnFull,"Transaction",-30788}} {
		t.Run(fmt.Sprint(row.code),func(t *testing.T){
			s,_,_:=treeNativeStore(t);o:=reservationOwner(t,805_306_368);callbacks,sources:=0,0
			op:=tsOperation(t,tsSource(func(TreePositionV1,*Reader,*TreeDeltaSinkV1)error{sources++;return nil}));var r tsResult
			evidence,err:=FixtureSelectedDamage(s,o,row.scenario,0,[]byte{0},func(){
				_ = o.WithOperation(TreeOperation,func(a *OperationAccount)error{r=tsInvoke(s,a,func(*Reader)(TreeOperationV1,error){callbacks++;return op,nil});return nil})
			})
			mustEnvironment(t,err);r.tuple(t,1,1,-1)
			treeNativeError(t,r.err,"update",row.class,row.code,expectedNativeDiagnostic(row.code),nil)
			if callbacks!=0||sources!=0||reservationLive(o)!=0||evidence.BeginOld!=1||evidence.Faults!=1||evidence.BeginWrite!=0||evidence.BeginRead!=0||evidence.OldAborts!=0{t.Fatalf("begin effects %+v callbacks%d sources%d",evidence,callbacks,sources)}
			tsConsumed(t,s,o,1,r.err)
		})
	}
}

func TestTreeStreamCallbackRecordedFailureV1(t *testing.T) {
	for _,mode:=range []string{"ignored","returned","wrapped","other","panic","goexit"} {
		t.Run(mode,func(t *testing.T){
			s,_,o:=tsNew(t);key:=tsTarget(71).Key;var f,application error;var kept *Reader;var r tsResult
			value:=new(int);post:=false
			run:=func(){
				_,fixtureErr:=FixtureSelectedDamage(s,o,SelectedDamageGetEIO,6,key,func(){
					_ = o.WithOperation(TreeOperation,func(a *OperationAccount)error{
						r=tsInvoke(s,a,func(reader *Reader)(TreeOperationV1,error){
							kept=reader;_,_,f=reader.Get(TreeSchemaV1DBIs()[6],key)
							switch mode{case "panic":panic(value);case "goexit":runtime.Goexit();case "returned":application=f;case "wrapped":application=fmt.Errorf("callback: %w",f);case "other":application=errors.New("application")}
							return tsPair(19),application
						});return nil
					})
				});mustEnvironment(t,fixtureErr);post=true
			}
			if mode=="goexit"{done:=make(chan struct{});go func(){defer close(done);run()}();<-done}else if mode=="panic"{var got any;func(){defer func(){got=recover()}();run()}();if got!=value{t.Fatal("callback F panic identity")}}else{run();r.tuple(t,1,1,-1)}
			if f==nil||kept==nil||kept.usable()||reservationLive(o)!=0{t.Fatal("recorded failure lifetime")}
			tsExpiredReader(t,kept)
			treeNativeError(t,f,"get","IO",5,"error 5",nil)
			if mode=="panic"||mode=="goexit"{if post||s.terminal!=f{t.Fatal("unwind lost F")}}else if mode=="ignored"||mode=="returned"{if r.err!=f{t.Fatalf("dedup identity %v want %v",r.err,f)}}else{joined,ok:=r.err.(interface{Unwrap()[]error});if !ok||len(joined.Unwrap())!=2||joined.Unwrap()[0]!=application||joined.Unwrap()[1]!=f{t.Fatalf("callback primary order %v",r.err)}}
			tsConsumed(t,s,o,1,s.terminal)
		})
	}
}

func TestTreeStreamSourceFailureAndDriftV1(t *testing.T) {
	for _,mode:=range []string{"lag2-drift","ignored-sink","excluded-create"} {
		t.Run(mode,func(t *testing.T){
			s:=tsfNew(t);var r tsResult
			switch mode {
			case "lag2-drift":
				count,err:=FixtureWriteSnapshotDrift(s.s,5,tdManifestKey(s.op.Primitives[2].Block),func(){r=s.run(t)});mustEnvironment(t,err)
				if count!=1{t.Fatal("drift site not reached")};r.tuple(t,1,2,2)
				treeNativeError(t,r.err,"update","StateMismatch",-30779,"OLD/write snapshot mismatch",nil)
			case "ignored-sink":
				s.p[1].custom=func(_ TreePositionV1,_ *Reader,sink *TreeDeltaSinkV1)error{
					_ = sink.BeginV1(TreeBlockV1{TxCount:2,EventCount:2})
					e:=TreeEventV1{Kind:1,Outpoint:TreeOutpointV1{Txid:tdTxid(0xee)},TxIndex:1}
					_ = sink.EventV1(e);_ = sink.EventV1(e);return nil
				}
				// after ignored first refusal, even the regular BEGIN must retain it.
				r=s.run(t);r.tuple(t,1,2,1);treeNativeError(t,r.err,"update","InvalidInput",22,"invalid tree delta",nil)
			case "excluded-create":
				p:=s.op.Primitives[1];treeNativeSeed(t,s.s,4,p.Block[:],tdFrame(200,2,[]byte{1}))
				r=s.run(t);r.tuple(t,1,2,1);treeNativeError(t,r.err,"update","InvalidInput",22,"invalid tree delta",nil)
			}
			tsConsumed(t,s.s,s.o,1,r.err)
			if mode=="lag2-drift"{
				s.durable(t,false,s.op.Primitives[2].Block)
				tsRead(t,s.s,TreeSchemaV1DBIs()[4],s.op.Primitives[1].Block[:],tdFrame(200,0,[]byte{1}))
				tsRead(t,s.s,TreeSchemaV1DBIs()[4],s.op.Primitives[2].Block[:],tdFrame(300,0,nil))
			}else{s.durable(t,false)}
		})
	}
}

func TestTreeStreamProviderUnwindAndLifetimeV1(t *testing.T) {
	for _,mode:=range []string{"panic","goexit","reader-panic","reader-goexit"} {
		t.Run(mode,func(t *testing.T){
			s:=tsfNew(t);value:=new(int);key:=tsTarget(77).Key;var failure error
			readerFault:=mode=="reader-panic"||mode=="reader-goexit"
			s.p[1].after=func(_ TreePositionV1,r *Reader,_ *TreeDeltaSinkV1)error{
				if readerFault{_,_,failure=r.Get(TreeSchemaV1DBIs()[6],key)}
				if mode=="goexit"||mode=="reader-goexit"{runtime.Goexit()};panic(value)
			}
			post:=false;var recovered any
			run:=func(){
				done:=make(chan struct{})
				go func(){defer close(done);defer func(){recovered=recover();if reservationLive(s.o)!=0{t.Error("hold still live at unwind delivery")}}();_ = s.run(t);post=true}()
				<-done
			}
			if readerFault{
				evidence,err:=FixtureSelectedDamage(s.s,s.o,SelectedDamageGetEIO,6,key,run);mustEnvironment(t,err)
				if failure==nil||evidence.Faults!=1||evidence.OldGets[6]!=1{t.Fatalf("provider Reader fault %v evidence%+v",failure,evidence)}
				treeNativeError(t,failure,"get","IO",5,"error 5",nil)
			}else{run()}
			if (mode=="panic"||mode=="reader-panic")&&recovered!=value{t.Fatalf("provider panic identity %v",recovered)}
			if (mode=="goexit"||mode=="reader-goexit")&&recovered!=nil{t.Fatalf("provider Goexit panicked %v",recovered)}
			if post||reservationLive(s.o)!=0||s.p[1].reader==nil||s.p[1].reader.usable(){t.Fatal("provider unwind lifetime")}
			tsExpiredReader(t,s.p[1].reader)
			if s.p[1].sink.WindowV1()!=nil{t.Fatal("expired sink window")}
			treeNativeError(t,s.p[1].sink.EventV1(TreeEventV1{Kind:2}),"update","InvalidInput",22,"tree delta sink is not active",nil)
			if readerFault{if s.s.terminal!=failure{t.Fatal("provider F was not terminal")};tsConsumed(t,s.s,s.o,1,failure)}else{if s.s.state!=storeOPEN||s.s.terminal!=nil{t.Fatal("clean provider unwind consumed Store")};tsFollowing(t,s.s,s.o)}
			s.durable(t,false)
		})
	}
}

func TestTreeStreamReadbackResultsV1(t *testing.T) {
	for _,mode:=range []string{"error","panic","larger-stream"} {
		t.Run(mode,func(t *testing.T){
			s:=tsfNew(t);marker:=errors.New("readback provider");value:=new(int);var before,after uint64
			s.p[1].before=func(pos TreePositionV1,_ *Reader,sink *TreeDeltaSinkV1)error{
				if pos!=2{return nil};before=reservationLive(s.o)
				switch mode{case "error":return marker;case "panic":panic(value);case "larger-stream":err:=sink.BeginV1(TreeBlockV1{TxCount:1,EventCount:10_000});after=reservationLive(s.o);return err};return nil
			}
			if mode=="larger-stream"{
				// Writer EventCount10 is satisfied by ten distinct CREATE outputs.
				s.p[1].block.EventCount=10;s.p[1].events=nil
				for vout:=uint32(0);vout<10;vout++{e:=tsfCreate(tdTxid(0x20),0,12);e.Outpoint.Vout=vout;s.p[1].events=append(s.p[1].events,e)}
			}
			var r tsResult
			if mode=="panic"{var got any;func(){defer func(){got=recover()}();r=s.crossed(t)}();if got!=value{t.Fatal("readback panic identity")}}else{
				r=s.crossed(t);r.tuple(t,3,3,-1)
				var ce *CommitError;if !errors.As(r.err,&ce)||ce.Truth!=3{t.Fatalf("readback CommitError %v",r.err)}
				treeNativeError(t,ce.Cause,"update","Capacity",28,"error 28",nil)
				if mode=="error"&&ce.ReadbackCause!=marker{t.Fatalf("ReadbackCause identity %v",ce.ReadbackCause)}
				if mode=="larger-stream"&&(ce.ReadbackCause!=errOperationReservationCapacity||before!=after){t.Fatalf("readback budget %v live%d->%d",ce.ReadbackCause,before,after)}
			}
			if s.p[2].calls[2]!=0||s.s.state!=storeCLOSED||s.s.terminalTruth!=3||reservationLive(s.o)!=0{t.Fatal("readback result disposition")}
			tsConsumed(t,s.s,s.o,3,s.s.terminal)
			s.durable(t,true)
		})
	}
}

// tsfFill starts ordinary competing operations, each bounded by TREE_LANE_MAX,
// and returns their explicit release. It never changes reservation internals.
func tsfFill(t *testing.T,o *OperationReservationOwner,n uint64) func() {
	t.Helper();release,entered:=make(chan struct{}),make(chan error);var wg sync.WaitGroup
	for n!=0{
		chunk:=min(n,uint64(402_653_184));n-=chunk;wg.Add(1)
		go func(){defer wg.Done();err:=o.WithOperation(TreeOperation,func(a *OperationAccount)error{return a.WithReservation(chunk,func()error{entered<-nil;<-release;return nil})});if err!=nil{entered<-err}}()
		if err:=<-entered;err!=nil{close(release);wg.Wait();t.Fatalf("competing reserve %v",err)}
	}
	return func(){close(release);wg.Wait()}
}

func TestTreeStreamNoReadbackAccountDrawV1(t *testing.T) {
	s:=tsfNew(t);var held,filler uint64;var release func()
	s.p[0].before=func(pos TreePositionV1,_ *Reader,_ *TreeDeltaSinkV1)error{
		if pos==2{held=reservationLive(s.o);filler=805_306_368-held;release=tsfFill(t,s.o,filler);if reservationLive(s.o)!=805_306_368{t.Error("competitor did not fill remainder")}};return nil
	}
	s.p[1].before=func(pos TreePositionV1,_ *Reader,_ *TreeDeltaSinkV1)error{if pos==2&&reservationLive(s.o)!=805_306_368{t.Error("account changed during replay")};return nil}
	s.p[2].after=func(pos TreePositionV1,_ *Reader,_ *TreeDeltaSinkV1)error{if pos==2&&reservationLive(s.o)!=805_306_368{t.Error("account changed before replay completed")};return nil}
	var r tsResult
	evidence,err:=fixtureLargeFault(s.s,12,0,[]byte{9},func(){
		mustEnvironment(t,s.o.WithOperation(TreeOperation,func(a *OperationAccount)error{
			r=tsInvoke(s.s,a,func(*Reader)(TreeOperationV1,error){return s.op,nil})
			if reservationLive(s.o)!=filler{t.Error("engine hold not released before result")};release();return nil
		}))
	})
	mustEnvironment(t,err);r.tuple(t,2,3,-1);tcCrossedCause(t,r.err,2,nil)
	if evidence.commits!=1||held==0||reservationLive(s.o)!=0{t.Fatal("readback account closure")}
	s.durable(t,true)
}

func TestTreeStreamNestedProviderReservationV1(t *testing.T) {
	s:=tsfNew(t);var account *OperationAccount;var before,during,after uint64
	s.p[0].before=func(_ TreePositionV1,_ *Reader,_ *TreeDeltaSinkV1)error{
		before=reservationLive(s.o)
		err:=account.WithReservation(17,func()error{during=reservationLive(s.o);return nil})
		after=reservationLive(s.o);return err
	}
	var r tsResult
	mustEnvironment(t,s.o.WithOperation(TreeOperation,func(a *OperationAccount)error{account=a;r=tsInvoke(s.s,a,func(*Reader)(TreeOperationV1,error){return s.op,nil});return nil}))
	r.tuple(t,2,3,-1);mustEnvironment(t,r.err)
	if during!=before+17||after!=before||reservationLive(s.o)!=0{t.Fatalf("nested sums %d/%d/%d",before,during,after)}
	for _,p:=range s.p{
		if p.reader.usable()||p.sink.WindowV1()!=nil{t.Fatal("provider escaped active object")}
		tsExpiredReader(t,p.reader)
		treeNativeError(t,p.sink.BeginV1(TreeBlockV1{TxCount:1}),"update","InvalidInput",22,"tree delta sink is not active",nil)
	}
	s.durable(t,true)
}

func TestTreeStreamCallbackCleanupDispositionV1(t *testing.T) {
	for _,mode:=range []uint32{9,10} {
		for _,delivery:=range []string{"error","panic","goexit"} {
			t.Run(fmt.Sprintf("cleanup%d-%s",mode,delivery),func(t *testing.T){
				s,path,o:=tsNew(t);marker:=errors.New("callback primary");value:=new(int);var kept *Reader;var r tsResult
				post:=false
				run:=func(){_,err:=fixtureLargeFault(s,mode,0,[]byte{2},func(){
					_ = o.WithOperation(TreeOperation,func(a *OperationAccount)error{
						r=tsInvoke(s,a,func(reader *Reader)(TreeOperationV1,error){kept=reader;switch delivery{case "panic":panic(value);case "goexit":runtime.Goexit()};return TreeOperationV1{},marker});return nil
					})
				});mustEnvironment(t,err);post=true}
				if delivery=="goexit"{done:=make(chan struct{});go func(){defer close(done);run()}();<-done}else if delivery=="panic"{var got any;func(){defer func(){got=recover()}();run()}();if got!=value{t.Fatal("cleanup changed panic")}}else{run();r.tuple(t,1,1,-1);if !errors.Is(r.err,marker){t.Fatal("cleanup lost callback primary")}}
				if delivery!="error"&&post{t.Fatal("cleanup delivered post-call statement")}
				if kept==nil||kept.usable()||reservationLive(o)!=0||s.terminal==nil||s.terminalTruth!=1{t.Fatal("cleanup ownership projection")}
				if mode==9{tsConsumed(t,s,o,1,s.terminal)}else{
					if s.state!=storePOISONEDTHREAD||s.txn==nil{t.Fatal("retained OLD not projected")}
					calls:=0;_ = o.WithOperation(TreeOperation,func(a *OperationAccount)error{next:=tsInvoke(s,a,func(*Reader)(TreeOperationV1,error){calls++;return tsPair(88),nil});if next.err!=s.terminal||calls!=0{t.Error("poisoned Store reused")};return nil})
					terminal:=s.terminal;_ = fixtureLargeRelease(s);if s.state!=storeCLOSED||s.terminal!=terminal{t.Fatal("retained fixture teardown")}
				}
				tsRead(t,tsReopen(t,s,path),TreeSchemaV1DBIs()[6],tsTarget(88).Key,nil)
			})
		}
	}
}

func TestTreeStreamLiteralRootsV1(t *testing.T) {
	s,path,o:=tsNew(t);tsRoots(t,s,o,1)
	block:=tdTxid(0xa1);treeNativeSeed(t,s,4,block[:],[]byte{0})
	treeNativeSeed(t,s,5,tdManifestKey(block),tdManifest(1,[16]byte{},2,3))
	keys:=[][36]byte{testKA,testKB,testKC};events:=make([]TreeEventV1,3)
	for i,key:=range keys{
		var txid [32]byte;copy(txid[:],key[:32]);vout:=binary.BigEndian.Uint32(key[32:])
		events[i]=TreeEventV1{Kind:1,Outpoint:TreeOutpointV1{Txid:txid,Vout:vout},TxIndex:1,InputIndex:uint32(i)}
		treeNativeSeed(t,s,5,tdEntryKey(block,txid,1,uint32(i),vout),testTreeE())
	}
	endpoint:=TreeEndpointV1{Kind:1,Height:0,BlockHash:tdTxid(0xa0),CumulativeChainwork:[40]byte{4:1,39:37}}
	provider:=&tsfProvider{block:TreeBlockV1{TxCount:2,EventCount:3},events:events}
	op:=TreeOperationV1{Primitives:[]TreePrimitiveV1{{Direction:2,Kind:7,Generation:1,Block:block,Height:1,Source:provider,Undo:5,Endpoint:endpoint}}}
	r:=tsRun(t,s,o,TreeOperation,op);r.tuple(t,2,3,-1);mustEnvironment(t,r.err)
	s=tsReopen(t,s,path)
	c02:=testTreeHex(t,"14bd6311f35ed9534d8cd8a101bc09c5d289978e393e775271fd9e446c8cde8d")
	c03:=testTreeHex(t,"480f5e45ffbf5dbc0ec499ef7574c3379e26ab4ffb25220df9eb023b057526cc")
	tsRead(t,s,TreeSchemaV1DBIs()[8],testTreeNodeKey(1,288,testKA),c02[:])
	tsRead(t,s,TreeSchemaV1DBIs()[8],testTreeNodeKey(1,288,testKB),c03[:])
	mustEnvironment(t,s.View(func(reader *Reader)error{
		b,_,err:=reader.Get(TreeSchemaV1DBIs()[0],tsRootKey(1));if err!=nil{return err};binding,err:=DecodeRootBindingV1(b);if err!=nil{return err}
		if binding.RootDigest!=testTreeHex(t,"0dbb5487445845169a856b31fe2877c6cb84df41cc170f6ae9c41d062164fd7d")||binding.Endpoint!=endpoint{t.Fatal("C06 or endpoint changed")}
		node,_,err:=reader.Get(TreeSchemaV1DBIs()[8],testTreeNodeKey(1,0,[36]byte{}));if err!=nil{return err}
		c05:=testTreeHex(t,"fc8c011e40853708f49a90759af0c9e5b738e3116dca9ed641539af0827cf9ac");if len(node)!=140||!bytes.Equal(node[38:70],c05[:]){t.Fatal("C05 zero-child digest")};return nil
	}))
	for i,e:=range events{tsRead(t,s,TreeSchemaV1DBIs()[1],tdUTXOKey(1,e.Outpoint.Txid,e.Outpoint.Vout),testTreeE());tsRead(t,s,TreeSchemaV1DBIs()[5],tdEntryKey(block,e.Outpoint.Txid,1,uint32(i),e.Outpoint.Vout),testTreeE())}
	// Remove B/C, then the last entry A, through two admitted forward operations.
	for j,group:=range [][]TreeEventV1{{events[1],events[2]},{events[0]}}{
		b:=tdTxid(byte(0xd1+j));treeNativeSeed(t,s,4,b[:],[]byte{0})
		for i:=range group{group[i].InputIndex=uint32(i)}
		p:=&tsfProvider{block:TreeBlockV1{TxCount:2,EventCount:uint32(len(group))},events:group}
		ep:=TreeEndpointV1{Kind:1,Height:uint64(j+2),BlockHash:b,CumulativeChainwork:[40]byte{39:byte(j+40)}}
		deleteOp:=TreeOperationV1{Primitives:[]TreePrimitiveV1{{Direction:1,Kind:1,Generation:1,Block:b,Height:uint64(j+2),Source:p,Undo:2,Endpoint:ep}}}
		r=tsRun(t,s,o,TreeOperation,deleteOp);r.tuple(t,2,3,-1);mustEnvironment(t,r.err)
	}
	s=tsReopen(t,s,path)
	mustEnvironment(t,s.View(func(reader *Reader)error{b,_,err:=reader.Get(TreeSchemaV1DBIs()[0],tsRootKey(1));if err!=nil{return err};root,err:=DecodeRootBindingV1(b);if err!=nil{return err};if root.RootDigest!=testTreeHex(t,"0a978e2cf0e03934b2ec7c369b301f8f3a687aed501227a7af76730a8e64f8bb")||root.Top.Kind!=0{t.Fatal("C01 after last deletion")};return nil}))
}

func TestTreeStreamEvidenceTargetsV1(t *testing.T) {
	for _,after:=range []AfterKind{1,2}{
		t.Run(fmt.Sprint(after),func(t *testing.T){
			s,path,o:=tsNew(t)
			evidence:=TreeEvidenceV1{OriginalDatabaseID:[32]byte{7},OriginalCurrentID:1,OriginalLagID:2,Payload:[]byte{4,5}}
			value,err:=evidence.Encode();mustEnvironment(t,err);hash:=sha3.Sum256(value);key:=append([]byte{0x12},hash[:]...)
			treeNativeSeed(t,s,0,key,value)
			m:=Mutation{DBI:TreeSchemaV1DBIs()[0],Key:key,BeforePresent:true,AfterKind:after};if after==2{m.Literal=bytes.Clone(value)}
			r:=tsRun(t,s,o,TreeOperation,TreeOperationV1{Pair:TreePairV1{Mutations:[]Mutation{m}}});tsRefusal(t,r,false);tsFollowing(t,s,o)
			s=tsReopen(t,s,path);tsRead(t,s,m.DBI,key,value)
			control:=tsPair(43);control.Pair.Consulted=[]ConsultedRow{{m.DBI,key}}
			r=tsRun(t,s,o,TreeOperation,control);r.tuple(t,2,3,-1);mustEnvironment(t,r.err)
		})
	}
}

func TestTreeStreamSinkFieldForwardingV1(t *testing.T) {
	s:=tsfNew(t);s.p[0].block.Generated=[16]byte{0:1,15:23}
	r:=s.run(t);r.tuple(t,2,3,-1);mustEnvironment(t,r.err);s.durable(t,true)
}

func TestTreeStreamSinkKindRefusalsV1(t *testing.T) {
	for _,kind:=range []TreeEventKindV1{0,3,255}{
		t.Run(fmt.Sprint(kind),func(t *testing.T){
			s:=tsfNew(t)
			s.p[0].custom=func(_ TreePositionV1,_ *Reader,sink *TreeDeltaSinkV1)error{
				if err:=sink.BeginV1(TreeBlockV1{TxCount:1,EventCount:1});err!=nil{return err}
				e:=s.p[0].events[0];e.Kind=kind;return sink.EventV1(e)
			}
			r:=s.run(t);r.tuple(t,1,2,0);treeNativeError(t,r.err,"update","InvalidInput",22,"invalid tree delta",nil)
			tsConsumed(t,s.s,s.o,1,r.err);s.durable(t,false)
		})
	}
}

