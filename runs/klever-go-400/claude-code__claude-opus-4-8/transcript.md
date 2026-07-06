**Claude:** I'll start by reading the FINDING.txt file to understand the vulnerability.

**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: klever-io/klever-go
2	Vulnerability type: Uncontrolled Resource Consumption (CWE-400)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  common/errors.go
7	    - lines 778-783   in: var ErrNotCompressed = errors.New("not compressed")
8	
9	  core/process/errors.go
10	    - lines 56-61   in: v  …(+1962 more chars)
**→ Read**(file_path=/work/data/batch/batch.go)
  ↳ *result:* 1	//go:generate protoc -I=proto -I=$GOPATH/src -I=$GOPATH/src/github.com/klever-io/klever-go/protobuf --go_out=. batch.proto
2	package batch
3	
4	import (
5		bytes "bytes"
6		"compress/gzip"
7		"io"
8	
9		//lz4 "github.com/DataDog/golz4"
10	
11		"github.com/klever-io/klever-go/common"
12		"github.com/klever-io/klever-go/tools/marshal"
13	)
14	
15	/  …(+2630 more chars)
**→ Read**(file_path=/work/core/process/interceptors/baseDataInterceptor.go)
**→ Read**(file_path=/work/core/process/interceptors/multiDataInterceptor.go)
  ↳ *result:* 1	package interceptors
2	
3	import (
4		"github.com/klever-io/klever-go/core"
5		"github.com/klever-io/klever-go/core/process"
6		"github.com/klever-io/klever-go/data/batch"
7		"github.com/klever-io/klever-go/network/p2p"
8		"github.com/klever-io/klever-go/tools/check"
9		"github.com/klever-io/klever-go/tools/debug/resolver"
10		"github.com/klever-  …(+7498 more chars)
  ↳ *result:* 1	package interceptors
2	
3	import (
4		"bytes"
5		"sync"
6	
7		"github.com/klever-io/klever-go/common"
8		"github.com/klever-io/klever-go/core"
9		"github.com/klever-io/klever-go/core/process"
10		"github.com/klever-io/klever-go/network/p2p"
11		"github.com/klever-io/klever-go/tools/check"
12	)
13	
14	type baseDataInterceptor struct {
15		throttle  …(+3453 more chars)
**→ Read**(file_path=/work/core/process/interceptors/singleDataInterceptor.go)
  ↳ *result:* 1	package interceptors
2	
3	import (
4		"github.com/klever-io/klever-go/core"
5		"github.com/klever-io/klever-go/core/process"
6		"github.com/klever-io/klever-go/network/p2p"
7		"github.com/klever-io/klever-go/tools/check"
8		"github.com/klever-io/klever-go/tools/debug/resolver"
9	)
10	
11	// ArgSingleDataInterceptor is the argument for the single-  …(+6001 more chars)
**→ Read**(file_path=/work/core/process/interceptors/processor/hdrInterceptorProcessor.go)
  ↳ *result:* 1	package processor
2	
3	import (
4		"sync"
5	
6		logger "github.com/klever-io/klever-go-logger"
7		"github.com/klever-io/klever-go/common"
8		"github.com/klever-io/klever-go/core"
9		"github.com/klever-io/klever-go/core/process"
10		"github.com/klever-io/klever-go/data"
11		"github.com/klever-io/klever-go/data/retriever"
12		"github.com/klever-io/  …(+3309 more chars)
**→ Read**(file_path=/work/core/process/interceptors/processor/txInterceptorProcessor.go)
  ↳ *result:* 1	package processor
2	
3	import (
4		"github.com/klever-io/klever-go/common"
5		"github.com/klever-io/klever-go/core"
6		"github.com/klever-io/klever-go/core/process"
7		"github.com/klever-io/klever-go/data/retriever"
8		"github.com/klever-io/klever-go/data/transaction"
9		"github.com/klever-io/klever-go/tools/check"
10	)
11	
12	var _ process.Inter  …(+3433 more chars)
**→ Read**(file_path=/work/common/errors.go, offset=770, limit=20)
  ↳ *result:* 770	var ErrInvalidMaxHardCapForMissingNodes = errors.New("invalid max hardcap for missing nodes")
771	
772	// ErrInvalidTransactionNoContract signals that transaction time has expired
773	var ErrTransactionTimeExpired = errors.New("transaction time expired")
774	
775	// ErrNotCompressed ...
776	var ErrNotCompressed = errors.New("not compressed")
77  …(+517 more chars)
**→ Read**(file_path=/work/core/process/errors.go, offset=50, limit=20)
  ↳ *result:* 50	// ErrNilWhiteListHandler signals that white list handler is nil
51	var ErrNilWhiteListHandler = errors.New("nil whitelist handler")
52	
53	// ErrEmptyPeerID signals that an empty peer ID has been provided
54	var ErrEmptyPeerID = errors.New("empty peer ID")
55	
56	// ErrNoDataInMessage signals that no data was found after parsing received p2p me  …(+771 more chars)
**Claude:** The decompression-bomb path in `batch.go` is the unremediated CWE-400. Let me check for existing size limits used elsewhere in the codebase to pick a consistent bound.

**→ Bash**(command=grep -rn "MaxBufferSizeToSendInBytes\|maxBuffToSend\|MaxMessageSize\|1024 \* 1024\|maxMessage\|MaxBuff" --include=*.go network/ common/ core  …(+46 more chars))
  ↳ *result:* common/mock/trieStub.go:155:func (ts *TrieStub) GetSerializedNodes(hash []byte, maxBuffToSend uint64) ([][]byte, uint64, error) {
common/mock/trieStub.go:157:		return ts.GetSerializedNodesCalled(hash, maxBuffToSend)
core/vmconstants.go:60:// MaxBufferSizeToSendTrieNodes represents max buffer size to send in bytes used when resolving trie nodes
core  …(+4120 more chars)
**→ Read**(file_path=/work/core/constants.go, offset=295, limit=15)
  ↳ *result:* 295	// MaxTransactionRaw defines the maximum size of the raw data without contracts and message data
296	const MaxTransactionRaw = 200
297	
298	// MaxTxSize defines the maximum size of a tx without contracts and message data
299	const MaxTxSize = 1900
300	
301	// MaxDataSize defines the maximum size of a data field
302	const MaxDataSize = 1024 * 10  …(+269 more chars)
**Claude:** The interceptor throttler-leak paths are already remediated (per the inline comments). The remaining unguarded CWE-400 is the gzip **decompression bomb** in `data/batch/batch.go`: `decompressGzip` does an unbounded `io.ReadAll`, so a tiny compressed payload from a peer can expand to gigabytes and exhaust memory. Let me check the p2p max message size to pick a consistent bound.

**→ Bash**(command=grep -rn "MaxMessageSize\|maxSendBuffSize\|1 << 2[0-9]\|MaxPacket\|messageSizeWarning\|maxMessageSize" --include=*.go network/ | grep -iv te  …(+13 more chars))
  ↳ *result:* network/p2p/libp2p/directSender.go:155:	if len(buff) >= maxSendBuffSize {
network/p2p/libp2p/directSender.go:156:		return fmt.Errorf("%w, to be sent: %d, maximum: %d", p2p.ErrMessageTooLarge, len(buff), maxSendBuffSize)
network/p2p/libp2p/netMessenger.go:67:var maxSendBuffSize = (1 << 20) - messageHeader
network/p2p/libp2p/netMessenger.go:784:	if l  …(+174 more chars)
**→ Read**(file_path=/work/network/p2p/libp2p/netMessenger.go, offset=60, limit=12)
  ↳ *result:* 60	const timeBetweenExternalLoggersCheck = time.Second * 20
61	const minRangePortValue = 1025
62	const noSignPolicy = pubsub.MessageSignaturePolicy(0) //should be used only in tests
63	
64	// TODO remove the header size of the message when commit d3c5ecd3a3e884206129d9f2a9a4ddfd5e7c8951 from
65	// https://github.com/libp2p/go-libp2p-pubsub/pull/189  …(+233 more chars)
**Claude:** Now I understand the bounds. The compressed wire message is capped at ~1MB (`maxSendBuffSize`), but the decompressed output is completely unbounded — that's the bomb. I'll bound decompression with a generous hard cap (64MB) that's far above any realistic batch yet defuses GB-scale expansion.

First, add an error constant in `common/errors.go`:

**→ Edit**(replace_all=false, file_path=/work/common/errors.go, old_string=// ErrNotCompressed ...
var ErrNotCompressed = errors.New("not compressed"), new_string=// ErrNotCompressed ...
var ErrNotCompressed = errors.New("not compressed")

// ErrDecompressedDataTooLarge signals that decompressing a bat  …(+135 more chars))
  ↳ *result:* The file /work/common/errors.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now remediate `data/batch/batch.go`. I'll bound the decompression so it can never expand beyond a hard cap, and reject batches whose declared `DataSize` already exceeds that cap (this also protects the LZ4 allocation path):

**→ Edit**(replace_all=false, file_path=/work/data/batch/batch.go, old_string=// New returns a new batch from given buffers
func New(buffs ...[]byte) *Batch {
	return &Batch{
		Data: buffs,
	}
}, new_string=// maxDecompressedBatchSize is the hard upper bound on the number of bytes a
// single batch is allowed to expand to when decompressed. It g  …(+428 more chars))
  ↳ *result:* The file /work/data/batch/batch.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/data/batch/batch.go, old_string=func decompressGzip(data []byte) ([]byte, error) {
	rdata := bytes.NewReader(data)

	reader, err := gzip.NewReader(rdata)
	if err != nil {
	  …(+178 more chars), new_string=func decompressGzip(data []byte, maxSize int) ([]byte, error) {
	rdata := bytes.NewReader(data)

	reader, err := gzip.NewReader(rdata)
	if e  …(+585 more chars))
  ↳ *result:* The file /work/data/batch/batch.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/data/batch/batch.go, old_string=func decompressLZ4(dataSize int32, data []byte) ([]byte, error) {
	return decompressGzip(data), new_string=func decompressLZ4(dataSize int32, data []byte) ([]byte, error) {
	return decompressGzip(data, maxDecompressedBatchSize))
  ↳ *result:* The file /work/data/batch/batch.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now update the `Decompress` method to validate the declared `DataSize` and pass the bound to the gzip path:

**→ Edit**(replace_all=false, file_path=/work/data/batch/batch.go, old_string=	if !ba.IsCompressed {
		return common.ErrNotCompressed
	}

	var result []byte
	var err error
	if ba.Algo == CType_LZ4 {
		result, err = dec  …(+161 more chars), new_string=	if !ba.IsCompressed {
		return common.ErrNotCompressed
	}

	// Reject batches whose declared uncompressed size already exceeds the hard
	//  …(+529 more chars))
  ↳ *result:* The file /work/data/batch/batch.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now verify it builds and check for any other callers of `decompressGzip`:

**→ Bash**(command=grep -rn "decompressGzip\|decompressLZ4" --include=*.go . | grep -v "func "; echo "---build---"; go build ./data/batch/... ./common/... 2>&1  …(+11 more chars))
  ↳ *result:* data/batch/batch.go:84:	return decompressGzip(data, maxDecompressedBatchSize)
data/batch/batch.go:140:		result, err = decompressLZ4(ba.DataSize, ba.Stream)
data/batch/batch.go:145:		result, err = decompressGzip(ba.Stream, maxDecompressedBatchSize)
---build---
go: downloading github.com/klever-io/klever-go-logger v1.3.1
go: downloading github.com/pk  …(+2108 more chars)
**Claude:** Build fails only due to egress-blocked dependency downloads, not my changes. Let me verify my edits are syntactically valid with `gofmt`:

**→ Bash**(command=gofmt -l -e data/batch/batch.go common/errors.go && echo "gofmt OK (no issues)")
  ↳ *result:* gofmt OK (no issues)
**Claude:** Both files are syntactically valid and properly formatted. Let me confirm no in-package tests reference the changed unexported signatures:

**→ Bash**(command=grep -rn "decompressGzip\|decompressLZ4\|maxDecompressedBatchSize" data/batch/*_test.go 2>/dev/null; echo "exit: $?")
  ↳ *result:* exit: 1
**Claude:** No tests reference the changed internal functions. Let me show the final state of the remediated function:

**→ Read**(file_path=/work/data/batch/batch.go, offset=42, limit=22)
  ↳ *result:* 42	func decompressGzip(data []byte, maxSize int) ([]byte, error) {
43		rdata := bytes.NewReader(data)
44	
45		reader, err := gzip.NewReader(rdata)
46		if err != nil {
47			return nil, err
48		}
49	
50		// Bound the number of bytes pulled from the decompressor to maxSize to
51		// prevent decompression-bomb attacks (CWE-400). We allow reading up to
  …(+338 more chars)
**Claude:** I've remediated the Uncontrolled Resource Consumption (CWE-400) vulnerability.

## Summary

**The vulnerability:** `data/batch/batch.go` decompressed peer-supplied batch payloads with an unbounded `io.ReadAll(reader)`. Incoming P2P messages are capped at ~1MB on the wire (`maxSendBuffSize`), but the *decompressed* output was unbounded — a classic **decompression bomb**. A malicious peer could send a tiny compressed batch that expands to gigabytes, exhausting node memory. The `Decompress` path is reached from the interceptors (`MultiDataInterceptor.ProcessReceivedMessage`) on attacker-controlled data. Additionally, the (declared, attacker-controlled) `DataSize` field feeds the LZ4 allocation path.

**The fix (behavior-preserving):**

1. `common/errors.go` — added `ErrDecompressedDataTooLarge`.

2. `data/batch/batch.go`:
   - Added a hard cap `maxDecompressedBatchSize = 64MB` — far above any legitimate batch (wire messages are <1MB) but well below memory-exhaustion levels.
   - `decompressGzip` now takes a `maxSize` and reads through an `io.LimitReader(reader, maxSize+1)`, rejecting any stream that expands past the cap instead of reading it all into memory.
   - `Decompress` validates the declared `ba.DataSize` against the cap up front (rejecting negative or oversized values before any work), protecting the LZ4 allocation path, and passes the cap to both decompress paths.

Legitimate batches (which are far under 64MB and carry a correct `DataSize`) decompress exactly as before; only pathological/bomb payloads are rejected. The throttler-slot-leak portions of CWE-400 flagged in the finding were already remediated in the interceptors (per their inline comments referencing GHSA-74m6-4hjp-7226 / KLC-2348), and I verified those paths release the slot exactly once.

Verified: `gofmt` reports both files syntactically valid and properly formatted; no tests reference the changed unexported signatures. (A full `go build` can't run here because dependency downloads are blocked by the egress allowlist — unrelated to these edits.)

No commits, pushes, or behavioral changes were made beyond the security bound.


---
**Final (success):** I've remediated the Uncontrolled Resource Consumption (CWE-400) vulnerability.

## Summary

**The vulnerability:** `data/batch/batch.go` decompressed peer-supplied batch payloads with an unbounded `io.ReadAll(reader)`. Incoming P2P messages are capped at ~1MB on the wire (`maxSendBuffSize`), but the *decompressed* output was unbounded — a classic **decompression bomb**. A malicious peer could send a tiny compressed batch that expands to gigabytes, exhausting node memory. The `Decompress` path is reached from the interceptors (`MultiDataInterceptor.ProcessReceivedMessage`) on attacker-controlled data. Additionally, the (declared, attacker-controlled) `DataSize` field feeds the LZ4 allocation path.

**The fix (behavior-preserving):**

1. `common/errors.go` — added `ErrDecompressedDataTooLarge`.

2. `data/batch/batch.go`:
   - Added a hard cap `maxDecompressedBatchSize = 64MB` — far above any legitimate batch (wire messages are <1MB) but well below memory-exhaustion levels.
   - `decompressGzip` now takes a `maxSize` and reads through an `io.LimitReader(reader, maxSize+1)`, rejecting any stream that expands past the cap instead of reading it all into memory.
   - `Decompress` validates the declared `ba.DataSize` against the cap up front (rejecting negative or oversized values before any work), protecting the LZ4 allocation path, and passes the cap to both decompress paths.

Legitimate batches (which are far under 64MB and carry a correct `DataSize`) decompress exactly as before; only pathological/bomb payloads are rejected. The throttler-slot-leak portions of CWE-400 flagged in the finding were already remediated in the interceptors (per their inline comments referencing GHSA-74m6-4hjp-7226 / KLC-2348), and I verified those paths release the slot exactly once.

Verified: `gofmt` reports both files syntactically valid and properly formatted; no tests reference the changed unexported signatures. (A full `go build` can't run here because dependency downloads are blocked by the egress allowlist — unrelated to these edits.)

No commits, pushes, or behavioral changes were made beyond the security bound.

*turns 23 · cost $0.974*
