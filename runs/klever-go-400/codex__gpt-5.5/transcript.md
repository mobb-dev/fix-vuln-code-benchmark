**Codex:** I’ll inspect the finding and the affected code first, then make the smallest source changes that close the vulnerability without changing behavior.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: klever-io/klever-go
Vulnerability type: Uncontrolled Resource Consumption (CWE-400)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  common/errors.go
    - lines 778-783   in: var ErrNotCompressed = errors.New("not compressed")

  core/process/errors.go
    - lines 56-61   in: var ErrEmptyPeerID = errors.New("empty peer ID")

  core/process/interceptors/baseDataInterceptor.go
    - lines 18-24   in: type baseDataInterceptor struct {
    - lines 2  …(+1698 more chars)
```
**→ shell:** `/bin/bash -lc 'pwd && rg --files'`
```
SECURITY.md
go.sum
sharding/errors.go
sharding/indexHashedNodesCoordinatorRegistry.go
sharding/nodesSetup_test.go
sharding/hashValidatorShuffler_test.go
sharding/common.go
sharding/validator_test.go
sharding/args.go
sharding/networksharding/nodesCoordinatorStub.go
sharding/networksharding/mock_test.go
sharding/networksharding/peerShardMapper_test.go
sharding/networksharding/export_test.go
sharding/networksharding/peerShardMapper.go
sharding/networksharding/pidQueue.go
sharding/networksharding/pi  …(+122951 more chars)
```
**Codex:** The finding points at compressed batch handling and interceptor paths. I’m narrowing this to how inbound compressed data is decompressed and forwarded, then I’ll add bounds where untrusted data expands.

**→ shell:** `/bin/bash -lc "sed -n '1,180p' data/batch/batch.go"`
```
//go:generate protoc -I=proto -I=$GOPATH/src -I=$GOPATH/src/github.com/klever-io/klever-go/protobuf --go_out=. batch.proto
package batch

import (
	bytes "bytes"
	"compress/gzip"
	"io"

	//lz4 "github.com/DataDog/golz4"

	"github.com/klever-io/klever-go/common"
	"github.com/klever-io/klever-go/tools/marshal"
)

// New returns a new batch from given buffers
func New(buffs ...[]byte) *Batch {
	return &Batch{
		Data: buffs,
	}
}

func compressGzip(data []byte) ([]byte, error) {
	var b bytes.Buffer
  …(+2036 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,190p' core/process/interceptors/baseDataInterceptor.go"`
```
package interceptors

import (
	"bytes"
	"sync"

	"github.com/klever-io/klever-go/common"
	"github.com/klever-io/klever-go/core"
	"github.com/klever-io/klever-go/core/process"
	"github.com/klever-io/klever-go/network/p2p"
	"github.com/klever-io/klever-go/tools/check"
)

type baseDataInterceptor struct {
	throttler        process.InterceptorThrottler
	antifloodHandler process.P2PAntifloodHandler
	topic            string
	currentPeerID    core.PeerID
	processor        process.InterceptorProcessor
  …(+2931 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,190p' core/process/interceptors/multiDataInterceptor.go"`
```
package interceptors

import (
	"github.com/klever-io/klever-go/core"
	"github.com/klever-io/klever-go/core/process"
	"github.com/klever-io/klever-go/data/batch"
	"github.com/klever-io/klever-go/network/p2p"
	"github.com/klever-io/klever-go/tools/check"
	"github.com/klever-io/klever-go/tools/debug/resolver"
	"github.com/klever-io/klever-go/tools/marshal"
)

// ArgMultiDataInterceptor is the argument for the multi-data interceptor
type ArgMultiDataInterceptor struct {
	Topic            string
	Ma  …(+5865 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,190p' core/process/interceptors/singleDataInterceptor.go"`
```
package interceptors

import (
	"github.com/klever-io/klever-go/core"
	"github.com/klever-io/klever-go/core/process"
	"github.com/klever-io/klever-go/network/p2p"
	"github.com/klever-io/klever-go/tools/check"
	"github.com/klever-io/klever-go/tools/debug/resolver"
)

// ArgSingleDataInterceptor is the argument for the single-data interceptor
type ArgSingleDataInterceptor struct {
	Topic            string
	DataFactory      process.InterceptedDataFactory
	Processor        process.InterceptorProcess  …(+5291 more chars)
```
**Codex:** The vulnerable expansion point is `Batch.Decompress`: gzip is read with `io.ReadAll`, so a small inbound message can expand without a cap before antiflood accounting sees item count. I’m checking the error conventions and tests around batch so the fix fits the project.

**→ shell:** `/bin/bash -lc "sed -n '740,810p' common/errors.go"`
```
var ErrInvalidTransactionType = errors.New("invalid transaction type")

// ErrTokenNameNotHumanReadable signals that token name is not human readable
var ErrTokenNameNotHumanReadable = errors.New("token name is not human readable")

// ErrTickerNameNotValid signals that ticker name is not valid
var ErrTickerNameNotValid = errors.New("ticker name is not valid")

// ErrInvalidContract signals an invalid contract sent
var ErrInvalidContract = errors.New("invalid contract")

// ErrNoPermission signa  …(+2589 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' data/batch/batch_test.go"`
```
package batch_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/klever-io/klever-go/data/batch"
	"github.com/klever-io/klever-go/tools/marshal/factory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func addRandom(b [][]byte, len int) [][]byte {
	for i := 0; i < len; i++ {
		data := []byte(fmt.Sprintf("%04d-abcdefghijklmnopqrstuvwxyz%f ", i, float64(i)*math.Pi))
		b = append(b, data)
	}
	return b
}

func TestGZIP(t *testing.T) {
	internalMarshalizer, err :=   …(+2373 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,90p' core/process/errors.go"`
```
package process

import "errors"

// ErrNilQuotaStatusHandler signals that a nil quota status handler has been provided
var ErrNilQuotaStatusHandler = errors.New("nil quota status handler")

// ErrEmptyFloodPreventerList signals that an empty flood preventer list has been provided
var ErrEmptyFloodPreventerList = errors.New("empty flood preventer provided")

// ErrNilTopicFloodPreventer signals that a nil topic flood preventer has been provided
var ErrNilTopicFloodPreventer = errors.New("nil top  …(+4054 more chars)
```
**→ shell:** `/bin/bash -lc "rg \"DataSize|Decompress\\(|ErrNotCompressed|ErrAlreadyCompressed|compressed\" data/batch common core/process -n"`
```
core/process/economics/economicsData_test.go:138:		assert.Equal(t, int64(700), cost.BandwidthFee) // (100 (DataSize) + 250 (BaseTxSize)) * 2 (FeePerDataByte)
core/process/economics/economicsData_test.go:167:		assert.Equal(t, int64(700), cost.BandwidthFee)  // (100 (DataSize) + 250 (BaseTxSize)) * 2 (FeePerDataByte)
core/process/economics/economicsData_test.go:280:				BandwidthFee: 350, // (100 (DataSize) + 250 (BaseTxSize)) * 1 (FeePerDataByte)
core/process/economics/economicsData.go:106:		Bandw  …(+1389 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '560,680p' core/process/interceptors/multiDataInterceptor_test.go"`
```
}

func TestMultiDataInterceptor_RegisterHandler(t *testing.T) {
	t.Parallel()

	arg := createMockArgMultiDataInterceptor()
	wasCalled := false
	arg.Processor = &mock.InterceptorProcessorStub{
		RegisterHandlerCalled: func(handler func(topic string, hash []byte, data interface{})) {
			wasCalled = true
		},
	}

	mdi, _ := interceptors.NewMultiDataInterceptor(arg)
	mdi.RegisterHandler(nil)

	assert.True(t, wasCalled)
}

//------- IsInterfaceNil

func TestMultiDataInterceptor_IsInterfaceNil(t *tes  …(+3058 more chars)
```
**→ shell:** `/bin/bash -lc "rg \"Max.*Size|size.*message|CanProcessMessagesOnTopic|Interceptor\" core common network data -g'*.go' -n"`
```
core/process/block/block_test.go:912:		cs.MaxSizeCalled = func() int {
core/process/block/block_test.go:1052:		cs.MaxSizeCalled = func() int {
core/process/block/block_test.go:1140:		cs.MaxSizeCalled = func() int {
core/process/block/block_test.go:1392:					MaxSizeCalled: func() int {
core/process/block/block_test.go:1429:				MaxSizeCalled: func() int {
core/process/block/block_test.go:1454:			cs.MaxSizeCalled = func() int {
core/process/block/block_test.go:1821:		cs.MaxSizeCalled = func() int {  …(+131439 more chars)
```
**Codex:** There is already regression coverage for throttler-slot leaks; this finding is a different CWE-400 path in the same area. I’m going to enforce the declared uncompressed size during decompression and reject invalid compressed batches before allocation grows beyond that bound.

**→ shell:** `/bin/bash -lc "sed -n '1,90p' network/p2p/libp2p/netMessenger.go"`
```
package libp2p

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	logging "github.com/ipfs/go-log/v2"
	logger "github.com/klever-io/klever-go-logger"
	"github.com/klever-io/klever-go/common/types"
	"github.com/klever-io/klever-go/config"
	"github.com/klever-io/klever-go/core"
	"github.com/klever-io/klever-go/core/throttler"
	"github.com/klever-io/klever-go/network/p2p"
	"github.com/klever-io/klever-go/ne  …(+3101 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' common/constants.go"`
```
package common

import "time"

// DefaultDirPermission represents the default directory permissions
const DefaultDirPermission = 0750

// FileModeUserReadWrite represents the permission for a file which allows the user for reading and writing
const FileModeUserReadWrite = 0600

// BaseOperationCost represents the field name for base operation costs
const BaseOperationCost = "BaseOperationCost"

// BuiltInCost represents the field name for built-in operation costs
const BuiltInCost = "BuiltInCost  …(+6262 more chars)
```
**→ shell:** `/bin/bash -lc 'rg "MaxBulkTransactionSize|Max.*Bulk|Max.*Message|MaxSendBuffSize|maxSendBuffSize|MaxBatch" core common config -n'`
```
core/process/interface.go:109:	SetMaxMessagesForTopic(topic string, maxNum uint32)
core/constants.go:126:// MaxBulkTransactionSize specifies the maximum size of one bulk with txs which can be send over the network
core/constants.go:128:const MaxBulkTransactionSize = 1 << 18 //256KB bulks
core/process/mock/topicFloodPreventerStub.go:9:	SetMaxMessagesForTopicCalled func(topic string, num uint32)
core/process/mock/topicFloodPreventerStub.go:32:// SetMaxMessagesForTopic -
core/process/mock/topicFloo  …(+23165 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '118,138p' core/constants.go"`
```
const MaxTxNonceDeltaAllowed = 100

// DefaultUnstakedEpoch represents the default epoch that is set for a validator that has not unstaked yet
const DefaultUnstakedEpoch = math.MaxUint32

// DefaultUndelegatedEpoch represents the default epoch that is set for a validator that has not undelegated yet
const DefaultUndelegatedEpoch = math.MaxUint32

// MaxBulkTransactionSize specifies the maximum size of one bulk with txs which can be send over the network
// TODO convert this const into a var and   …(+440 more chars)
```
**→ shell:** `/bin/bash -lc 'rg "func .*PackDataInChunks|PackDataInChunks" -n'`
```
data/retriever/resolvers/transactionResolver.go:217:	buffsToSend, errPack := txRes.dataPacker.PackDataInChunks(txsBuffSlice, maxBuffToSendBulkTransactions)
data/retriever/resolvers/transactionResolver_test.go:394:		PackDataInChunksCalled: func(data [][]byte, limit int) ([][]byte, error) {
data/retriever/resolvers/transactionResolver_test.go:453:		PackDataInChunksCalled: func(data [][]byte, limit int) ([][]byte, error) {
data/retriever/storageResolvers/sliceResolver.go:114:	buffsToSend, errPack :  …(+4910 more chars)
```
**Codex:** The outbound packer already builds compressed batches from a bounded uncompressed buffer. To preserve intended traffic while rejecting malicious payloads, I’ll mirror that protocol invariant in `data/batch` rather than letting a peer choose an arbitrary expansion size.

**→ shell:** `/bin/bash -lc "sed -n '1,130p' core/partitioning/simpleDataPacker.go"`
```
package partitioning

import (
	logger "github.com/klever-io/klever-go-logger"
	"github.com/klever-io/klever-go/common"
	"github.com/klever-io/klever-go/data/batch"
	"github.com/klever-io/klever-go/data/retriever"
	"github.com/klever-io/klever-go/tools/marshal"
)

var _ retriever.DataPacker = (*SimpleDataPacker)(nil)

var log = logger.GetOrCreate("SimpleDataPacker")

// SimpleDataPacker can split a large slice of byte slices in chunks <= maxPacketSize
// If one element still exceeds maxPacketSiz  …(+2414 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,115p' core/partitioning/sizeDataPacker.go"`
```
package partitioning

import (
	"github.com/klever-io/klever-go/common"
	"github.com/klever-io/klever-go/data/batch"
	"github.com/klever-io/klever-go/data/retriever"
	"github.com/klever-io/klever-go/tools/marshal"
)

var _ retriever.DataPacker = (*SizeDataPacker)(nil)

const minimumMaxPacketSizeInBytes = 1

// SizeDataPacker can split a large slice of byte slices in chunks <= maxPacketSize
// If one element still exceeds maxPacketSize, it will be returned alone
// It does the marshaling of the r  …(+2246 more chars)
```
**→ shell:** `/bin/bash -lc 'rg "New.*DataPacker|SizeDataPacker|SimpleDataPacker" -n core node factory data/retriever | head -80'`
```
/simpleDataPacker.go:21:type SimpleDataPacker struct {
core/partitioning/simpleDataPacker.go:25:// NewSimpleDataPacker creates a new SizeDataPacker instance
core/partitioning/simpleDataPacker.go:26:func NewSimpleDataPacker(marshalizer marshal.Marshalizer) (*SimpleDataPacker, error) {
core/partitioning/simpleDataPacker.go:31:	return &SimpleDataPacker{
core/partitioning/simpleDataPacker.go:38:func (sdp *SimpleDataPacker) PackDataInChunks(data [][]byte, limit int) ([][]byte, error) {
core/partition  …(+2169 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '100,122p' data/retriever/storageResolvers/sliceResolver.go"`
```
	for _, hash := range hashes {
		mb, errTemp := sliceRes.storage.Get(hash)
		if errTemp != nil {
			errFetch = fmt.Errorf("%w for hash %s", errTemp, logger.DisplayByteSlice(hash))
			log.Trace("fetchMbAsByteSlice missing",
				"error", errFetch.Error(),
				"hash", hash)
			errorsFound++

			continue
		}
		mbsBuffSlice = append(mbsBuffSlice, mb)
	}

	buffsToSend, errPack := sliceRes.dataPacker.PackDataInChunks(mbsBuffSlice, maxBuffToSend)
	if errPack != nil {
		return errPack
	}

	for _, buff :=  …(+100 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '190,230p' data/retriever/resolvers/transactionResolver.go"`
```
	hashes := b.Data

	var errFetch error
	errorsFound := 0
	txsBuffSlice := make([][]byte, 0, len(hashes))
	for _, hash := range hashes {
		tx, errTemp := txRes.fetchTxAsByteSlice(hash)
		if errTemp != nil {
			errFetch = fmt.Errorf("%w for hash %s", errTemp, logger.DisplayByteSlice(hash))
			//it might happen to error on a tx (maybe it is missing) but should continue
			// as to send back as many as it can
			log.Trace("fetchTxAsByteSlice missing",
				"error", errFetch.Error(),
				"hash", hash)  …(+580 more chars)
```
**→ shell:** `/bin/bash -lc 'rg "maxBuffToSend|maxBuffToSendBulkTransactions" -n data core'`
**Codex:** I’m making two coordinated changes: `Batch.Decompress` will stream through a size-limited reader and verify the decompressed byte count matches `DataSize`, and `MultiDataInterceptor` will account the declared uncompressed size with antiflood before doing decompression. That closes the expansion path while keeping valid compressed batches flowing as before.

**✎ files:** update `/work/common/errors.go`

**✎ files:** update `/work/data/batch/batch.go`

**Codex:** The decompressor now refuses oversized, negative, truncated, or over-expanding compressed batches without reading the whole stream. I’m adding the interceptor-side accounting before decompression so the peer’s quota is charged for the uncompressed payload, not just the compressed envelope.

**✎ files:** update `/work/core/process/interceptors/multiDataInterceptor.go`

**Codex:** The interceptor change references the shared error type, so I’m updating imports and adding focused tests that exercise the resource-consumption case instead of relying only on the old malformed-gzip tests.

**✎ files:** update `/work/core/process/interceptors/multiDataInterceptor.go`

**→ shell:** `/bin/bash -lc "sed -n '1,130p' common/mock/p2pAntifloodHandlerStub.go"`
```
package mock

import (
	"time"

	"github.com/klever-io/klever-go/core"
	"github.com/klever-io/klever-go/core/process"
	"github.com/klever-io/klever-go/network/p2p"
)

// P2PAntifloodHandlerStub -
type P2PAntifloodHandlerStub struct {
	CanProcessMessageCalled            func(message p2p.MessageP2P, fromConnectedPeer core.PeerID) error
	CanProcessMessagesOnTopicCalled    func(peer core.PeerID, topic string, numMessages uint32, totalSize uint64, sequence []byte) error
	ApplyConsensusSizeCalled       …(+2792 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,120p' core/process/interceptors/multiDataInterceptor_test.go"`
```
package interceptors_test

import (
	"bytes"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klever-io/klever-go/common"
	"github.com/klever-io/klever-go/common/mock"
	"github.com/klever-io/klever-go/core"
	"github.com/klever-io/klever-go/core/process"
	"github.com/klever-io/klever-go/core/process/interceptors"
	"github.com/klever-io/klever-go/core/throttler"
	"github.com/klever-io/klever-go/data/batch"
	"github.com/klever-io/klever-go/tools/check"
	"github.com/stretchr/testify/  …(+2875 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,120p' common/mock/marshalizerMock.go"`
```
package mock

import (
	"encoding/json"
	"errors"
)

var errMockMarshalizer = errors.New("MarshalizerMock generic error")

// MarshalizerMock that will be used for testing
type MarshalizerMock struct {
	Fail bool
}

// Marshal converts the input object in a slice of bytes
func (mm *MarshalizerMock) Marshal(obj interface{}) ([]byte, error) {
	if mm.Fail {
		return nil, errMockMarshalizer
	}

	if obj == nil {
		return nil, errors.New("nil object to serilize from")
	}

	return json.Marshal(obj)
}

  …(+609 more chars)
```
**Codex:** I found the test marshalizer uses JSON, while production can use protobuf; the size checks work at the compressed batch layer for both. I’m covering the exact failure modes: declared size too small for the gzip stream, and declared size beyond the accepted batch limit.

**✎ files:** update `/work/data/batch/batch_test.go`

**✎ files:** update `/work/core/process/interceptors/multiDataInterceptor_test.go`

**Codex:** The focused tests are in place. I’m formatting the touched Go files and then running the batch and interceptor test packages to catch compile issues and behavioral regressions.

**→ shell:** `/bin/bash -lc 'gofmt -w common/errors.go data/batch/batch.go data/batch/batch_test.go core/process/interceptors/multiDataInterceptor.go core/process/interceptors/multiDataInterceptor_test.go'`
```
/bin/bash: line 1: gofmt: command not found

```
**→ shell:** `/bin/bash -lc 'git diff -- common/errors.go data/batch/batch.go data/batch/batch_test.go core/process/interceptors/multiDataInterceptor.go core/process/interceptors/multiDataInterceptor_test.go'`
```
diff --git a/common/errors.go b/common/errors.go
index 5cc8991..3f744a2 100644
--- a/common/errors.go
+++ b/common/errors.go
@@ -778,6 +778,9 @@ var ErrNotCompressed = errors.New("not compressed")
 // ErrAlreadyCompressed ...
 var ErrAlreadyCompressed = errors.New("already compressed")
 
+// ErrInvalidCompressedDataSize signals that a compressed batch has an invalid decompressed size
+var ErrInvalidCompressedDataSize = errors.New("invalid compressed data size")
+
 // ErrInvalidParameter signals   …(+6773 more chars)
```
**Codex:** This environment does not have `gofmt` on `PATH`, so I can’t format or run Go tests in the usual way yet. I’m checking whether a Go toolchain exists elsewhere in the image before I fall back to manual formatting review.

**→ shell:** `/bin/bash -lc 'command -v go || true'`
**→ shell:** `/bin/bash -lc 'find /usr /usr/local /opt -name go -type f 2>/dev/null | head -20'`
```
/usr/local/go/bin/go
/usr/local/go/bin/go

```
**→ shell:** `/bin/bash -lc 'find /usr /usr/local /opt -name gofmt -type f 2>/dev/null | head -20'`
```
/usr/local/go/bin/gofmt
/usr/local/go/bin/gofmt

```
**Codex:** A Go toolchain is installed under `/usr/local/go/bin`, just not on `PATH`. I’m using that directly for formatting and targeted tests.

**→ shell:** `/bin/bash -lc '/usr/local/go/bin/gofmt -w common/errors.go data/batch/batch.go data/batch/batch_test.go core/process/interceptors/multiDataInterceptor.go core/process/interceptors/multiDataInterceptor  …(+79 more chars)`
```
go: downloading google.golang.org/protobuf v1.36.11
go: downloading github.com/stretchr/testify v1.11.1
go: downloading github.com/klever-io/klever-go-logger v1.3.1
go: downloading github.com/mr-tron/base58 v1.2.0
go: downloading github.com/gogo/protobuf v1.3.2
go: downloading github.com/multiformats/go-base36 v0.2.0
go: downloading github.com/pkg/errors v0.9.1
go: downloading golang.org/x/crypto v0.49.0
go: downloading github.com/hashicorp/golang-lru v1.0.2
go: downloading gopkg.in/yaml.v2 v2.4  …(+3446 more chars)
```
**Codex:** Formatting completed. The targeted `go test` run is blocked because required modules are not present locally and proxy downloads are denied by the network allowlist; I’m still doing a local compile-oriented review of the diff for obvious issues.

**→ shell:** `/bin/bash -lc 'git diff -- common/errors.go data/batch/batch.go data/batch/batch_test.go core/process/interceptors/multiDataInterceptor.go core/process/interceptors/multiDataInterceptor_test.go'`
```
diff --git a/common/errors.go b/common/errors.go
index 5cc8991..3f744a2 100644
--- a/common/errors.go
+++ b/common/errors.go
@@ -778,6 +778,9 @@ var ErrNotCompressed = errors.New("not compressed")
 // ErrAlreadyCompressed ...
 var ErrAlreadyCompressed = errors.New("already compressed")
 
+// ErrInvalidCompressedDataSize signals that a compressed batch has an invalid decompressed size
+var ErrInvalidCompressedDataSize = errors.New("invalid compressed data size")
+
 // ErrInvalidParameter signals   …(+6773 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,165p' data/batch/batch.go && sed -n '96,132p' core/process/interceptors/multiDataInterceptor.go"`
```
//go:generate protoc -I=proto -I=$GOPATH/src -I=$GOPATH/src/github.com/klever-io/klever-go/protobuf --go_out=. batch.proto
package batch

import (
	bytes "bytes"
	"compress/gzip"
	"io"

	//lz4 "github.com/DataDog/golz4"

	"github.com/klever-io/klever-go/common"
	"github.com/klever-io/klever-go/tools/marshal"
)

const maxDecompressedBatchSize = 1 << 20

// New returns a new batch from given buffers
func New(buffs ...[]byte) *Batch {
	return &Batch{
		Data: buffs,
	}
}

func compressGzip(data []by  …(+3454 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M common/errors.go
 M core/process/interceptors/multiDataInterceptor.go
 M core/process/interceptors/multiDataInterceptor_test.go
 M data/batch/batch.go
 M data/batch/batch_test.go

```
**Codex:** The diff is formatted and internally consistent. The remaining verification gap is external module availability; since downloads are blocked, I’m checking whether the module cache already has these dependencies under the Go path before concluding tests can’t run here.

**→ shell:** `/bin/bash -lc '/usr/local/go/bin/go env GOPATH GOMODCACHE GOPROXY'`
```
/go
/go/pkg/mod
https://proxy.golang.org,direct

```
**→ shell:** `/bin/bash -lc 'ls -d /root/go/pkg/mod/google.golang.org/protobuf* /root/go/pkg/mod/github.com/klever-io/klever-go-logger* 2>/dev/null || true'`
**Codex:** The configured module cache is empty for the needed packages, so the failed tests are an environment limitation rather than a code failure. I’m doing one final status/diff pass and then I’ll summarize exactly what changed and what could not be verified.

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff --stat'`
```
 common/errors.go                                   |  3 ++
 core/process/interceptors/multiDataInterceptor.go  | 15 ++++++++
 .../interceptors/multiDataInterceptor_test.go      | 44 ++++++++++++++++++++++
 data/batch/batch.go                                | 26 +++++++++----
 data/batch/batch_test.go                           | 37 ++++++++++++++++++
 5 files changed, 118 insertions(+), 7 deletions(-)

```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M common/errors.go
 M core/process/interceptors/multiDataInterceptor.go
 M core/process/interceptors/multiDataInterceptor_test.go
 M data/batch/batch.go
 M data/batch/batch_test.go

```
**Codex:** Implemented the remediation for the compressed batch resource-consumption issue.

Changed:
- [data/batch/batch.go](/work/data/batch/batch.go): `Decompress` now validates `DataSize`, caps decompressed batches at 1 MiB, reads through `io.LimitedReader`, and rejects streams that expand beyond or differ from the declared size.
- [core/process/interceptors/multiDataInterceptor.go](/work/core/process/interceptors/multiDataInterceptor.go): compressed inbound batches now charge antiflood quota using declared decompressed size before decompression.
- [common/errors.go](/work/common/errors.go): added `ErrInvalidCompressedDataSize`.
- Added focused regression tests in [data/batch/batch_test.go](/work/data/batch/batch_test.go) and [core/process/interceptors/multiDataInterceptor_test.go](/work/core/process/interceptors/multiDataInterceptor_test.go).

Verification:
- Ran `/usr/local/go/bin/gofmt` successfully.
- Ran `git diff --check` successfully.
- Could not complete `go test ./data/batch ./core/process/interceptors` because required Go modules are not cached locally and downloads from `proxy.golang.org` are blocked by the environment allowlist.


---
*tokens — input 1298432 (cached 1174144), output 7999, reasoning 2520*
