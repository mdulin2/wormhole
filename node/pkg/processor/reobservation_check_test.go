package processor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certusone/wormhole/node/pkg/common"
	guardianDB "github.com/certusone/wormhole/node/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"go.uber.org/zap"
)

func testReobsMsg(payload []byte) *common.MessagePublication {
	return &common.MessagePublication{
		Timestamp:        time.Unix(1700000000, 0),
		Nonce:            1,
		Sequence:         42,
		ConsistencyLevel: 1,
		EmitterChain:     vaa.ChainIDSui,
		EmitterAddress:   vaa.Address{1, 2, 3},
		Payload:          payload,
		IsReobservation:  true,
	}
}

// wormholescanServer returns an httptest server that serves the given VAA (base64) for any
// vaas path, or a 404/500 if vaaB64 is empty / status is set. It records whether it was hit.
func wormholescanServer(t *testing.T, status int, vaaB64 string, hit *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hit != nil {
			*hit = true
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"vaa": vaaB64}})
	}))
}

func signedVAAB64(t *testing.T, msg *common.MessagePublication) string {
	t.Helper()
	v := msg.CreateVAA(0)
	// Give it a dummy signature so it round-trips as a "signed" VAA.
	v.Signatures = []*vaa.Signature{{Index: 0}}
	b, err := v.Marshal()
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(b)
}

func TestVerifyReobservation(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("off returns true", func(t *testing.T) {
		hit := false
		srv := wormholescanServer(t, http.StatusOK, "", &hit)
		defer srv.Close()
		ConfigureReobservationCheck(ReobsCheckOff, srv.URL)
		assert.True(t, VerifyReobservation(ctx, logger, nil, testReobsMsg([]byte("x"))))
		assert.False(t, hit, "no HTTP call when off")
	})

	t.Run("non-reobservation returns true", func(t *testing.T) {
		hit := false
		srv := wormholescanServer(t, http.StatusOK, "", &hit)
		defer srv.Close()
		ConfigureReobservationCheck(ReobsCheckAll, srv.URL)
		msg := testReobsMsg([]byte("x"))
		msg.IsReobservation = false
		assert.True(t, VerifyReobservation(ctx, logger, nil, msg))
		assert.False(t, hit, "no HTTP call for a non-reobservation")
	})

	t.Run("remote match publishes", func(t *testing.T) {
		msg := testReobsMsg([]byte("hello"))
		srv := wormholescanServer(t, http.StatusOK, signedVAAB64(t, msg), nil)
		defer srv.Close()
		ConfigureReobservationCheck(ReobsCheckRemote, srv.URL)
		assert.True(t, VerifyReobservation(ctx, logger, nil, msg))
	})

	t.Run("remote mismatch drops", func(t *testing.T) {
		msg := testReobsMsg([]byte("hello"))
		// Server returns a VAA with a different payload -> different digest.
		other := testReobsMsg([]byte("DIFFERENT"))
		srv := wormholescanServer(t, http.StatusOK, signedVAAB64(t, other), nil)
		defer srv.Close()
		ConfigureReobservationCheck(ReobsCheckRemote, srv.URL)
		assert.False(t, VerifyReobservation(ctx, logger, nil, msg))
	})

	t.Run("remote 404 publishes", func(t *testing.T) {
		srv := wormholescanServer(t, http.StatusNotFound, "", nil)
		defer srv.Close()
		ConfigureReobservationCheck(ReobsCheckRemote, srv.URL)
		assert.True(t, VerifyReobservation(ctx, logger, nil, testReobsMsg([]byte("x"))))
	})

	t.Run("remote 500 fails open", func(t *testing.T) {
		srv := wormholescanServer(t, http.StatusInternalServerError, "", nil)
		defer srv.Close()
		ConfigureReobservationCheck(ReobsCheckRemote, srv.URL)
		assert.True(t, VerifyReobservation(ctx, logger, nil, testReobsMsg([]byte("x"))))
	})

	t.Run("local-only mode never consults Wormholescan", func(t *testing.T) {
		msg := testReobsMsg([]byte("hello"))
		db := guardianDB.OpenDb(nil, nil)
		defer db.Close() // empty DB -> local miss

		hit := false
		srv := wormholescanServer(t, http.StatusOK, signedVAAB64(t, msg), &hit)
		defer srv.Close()
		ConfigureReobservationCheck(ReobsCheckLocal, srv.URL)

		assert.True(t, VerifyReobservation(ctx, logger, db, msg), "local miss publishes")
		assert.False(t, hit, "local mode must not hit Wormholescan")
	})

	t.Run("local match publishes", func(t *testing.T) {
		msg := testReobsMsg([]byte("hello"))
		db := guardianDB.OpenDb(nil, nil)
		defer db.Close()
		stored := msg.CreateVAA(0)
		stored.Signatures = []*vaa.Signature{{Index: 0}}
		require.NoError(t, db.StoreSignedVAA(stored))

		hit := false
		srv := wormholescanServer(t, http.StatusOK, "", &hit)
		defer srv.Close()
		ConfigureReobservationCheck(ReobsCheckAll, srv.URL)

		assert.True(t, VerifyReobservation(ctx, logger, db, msg))
		assert.False(t, hit, "local hit should skip Wormholescan")
	})

	t.Run("local mismatch drops without HTTP (all mode)", func(t *testing.T) {
		msg := testReobsMsg([]byte("hello"))
		db := guardianDB.OpenDb(nil, nil)
		defer db.Close()
		// Store a canonical VAA with the same (chain,emitter,seq) but a different payload.
		other := testReobsMsg([]byte("DIFFERENT"))
		stored := other.CreateVAA(0)
		stored.EmitterChain = msg.EmitterChain
		stored.EmitterAddress = msg.EmitterAddress
		stored.Sequence = msg.Sequence
		stored.Signatures = []*vaa.Signature{{Index: 0}}
		require.NoError(t, db.StoreSignedVAA(stored))

		hit := false
		srv := wormholescanServer(t, http.StatusOK, "", &hit)
		defer srv.Close()
		ConfigureReobservationCheck(ReobsCheckAll, srv.URL)

		assert.False(t, VerifyReobservation(ctx, logger, db, msg))
		assert.False(t, hit, "local mismatch should not consult Wormholescan")
	})

	t.Run("all mode: local miss falls back to wormholescan", func(t *testing.T) {
		msg := testReobsMsg([]byte("hello"))
		db := guardianDB.OpenDb(nil, nil)
		defer db.Close() // empty DB -> ErrVAANotFound

		hit := false
		srv := wormholescanServer(t, http.StatusOK, signedVAAB64(t, msg), &hit)
		defer srv.Close()
		ConfigureReobservationCheck(ReobsCheckAll, srv.URL)

		assert.True(t, VerifyReobservation(ctx, logger, db, msg))
		assert.True(t, hit, "local miss should consult Wormholescan in all mode")
	})
}

func TestParseReobsCheckMode(t *testing.T) {
	for in, want := range map[string]ReobsCheckMode{
		"":       ReobsCheckOff,
		"off":    ReobsCheckOff,
		"local":  ReobsCheckLocal,
		"remote": ReobsCheckRemote,
		"all":    ReobsCheckAll,
		"ALL":    ReobsCheckAll,
	} {
		got, err := ParseReobsCheckMode(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	_, err := ParseReobsCheckMode("bogus")
	assert.Error(t, err)

	assert.True(t, ReobsCheckAll.UsesLocal() && ReobsCheckAll.UsesRemote())
	assert.True(t, ReobsCheckLocal.UsesLocal() && !ReobsCheckLocal.UsesRemote())
	assert.True(t, !ReobsCheckRemote.UsesLocal() && ReobsCheckRemote.UsesRemote())
}

func TestWormholescanURLForEnv(t *testing.T) {
	url, ok := WormholescanURLForEnv(common.MainNet)
	assert.True(t, ok)
	assert.Equal(t, MainnetWormholescanURL, url)

	url, ok = WormholescanURLForEnv(common.TestNet)
	assert.True(t, ok)
	assert.Equal(t, TestnetWormholescanURL, url)

	_, ok = WormholescanURLForEnv(common.UnsafeDevNet)
	assert.False(t, ok)
}
