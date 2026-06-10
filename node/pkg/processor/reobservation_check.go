package processor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"

	"github.com/certusone/wormhole/node/pkg/common"
	guardianDB "github.com/certusone/wormhole/node/pkg/db"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
)

// ReobsCheckMode selects how a reobservation is verified before publishing.
type ReobsCheckMode uint8

const (
	ReobsCheckOff    ReobsCheckMode = iota // no check
	ReobsCheckLocal                        // compare against the local signed-VAA store only
	ReobsCheckRemote                       // compare against Wormholescan only
	ReobsCheckAll                          // local store first, then Wormholescan
)

// UsesLocal reports whether the mode consults the local signed-VAA store.
func (m ReobsCheckMode) UsesLocal() bool { return m == ReobsCheckLocal || m == ReobsCheckAll }

// UsesRemote reports whether the mode consults Wormholescan.
func (m ReobsCheckMode) UsesRemote() bool { return m == ReobsCheckRemote || m == ReobsCheckAll }

func (m ReobsCheckMode) String() string {
	switch m {
	case ReobsCheckLocal:
		return "local"
	case ReobsCheckRemote:
		return "remote"
	case ReobsCheckAll:
		return "all"
	default:
		return "off"
	}
}

// ParseReobsCheckMode parses the CLI mode string. An empty string is "off".
func ParseReobsCheckMode(s string) (ReobsCheckMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off":
		return ReobsCheckOff, nil
	case "local":
		return ReobsCheckLocal, nil
	case "remote":
		return ReobsCheckRemote, nil
	case "all":
		return ReobsCheckAll, nil
	default:
		return ReobsCheckOff, fmt.Errorf("invalid reobservation consistency check mode %q (valid: off, local, remote, all)", s)
	}
}

// Wormholescan API base URLs. There is no Wormholescan for devnet, so the remote
// modes cannot run there. ConfigureReobservationCheck takes a resolved base URL
// (rather than the environment) so tests can point it at an httptest.Server.
const (
	MainnetWormholescanURL = "https://api.wormholescan.io"
	TestnetWormholescanURL = "https://api.testnet.wormholescan.io"
)

// WormholescanURLForEnv returns the Wormholescan base URL for env and whether the
// remote check is supported there. Devnet (and test envs) are unsupported.
func WormholescanURLForEnv(env common.Environment) (string, bool) {
	switch env {
	case common.MainNet:
		return MainnetWormholescanURL, true
	case common.TestNet:
		return TestnetWormholescanURL, true
	default:
		return "", false
	}
}

// reobservationCheckHTTPTimeout bounds a single Wormholescan request, since the check
// runs synchronously on the reobservation path.
const reobservationCheckHTTPTimeout = 10 * time.Second

var reobservationConsistencyChecks = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "wormhole_reobservation_consistency_checks",
		Help: "Outcome of the reobservation consistency check, by chain and outcome",
	}, []string{"chain", "outcome"})

// reobservationCheckMode and reobservationCheckBaseURL are set once at startup (before any
// watcher or the processor goroutine is launched) and only read afterwards, so the
// startup write happens-before every read and no synchronization is required.
var (
	reobservationCheckMode    ReobsCheckMode
	reobservationCheckBaseURL = MainnetWormholescanURL
)

// ConfigureReobservationCheck sets the process-wide config. Call once at startup, before
// watchers run. The mode defaults to off. baseURL may be empty when no remote mode is used.
func ConfigureReobservationCheck(mode ReobsCheckMode, baseURL string) {
	reobservationCheckMode = mode
	reobservationCheckBaseURL = baseURL
}

// VerifyReobservation reports whether a reobserved message may be published, per the
// configured mode. It returns true (publish) when the check is off, the message is not a
// reobservation, no canonical VAA is found, the digests match, or any lookup errors (fail
// open). It returns false only when a canonical VAA exists and its signing digest differs
// from the locally produced one.
func VerifyReobservation(ctx context.Context, logger *zap.Logger, db *guardianDB.Database, msg *common.MessagePublication) bool {
	if msg == nil || !msg.IsReobservation {
		return true
	}

	mode := reobservationCheckMode
	baseURL := reobservationCheckBaseURL

	if mode == ReobsCheckOff {
		return true
	}

	chainStr := msg.EmitterChain.String()
	local := msg.CreateVAA(0) // Guardian set index is not part of the digest.
	localDigest := local.SigningDigest()

	// Local signed-VAA store: works on every environment, no network call.
	if mode.UsesLocal() && db != nil {
		id := guardianDB.VAAID{EmitterChain: msg.EmitterChain, EmitterAddress: msg.EmitterAddress, Sequence: msg.Sequence}
		b, err := db.GetSignedVAABytes(id)
		switch {
		case err == nil:
			if storedVAA, uerr := vaa.Unmarshal(b); uerr != nil {
				logger.Warn("reobservation consistency check: local VAA unmarshal failed; treating as a local miss",
					msg.ZapFields(zap.Error(uerr))...)
			} else if localDigest != storedVAA.SigningDigest() {
				logReobservationHashMismatch(logger, msg, local, storedVAA)
				logger.Error("reobservation consistency check: local signing digest mismatch; NOT publishing reobservation",
					msg.ZapFields(zap.String("localDigest", localDigest.Hex()), zap.String("localStoredDigest", storedVAA.SigningDigest().Hex()))...)
				reobservationConsistencyChecks.WithLabelValues(chainStr, "local_mismatch_dropped").Inc()
				return false
			} else {
				reobservationConsistencyChecks.WithLabelValues(chainStr, "local_match").Inc()
				return true
			}
		case errors.Is(err, guardianDB.ErrVAANotFound):
			// Not stored locally; fall through (to Wormholescan if the mode allows it).
		default:
			logger.Warn("reobservation consistency check: local VAA lookup failed; treating as a local miss",
				msg.ZapFields(zap.Error(err))...)
		}

		// Local miss and no remote fallback configured: nothing to contradict, publish.
		if !mode.UsesRemote() {
			reobservationConsistencyChecks.WithLabelValues(chainStr, "local_not_found").Inc()
			return true
		}
	}

	if !mode.UsesRemote() {
		return true
	}

	whVAA, found, err := fetchSignedVAAFromWormholescan(ctx, baseURL, uint16(msg.EmitterChain), msg.EmitterAddress, msg.Sequence)
	if err != nil {
		logger.Warn("reobservation consistency check: Wormholescan lookup failed; failing open and publishing",
			msg.ZapFields(zap.Error(err))...)
		reobservationConsistencyChecks.WithLabelValues(chainStr, "error_failopen").Inc()
		return true
	}
	if !found {
		logger.Info("reobservation consistency check: no canonical VAA on Wormholescan; publishing",
			msg.ZapFields()...)
		reobservationConsistencyChecks.WithLabelValues(chainStr, "not_found").Inc()
		return true
	}

	whDigest := whVAA.SigningDigest()
	if localDigest != whDigest {
		logReobservationHashMismatch(logger, msg, local, whVAA)
		logger.Error("reobservation consistency check: signing digest mismatch; NOT publishing reobservation",
			msg.ZapFields(
				zap.String("localDigest", localDigest.Hex()),
				zap.String("wormholescanDigest", whDigest.Hex()),
			)...)
		reobservationConsistencyChecks.WithLabelValues(chainStr, "mismatch_dropped").Inc()
		return false
	}

	reobservationConsistencyChecks.WithLabelValues(chainStr, "match").Inc()
	return true
}

// fetchSignedVAAFromWormholescan looks up a signed VAA by (chainID, emitter, sequence),
// returning (vaa, true, nil) when one exists, (nil, false, nil) on a 404, and
// (nil, false, err) on any network/status/parse failure.
func fetchSignedVAAFromWormholescan(ctx context.Context, baseURL string, chainID uint16, emitter vaa.Address, sequence uint64) (*vaa.VAA, bool, error) {
	url := fmt.Sprintf("%s/api/v1/vaas/%d/%s/%d", baseURL, chainID, hex.EncodeToString(emitter[:]), sequence)

	reqCtx, cancel := context.WithTimeout(ctx, reobservationCheckHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to build wormholescan request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("wormholescan GET %s failed: %w", url, err)
	}
	defer res.Body.Close()

	body, err := common.SafeRead(res.Body)
	if err != nil {
		return nil, false, fmt.Errorf("wormholescan read body failed: %w", err)
	}

	if res.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("wormholescan %s returned status %d: %.500s", url, res.StatusCode, string(body))
	}

	var parsed struct {
		Data struct {
			Vaa string `json:"vaa"`
		} `json:"data"`
		Vaa string `json:"vaa"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, false, fmt.Errorf("wormholescan unmarshal failed: %w (body=%.500s)", err, string(body))
	}
	encoded := parsed.Data.Vaa
	if encoded == "" {
		encoded = parsed.Vaa
	}
	if encoded == "" {
		return nil, false, fmt.Errorf("wormholescan response missing 'vaa' field: %.500s", string(body))
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false, fmt.Errorf("wormholescan vaa not base64-decodable: %w", err)
	}
	whVAA, err := vaa.Unmarshal(raw)
	if err != nil {
		return nil, false, fmt.Errorf("wormholescan vaa.Unmarshal failed: %w", err)
	}
	return whVAA, true, nil
}

// logReobservationHashMismatch logs a field-by-field diff between the local and canonical VAAs.
func logReobservationHashMismatch(logger *zap.Logger, msg *common.MessagePublication, local, canonical *vaa.VAA) {
	fields := []zap.Field{
		zap.String("msgID", string(msg.MessageID())),
		zap.String("localDigest", local.SigningDigest().Hex()),
		zap.String("canonicalDigest", canonical.SigningDigest().Hex()),
	}
	if !local.Timestamp.Equal(canonical.Timestamp) {
		fields = append(fields, zap.Time("localTimestamp", local.Timestamp), zap.Time("canonicalTimestamp", canonical.Timestamp))
	}
	if local.Nonce != canonical.Nonce {
		fields = append(fields, zap.Uint32("localNonce", local.Nonce), zap.Uint32("canonicalNonce", canonical.Nonce))
	}
	if local.ConsistencyLevel != canonical.ConsistencyLevel {
		fields = append(fields, zap.Uint8("localConsistency", local.ConsistencyLevel), zap.Uint8("canonicalConsistency", canonical.ConsistencyLevel))
	}
	if !bytes.Equal(local.Payload, canonical.Payload) {
		fields = append(fields, zap.String("localPayload", hex.EncodeToString(local.Payload)), zap.String("canonicalPayload", hex.EncodeToString(canonical.Payload)))
	}
	logger.Error("reobservation consistency check: field-by-field diff", fields...)
}
