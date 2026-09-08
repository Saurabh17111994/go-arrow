// quotes.go
package arrow

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
)

// InfoQuoteMode is the URL segment for REST /info/quote/{mode} and /info/quotes/{mode}.
// This matches pyarrow_client.constants.QuoteMode (ltp, full, ohlcv). It is not the same
// as WebSocket StreamMode (which includes ltpc, quote, full, ltp for binary ticks).
type InfoQuoteMode string

const (
	InfoQuoteLTP   InfoQuoteMode = "ltp"
	InfoQuoteFull  InfoQuoteMode = "full"
	InfoQuoteOHLCV InfoQuoteMode = "ohlcv"
)

// QuoteInstrument is the JSON body shape for /info/quotes/{mode} (symbol + exchange only).
type QuoteInstrument struct {
	Exchange string `json:"exchange"`
	Symbol   string `json:"symbol"`
}

// QuoteRequest is kept for documentation compatibility; Mode is never sent
// (the mode travels in the URL path /info/quotes/{mode}). (WAVE9-F: P1-301 —
// `mode,omitempty` still serialized when set, contradicting the contract.)
type QuoteRequest struct {
	Exchange string `json:"exchange"`
	Symbol   string `json:"symbol"`
	Mode     string `json:"-"`
}

// QuoteLTP is a common subset of quote fields when the API returns token/LTP/close style data.
// (WAVE9-E: P1-196 — REST money is integer paise per
// https://docs.arrow.trade/go-sdk/market-data/ price scaling; quote["ltp"]
// is consumed as float64 paise then /100 for rupees. Paise (int64 +
// UnmarshalJSON) accepts numeric and string shapes without binary-float
// drift.)
type QuoteLTP struct {
	Token Paise `json:"token"`
	Ltp   Paise `json:"ltp"`
	Close Paise `json:"close"`
}

// QuoteLTPResponse is the batch quotes API envelope when data is a list of QuoteLTP-like objects.
type QuoteLTPResponse struct {
	Data   []QuoteLTP `json:"data"`
	Status string     `json:"status"`
}

// validateInfoQuoteMode enforces the three allowed InfoQuoteMode values
// (R-243) — Go does not enforce a string-const set at compile time, and an
// unexpected mode interpolated into the URL path would 404 or worse.
func validateInfoQuoteMode(mode InfoQuoteMode) error {
	switch mode {
	case InfoQuoteLTP, InfoQuoteFull, InfoQuoteOHLCV:
		return nil
	default:
		return fmt.Errorf("invalid quote mode %q (must be ltp, full, or ohlcv)", string(mode))
	}
}

// GetQuotes posts to /info/quotes/{mode} with a JSON array of {exchange, symbol} (no mode in body).
func (c *Client) GetQuotes(instruments []QuoteInstrument, mode InfoQuoteMode) ([]map[string]any, error) {
	// R-243: reject unknown mode before it reaches the URL path.
	if err := validateInfoQuoteMode(mode); err != nil {
		return nil, err
	}
	// WAVE9-E (P1-197): nil batch marshals to `null` — short-circuit before
	// paying for a doomed network call.
	if len(instruments) == 0 {
		return []map[string]any{}, nil
	}
	// WAVE9-F (P1-300): reject empty exchange/symbol fail-fast instead of
	// sending a violating body to the API.
	for i, ins := range instruments {
		if ins.Exchange == "" || ins.Symbol == "" {
			return nil, fmt.Errorf("quotes: instrument %d has empty exchange/symbol", i)
		}
	}
	endpoint := fmt.Sprintf("/info/quotes/%s", mode)
	payload, err := json.Marshal(instruments)
	if err != nil {
		return nil, fmt.Errorf("quotes: marshal instruments: %w", err)
	}
	resp, err := c.request(endpoint, "POST", payload)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch quotes")
		return nil, err
	}

	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Status string          `json:"status"`
	}
	if err := json.Unmarshal(resp, &envelope); err != nil {
		log.Error().Err(err).Msg("Failed to parse quotes response")
		return nil, err
	}
	if envelope.Status != "success" {
		// G6: batch path joins the apiError unification (same as GetQuote
		// single + market.go) — bare status discarded code/message.
		return nil, apiError("quotes", envelope.Status, resp)
	}

	// R-201: a `data: null` response (JSON null) previously unmarshalled into a
	// nil slice returned with a nil error — indistinguishable from a genuine
	// empty result. Return a non-nil empty slice so callers can tell "no
	// quotes" apart from "no data at all".
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return []map[string]any{}, nil
	}

	var asSlice []map[string]any
	if err := json.Unmarshal(envelope.Data, &asSlice); err == nil {
		c.debugf("Quotes retrieved successfully", nil)
		if asSlice == nil {
			return []map[string]any{}, nil
		}
		return asSlice, nil
	}
	var one map[string]any
	if err := json.Unmarshal(envelope.Data, &one); err == nil && len(one) > 0 {
		c.debugf("Quotes retrieved successfully", nil)
		return []map[string]any{one}, nil
	}
	// WAVE9-E (P1-198): include a truncated Data excerpt + Status so an API
	// contract change is diagnosable instead of opaque.
	return nil, fmt.Errorf("quotes data: unsupported JSON shape (status=%s, data=%.120s)", envelope.Status, string(envelope.Data))
}

// GetQuote posts to /info/quote/{mode} with {"symbol","exchange"}.
func (c *Client) GetQuote(exchange Exchange, symbol string, mode InfoQuoteMode) (map[string]any, error) {
	// R-243: same mode gate as the batch path.
	if err := validateInfoQuoteMode(mode); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("/info/quote/%s", mode)
	body := QuoteInstrument{Exchange: string(exchange), Symbol: symbol}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	resp, err := c.request(endpoint, "POST", payload)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch quote")
		return nil, err
	}
	var result struct {
		Data   map[string]any `json:"data"`
		Status string         `json:"status"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}
	if result.Status != "success" {
		// G6: same apiError unification as the batch path + market.go —
		// the old bare-status error discarded server code/message.
		return nil, apiError("quote", result.Status, resp)
	}
	// R-202: nil data (a `data: null` success) must not be returned as a nil
	// map with a nil error — follow the package convention and return an
	// empty map.
	if result.Data == nil {
		return map[string]any{}, nil
	}
	return result.Data, nil
}
