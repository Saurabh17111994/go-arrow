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

// GetQuotes posts to /info/quotes/{mode} with a JSON array of {exchange, symbol} (no mode in body).
func (c *Client) GetQuotes(instruments []QuoteInstrument, mode InfoQuoteMode) ([]map[string]any, error) {
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
		return nil, fmt.Errorf("quotes retrieval failed with status: %s", envelope.Status)
	}

	var asSlice []map[string]any
	if err := json.Unmarshal(envelope.Data, &asSlice); err == nil {
		c.debugf("Quotes retrieved successfully", nil)
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
		return nil, fmt.Errorf("quote retrieval failed with status: %s", result.Status)
	}
	return result.Data, nil
}
