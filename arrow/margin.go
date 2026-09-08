// margin.go
package arrow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// Paise is an integer paise amount (1/100 INR). All REST money on the quote,
// margin, positions and holdings paths is transported as integer paise per
// https://docs.arrow.trade/go-sdk/market-data/ ("Price scaling: REST quote
// endpoints return prices as integers in paise (x100)") and the portfolio
// samples (positions qty/avgPrice/dayBuyAvgPrice as integer strings, e.g.
// "14675"). Integer transport never loses a 2-decimal INR value, unlike
// binary float64. (WAVE9-E: P1-040/044/182/196.)
type Paise int64

// UnmarshalJSON implements json.Unmarshaler via ParsePaise so MarginResponse
// integer fields (and future QuoteLTP-style fields) accept both JSON numbers
// and strings without failing the whole fetch.
func (p *Paise) UnmarshalJSON(b []byte) error {
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("paise: decode: %w", err)
	}
	got, err := ParsePaise("paise", v)
	if err != nil {
		return err
	}
	*p = Paise(got)
	return nil
}
func ParsePaise(field string, v any) (Paise, error) {
	switch n := v.(type) {
	case nil:
		return 0, fmt.Errorf("money %s: null value", field)
	case json.Number:
		return paiseFromNumber(field, string(n))
	case float64:
		if n != float64(int64(n)) {
			return 0, fmt.Errorf("money %s: non-integer paise %v", field, n)
		}
		return Paise(int64(n)), nil
	case string:
		s := strings.TrimSpace(n)
		if s == "" {
			return 0, fmt.Errorf("money %s: empty value", field)
		}
		if p, err := strconv.ParseInt(s, 10, 64); err == nil {
			return Paise(p), nil
		}
		return paiseFromDecimalString(field, s)
	default:
		return 0, fmt.Errorf("money %s: unsupported JSON shape %T", field, v)
	}
}

func paiseFromNumber(field, s string) (Paise, error) {
	s = strings.TrimSpace(s)
	if p, err := strconv.ParseInt(s, 10, 64); err == nil {
		return Paise(p), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("money %s: unparseable number %q", field, s)
	}
	if f != float64(int64(f)) {
		return 0, fmt.Errorf("money %s: non-integer paise %q", field, s)
	}
	return Paise(int64(f)), nil
}

func paiseFromDecimalString(field, s string) (Paise, error) {
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	} else {
		s = strings.TrimPrefix(s, "+")
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) > 2 {
		return 0, fmt.Errorf("money %s: bad decimal %q", field, s)
	}
	whole := parts[0]
	if whole == "" {
		whole = "0"
	}
	frac := ""
	if len(parts) == 2 {
		frac = parts[1]
	}
	if len(frac) > 2 {
		return 0, fmt.Errorf("money %s: sub-paise precision %q", field, s)
	}
	for _, r := range whole + frac {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("money %s: unparseable value %q", field, s)
		}
	}
	for len(frac) < 2 {
		frac += "0"
	}
	w, err1 := strconv.ParseInt(whole, 10, 64)
	f, err2 := strconv.ParseInt(frac, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("money %s: unparseable value %q", field, s)
	}
	p := Paise(w*100 + f)
	if neg {
		p = -p
	}
	return p, nil
}

// Rupees renders integer paise as a 2-decimal rupee string for display/logs.
func Rupees(p Paise) string {
	neg := ""
	if p < 0 {
		neg = "-"
		p = -p
	}
	return fmt.Sprintf("%s%d.%02d", neg, p/100, p%100)
}

// MarginRequest represents the request payload for margin calculation.
type MarginRequest struct {
	Exchange         Exchange        `json:"exchange"`
	Symbol           string          `json:"symbol"`
	Quantity         string          `json:"quantity"`
	Price            string          `json:"price"`
	Product          Product         `json:"product"`
	TransactionType  TransactionType `json:"transactionType"`
	Order            OrderType       `json:"order"`
	IncludePositions bool            `json:"includePositions"`
}
type MarginResponse struct {
	Data struct {
		RequiredMargin       Paise `json:"requiredMargin"`
		MinimumCashRequired  Paise `json:"minimumCashRequired"`
		MarginUsedAfterTrade Paise `json:"marginUsedAfterTrade"`
		Charge               struct {
			Brokerage      Paise `json:"brokerage"`
			ExchangeTxnFee Paise `json:"exchangeTxnFee"`
			Gst            struct {
				Cgst  Paise `json:"cgst"`
				Igst  Paise `json:"igst"`
				Sgst  Paise `json:"sgst"`
				Total Paise `json:"total"`
			} `json:"gst"`
			Ipft           Paise `json:"ipft"`
			SebiCharges    Paise `json:"sebiCharges"`
			StampDuty      Paise `json:"stampDuty"`
			Total          Paise `json:"total"`
			TransactionTax Paise `json:"transactionTax"`
		} `json:"charge"`
	} `json:"data"`
	Status string `json:"status"`
}

// (WAVE9-E: P1-040/182 — REST money is integer paise per
// https://docs.arrow.trade/go-sdk/market-data/ price scaling; float64 lost
// paise and broke on string-encoded decimals. MarginResponse itself now
// carries Paise (int64 + UnmarshalJSON) so both numeric and string shapes
// decode; P1-183/184 context+excerpt provided below.)
func (c *Client) GetMargin(order MarginRequest) (*MarginResponse, error) {
	endpoint := "/margin/order"

	// Convert order details into JSON payload.
	payload, err := json.Marshal(order)
	if err != nil {
		log.Error().Err(err).Msg("Failed to serialize margin request")
		return nil, err
	}

	// Send the request to the API.
	resp, err := c.request(endpoint, "POST", []byte(payload))
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch margin")
		return nil, fmt.Errorf("margin: request: %w", err)
	}

	// Parse the JSON response into the OrderMargin struct.
	var result MarginResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		log.Error().Err(err).Msg("Failed to parse margin response")
		return nil, fmt.Errorf("margin: decode: %w (body=%.200s)", err, string(resp))
	}
	if result.Status != "success" {
		return nil, apiError("margin", result.Status, resp)
	}

	return &result, nil
}
