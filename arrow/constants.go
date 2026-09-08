// constants.go
package arrow

// Exchange represents a trading exchange.
// Use these constants when specifying exchange in requests (e.g., arrow.ExchangeNSE).
//
// WARNING (WAVE9-F, P1-172): ExchangeINDEX is quote/market-data-only —
// ValidateOrderRequest rejects it on the order path. Keep it for
// /info/quote and option-chain symbols; never place orders on INDEX.
type Exchange string

const (
	ExchangeNSE     Exchange = "NSE"
	ExchangeBSE     Exchange = "BSE"
	ExchangeNFO     Exchange = "NFO"
	ExchangeNCD     Exchange = "NCD"
	ExchangeBFO     Exchange = "BFO"
	ExchangeBCD     Exchange = "BCD"
	ExchangeMCX     Exchange = "MCX"
	ExchangeNSESLBM Exchange = "NSESLBM"
	ExchangeINDEX   Exchange = "INDEX"
)

// Product represents the order product type (delivery, intraday, etc.).
type Product string

const (
	ProductCNC  Product = "C" // Cash and Carry (delivery)
	ProductMIS  Product = "I" // Intraday
	ProductNRML Product = "M" // Normal (F&O)
)

// TransactionType represents buy or sell.
type TransactionType string

const (
	TransactionTypeBuy  TransactionType = "B"
	TransactionTypeSell TransactionType = "S"
)

// WAVE9-G9 (P1-173): single-letter wire codes route delivery-vs-intraday
// vs-F&O — validate SDK-side instead of failing broker-side on a typo.
// (OrderRequest fields stay string-typed; ValidateOrderRequest enforces
// validity/day-ioc/index/qty/price. Typed-enum migration deferred.)
func (p Product) IsValid() bool {
	switch p {
	case ProductCNC, ProductMIS, ProductNRML:
		return true
	}
	return false
}

func (t TransactionType) IsValid() bool {
	switch t {
	case TransactionTypeBuy, TransactionTypeSell:
		return true
	}
	return false
}

func (e Exchange) IsValid() bool {
	switch e {
	case ExchangeNSE, ExchangeBSE, ExchangeNFO, ExchangeNCD, ExchangeBFO,
		ExchangeBCD, ExchangeMCX, ExchangeNSESLBM, ExchangeINDEX:
		return true
	}
	return false
}

func (o OrderType) IsValid() bool {
	// P1-175: aliases share wire values with the canonical twins, so they
	// cannot be distinct switch cases — compare against the four canonical
	// encodings (string comparison covers both names of each pair).
	switch string(o) {
	case string(OrderTypeLimit), string(OrderTypeMarket),
		string(OrderTypeSLLMT), string(OrderTypeSLMKT):
		return true
	}
	return false
}

func (v Validity) IsValid() bool {
	switch v {
	case ValidityDAY, ValidityIOC, ValidityGTC:
		return true
	}
	return false
}

// OrderType represents the type of order (limit, market, etc.).
// R-240: the legacy constants no longer define a second wire encoding — a
// stop-loss must be sent as one canonical value. The REST-doc encodings
// (SL-LMT / SL-MKT) are authoritative; OrderTypeSL / OrderTypeSLM alias them
// and are kept only as deprecated names.
type OrderType string

const (
	OrderTypeLimit  OrderType = "LMT"    // Limit order
	OrderTypeMarket OrderType = "MKT"    // Market order
	OrderTypeSLLMT  OrderType = "SL-LMT" // Stop Loss Limit (REST docs — canonical)
	OrderTypeSLMKT  OrderType = "SL-MKT" // Stop Loss Market (REST docs — canonical)
	// Deprecated aliases — same wire value as the canonical constants
	// above (P1-175: indistinguishable at runtime; never use an alias and
	// its canonical twin as distinct switch cases or map keys — they
	// collide. Kept for wire-compat; removal needs a broker migration).
	// Deprecated: use OrderTypeSLLMT instead.
	OrderTypeSL OrderType = "SL-LMT"
	// Deprecated: use OrderTypeSLMKT instead.
	OrderTypeSLM OrderType = "SL-MKT"
)

// Validity represents order validity period.
//
// NOTE (WAVE9-F, P1-036): only DAY and IOC are accepted on the order path
// (ValidateOrderRequest rejects GTC). ValidityGTC is retained as a constant
// for broker responses that echo it — do not send GTC on PlaceOrder.
type Validity string

const (
	ValidityDAY Validity = "DAY" // Valid for the day
	ValidityIOC Validity = "IOC" // Immediate or Cancel
	ValidityGTC Validity = "GTC" // Good Till Cancelled
)
