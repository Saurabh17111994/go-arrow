// holdings.go
package arrow

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Symbol represents trading symbol information within a holding.
//
// A holding can have multiple symbols (e.g., NSE and BSE variants of the same instrument).
// This struct contains the essential identifiers for a trading instrument.
type Symbol struct {
	Symbol        string `json:"symbol"`        // Base symbol of the instrument (e.g., RELIANCE, TCS, HDFCBANK).
	TradingSymbol string `json:"tradingSymbol"` // Exchange-specific trading symbol (e.g., RELIANCE-EQ for NSE).
	Exchange      string `json:"exchange"`      // Name of the exchange (e.g., NSE, BSE).
	Token         string `json:"token"`         // Unique token identifier for the trading instrument.
}

// Holding represents a long-term investment holding owned by the user.
//
// This struct contains comprehensive information about investment holdings,
// including quantity details across different categories (T1, depository, collateral),
// pricing information, profit/loss calculations, and various quantity classifications
// that determine trading eligibility and collateral usage.
type Holding struct {
	Symbols             []Symbol   `json:"symbols"`             // Array of symbol information for the holding across different exchanges.
	AvgPrice            FlexString `json:"avgPrice"`            // Average price at which the holding was acquired.
	Qty                 FlexString `json:"qty"`                 // Total quantity of the holding owned by the user.
	UsedQty             FlexString `json:"usedQty"`             // Quantity currently used as collateral or margin.
	T1Qty               FlexString `json:"t1Qty"`               // Quantity in T1 (Trade day + 1) settlement cycle, available for trading next day.
	DepositoryQty       FlexString `json:"depositoryQty"`       // Quantity held in the depository (NSDL/CDSL) and available for trading.
	CollateralQty       FlexString `json:"collateralQty"`       // Quantity pledged as collateral for margin requirements.
	BrokerCollateralQty FlexString `json:"brokerCollateralQty"` // Quantity pledged with the broker for additional margin benefits.
	AuthorizedQty       FlexString `json:"authorizedQty"`       // Total authorized quantity including all categories.
	UnPledgedQty        FlexString `json:"unPledgedQty"`        // Quantity not pledged as collateral and available for free trading.
	NonPOAQty           FlexString `json:"nonPOAQty"`           // Quantity for which Power of Attorney (POA) is not provided.
	Haircut             FlexString `json:"haircut"`             // Haircut percentage applied to the holding value for margin calculations.
	EffectiveQty        FlexString `json:"effectiveQty"`        // Effective quantity after applying haircuts and margin requirements.
	SellableQty         FlexString `json:"sellableQty"`         // Quantity available for immediate selling in the market.
	Ltp                 FlexString `json:"ltp"`                 // Last traded price of the instrument.
	Pnl                 FlexString `json:"pnl"`                 // Profit and loss calculated based on current market price vs average price.
	Close               FlexString `json:"close"`               // Previous day's closing price of the instrument.
}

// HoldingsResponse represents the API response structure for user holdings.
//
// This struct encapsulates the response from the holdings API endpoint,
// containing both the holdings data and the API response status.
type HoldingsResponse struct {
	Data   []Holding `json:"data"`   // Array of Holding objects representing all user holdings.
	Status string    `json:"status"` // API response status indicating success or failure.
}

// GetHoldings retrieves all investment holdings for the authenticated user.
//
// This method sends a GET request to the "/user/holdings" endpoint to fetch
// comprehensive holdings data including long-term investments, quantity breakdowns
// across different settlement cycles, collateral information, and current valuations.
//
// The returned holdings include equity shares, ETFs, mutual funds, and other
// investment instruments held across all exchanges and depositories.
//
// Holdings represent long-term investments that are carried forward beyond the
// current trading session, unlike positions which may include intraday transactions.
// The data includes detailed quantity classifications that determine trading
// eligibility and margin benefits.
//
// Returns:
//   - A slice of Holding structs containing detailed information about each investment holding.
//   - An error if the API request fails, authentication is invalid, or response parsing fails.
//
// Example usage:
//
//	holdings, err := client.GetHoldings()
//	if err != nil {
//	    log.Printf("Failed to get holdings: %v", err)
//	    return
//	}
//
//	for _, holding := range holdings {
//	    if len(holding.Symbols) > 0 {
//	        fmt.Printf("Symbol: %s, Qty: %s, PnL: %s, Sellable: %s\n",
//	                   holding.Symbols[0].Symbol, holding.Qty,
//	                   holding.Pnl, holding.SellableQty)
//	    }
//	}
//
// Note: Holdings data is typically updated at the end of each trading day and
// reflects the settled quantities in the user's demat account.
func (c *Client) GetHoldings() ([]Holding, error) {
	endpoint := "/user/holdings"

	// Send a GET request to the API to fetch holdings details.
	resp, err := c.request(endpoint, "GET", nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch holdings")
		return nil, err
	}

	var result HoldingsResponse
	// Parse the JSON response into the HoldingsResponse struct.
	// (WAVE9-F: P1-179 — money/qty fields are FlexString so numeric or
	// string JSON both decode; decode failures carry a body excerpt.)
	if err := json.Unmarshal(resp, &result); err != nil {
		log.Error().Err(err).Msg("Failed to parse holdings response")
		return nil, fmt.Errorf("holdings: decode: %w (body=%.200s)", err, string(resp))
	}

	// Check if the API response status indicates success.
	if result.Status != "success" {
		return nil, apiError("holdings", result.Status, resp)
	}

	c.debugf("Holdings retrieved successfully", func(e *zerolog.Event) {
		e.Int("count", len(result.Data))
	})
	return result.Data, nil
}
