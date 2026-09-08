package arrow

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
)

// Limits is the /user/limits payload: segment allocations plus account margin summary.
// Field values are strings in live API responses (e.g. "usableMargin", "netPnl").
// Values inside the nested margin object may be numbers as well; MarginValue
// keeps both shapes without failing the whole fetch.
// (WAVE9-F: P1-180/181.)
type Limits struct {
	Data struct {
		Allocations []map[string]any   `json:"allocations"`
		Margin      map[string]FlexStr `json:"margin"`
	} `json:"data"`
	Status string `json:"status"`
}

// FlexStr is an alias kept next to its use so limits.go compiles standalone;
// canonical behavior lives on FlexString in positions.go.
type FlexStr = FlexString

// GetLimits fetches trading limits and margin for the authenticated user.
func (c *Client) GetLimits() (*Limits, error) {
	endpoint := "/user/limits"

	resp, err := c.request(endpoint, "GET", nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch trading limits")
		return nil, err
	}

	var result Limits
	if err := json.Unmarshal(resp, &result); err != nil {
		log.Error().Err(err).Msg("Failed to parse trading limits response")
		return nil, fmt.Errorf("limits: decode: %w (body=%.200s)", err, string(resp))
	}

	if result.Status != "success" {
		return nil, apiError("trading limits", result.Status, resp)
	}

	c.debugf("Trading limits retrieved successfully", nil)
	return &result, nil
}
