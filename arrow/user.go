// user.go
package arrow

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// BankDetail represents a single bank account associated with a user.
// Each user can have multiple bank accounts configured for transactions.
type BankDetail struct {
	ID            string `json:"id"`            // Unique identifier for the bank detail record
	Vpa           string `json:"vpa"`           // Virtual Payment Address (UPI ID)
	BankName      string `json:"bankName"`      // Name of the bank (e.g., "HDFC Bank")
	AccountType   string `json:"accountType"`   // Type of account (e.g., "SAVINGS", "CURRENT")
	AccountNumber string `json:"accountNumber"` // Bank account number (may be masked, e.g. "*9380")
	IfscCode      string `json:"ifscCode"`      // Indian Financial System Code for the bank branch
	IsDefault     bool   `json:"isDefault"`     // Whether this is the default bank account for transactions
}

// Depository represents a depository participant (DP) account for securities trading.
// Users need DP accounts to hold and trade securities in electronic form.
type Depository struct {
	Dp string `json:"dp"` // Depository Participant identifier
	ID string `json:"id"` // Unique client ID with the depository
}

// UserData contains all the profile information for a user.
// This includes personal details, financial accounts, and trading permissions.
type UserData struct {
	BankDetails []BankDetail `json:"bankDetails"` // List of linked bank accounts
	Depository  []Depository `json:"depository"`  // List of depository accounts for securities
	Email       string       `json:"email"`       // User's email address
	Exchanges   []string     `json:"exchanges"`   // List of exchanges user has access to (e.g., "NSE", "BSE")
	ID          string       `json:"id"`          // Unique user identifier in Arrow system
	Image       string       `json:"image"`       // URL to user's profile image
	Name        string       `json:"name"`        // Full name of the user
	OrdersTypes int          `json:"ordersTypes"` // Bitmask representing allowed order types
	Pan         string       `json:"pan"`         // Permanent Account Number (Indian tax identifier)
	Phone       string       `json:"phone"`       // User's phone number
	Products    []string     `json:"products"`    // List of enabled products (e.g., "CNC", "MIS", "NRML")
	TotpEnabled bool         `json:"totpEnabled"` // Whether Time-based One-Time Password is enabled
	UserType    string       `json:"userType"`    // Type of user account (e.g., "INDIVIDUAL", "HUF")
}

// User represents the complete API response structure for user details.
// This follows Arrow API's standard response format with data and status fields.
// (WAVE9-F: P1-204 — Data is a pointer so a `data:null` body decodes to nil
// instead of a zero struct; helpers above are nil-safe.)
type User struct {
	Data   *UserData `json:"data"`   // The actual user profile data
	Status string    `json:"status"` // API response status ("success" or "error")
}

// GetUserDetails fetches comprehensive user profile details from the Arrow API.
//
// This method retrieves all available information about the authenticated user,
// including personal details, linked bank accounts, depository information,
// trading permissions, and account settings.
//
// The method handles the complete request lifecycle:
//   - Sends an authenticated GET request to the user details endpoint
//   - Parses the JSON response into a structured User object
//   - Validates the response status for success
//   - Provides detailed error logging for troubleshooting
//
// Returns:
//   - *User: A pointer to the User struct containing all profile details
//   - error: nil on success, or an error describing what went wrong
func (c *Client) GetUserDetails() (*User, error) {
	endpoint := "/user/details"

	// Send a GET request to the API to retrieve user details.
	// This will include authentication headers automatically via the client's request method.
	resp, err := c.request(endpoint, "GET", nil)
	if err != nil {
		log.Error().
			Err(err).
			Str("endpoint", endpoint).
			Msg("Failed to fetch user profile from Arrow API")
		return nil, fmt.Errorf("failed to fetch user profile: %w", err)
	}

	var result User
	// Parse the JSON response into the User struct.
	// The Arrow API returns nested JSON with data and status fields.
	if err := json.Unmarshal(resp, &result); err != nil {
		log.Error().
			Err(err).
			Str("endpoint", endpoint).
			Msg("Failed to parse user profile response JSON")
		return nil, fmt.Errorf("user profile: decode: %w (body=%.200s)", err, string(resp))
	}

	// Check if the API response status indicates success.
	// Arrow API uses "success" string to indicate successful operations.
	if result.Status != "success" {
		log.Error().
			Str("status", result.Status).
			Str("endpoint", endpoint).
			Msg("Arrow API returned non-success status for user profile")
		// P1-203: the old error carried only the bare status — server detail
		// (message/error/code) was discarded. apiError re-parses the raw body
		// (same helper as holdings/limits/margin/positions/quote/market).
		uerr := apiError("user profile", result.Status, resp)
		log.Error().Err(uerr).Msg("user profile failure detail")
		return nil, uerr
	}

	c.debugf("User profile retrieved successfully from Arrow API", func(e *zerolog.Event) {
		e.Str("user_id", result.Data.ID).
			Str("user_name", result.Data.Name).
			Int("bank_accounts", len(result.Data.BankDetails)).
			Int("depositories", len(result.Data.Depository))
	})

	return &result, nil
}

// (WAVE9-F: P1-204 — every helper below is nil-receiver safe; a nil *User or
// a User with nil Data no longer panics.)
func (u *User) HasDefaultBankAccount() bool {
	if u == nil || u.Data == nil {
		return false
	}
	for _, bank := range u.Data.BankDetails {
		if bank.IsDefault {
			return true
		}
	}
	return false
}

// GetDefaultBankAccount returns the user's default bank account details.
//
// Returns:
//   - *BankDetail: pointer to the default bank account, or nil if none exists
//
// (WAVE9-F: P1-204/205 — nil-safe; returns a copy so the caller cannot alias
// or mutate the interior slice element.)
func (u *User) GetDefaultBankAccount() *BankDetail {
	if u == nil || u.Data == nil {
		return nil
	}
	for _, bank := range u.Data.BankDetails {
		if bank.IsDefault {
			cp := bank
			return &cp
		}
	}
	return nil
}

// HasExchangeAccess checks if the user has access to trade on a specific exchange.
//
// Parameters:
//   - exchange: The exchange code to check (e.g., "NSE", "BSE", "MCX")
//
// Returns:
//   - bool: true if the user has access to the specified exchange
func (u *User) HasExchangeAccess(exchange string) bool {
	// P1-204: nil-receiver safe like the bank helpers above.
	if u == nil || u.Data == nil {
		return false
	}
	for _, ex := range u.Data.Exchanges {
		if ex == exchange {
			return true
		}
	}
	return false
}

// IsTotpEnabled returns whether the user has enabled Two-Factor Authentication.
//
// Returns:
//   - bool: true if TOTP/2FA is enabled for the user account
func (u *User) IsTotpEnabled() bool {
	// P1-204: nil-receiver safe like the bank helpers above.
	if u == nil || u.Data == nil {
		return false
	}
	return u.Data.TotpEnabled
}
