// auth.go
package arrow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// AuthResponse represents the structure of the authentication response from the API.
type AuthResponse struct {
	Status string `json:"status"` // API response status (e.g., "success" or "error").
	Data   struct {
		Name         string `json:"name"`         // User's name.
		Token        string `json:"token"`        // Authentication token.
		UserID       string `json:"userId"`       // Unique identifier for the user.
		RefreshToken string `json:"refreshToken"` // Token used for refreshing authentication.
	} `json:"data"`
}

// GenerateChecksum creates a SHA256 hash of "appId:appSecret:request-token".
//
// This is used to securely authenticate API requests.
//
// Parameters:
//   - appID: The application ID.
//   - appSecret: The application secret key.
//   - requestToken: The temporary request token obtained from the login process.
//
// Returns:
//   - A SHA256 checksum string.
func GenerateChecksum(appID, appSecret, requestToken string) string {
	// WAVE9-B (P1-294): an empty secret/token yields a checksum over
	// attacker-known input — callers must refuse "" before sending.
	if appSecret == "" || requestToken == "" {
		return ""
	}
	data := fmt.Sprintf("%s:%s:%s", appID, appSecret, requestToken)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Authenticate exchanges the request token for an access token.
//
// This function sends a POST request to authenticate the user and obtain an API token.
//
// Parameters:
//   - requestToken: The temporary token received after user login.
//
// Returns:
//   - A string containing the authentication token if successful.
//   - An error if authentication fails.
func (c *Client) Authenticate(requestToken string) (string, error) {
	// WAVE9-B (P1-161): never authenticate with an empty token.
	if requestToken == "" {
		return "", fmt.Errorf("authenticate: empty request token")
	}
	// WAVE9-A: snapshot credentials under RLock; token write below takes Lock.
	c.mu.RLock()
	authAppID, authSecret := c.Config.AppID, c.Config.AppSecret
	c.mu.RUnlock()
	if authSecret == "" {
		// WAVE9-B (P1-294): empty secret yields an unusable checksum —
		// refuse before sending a doomed request.
		return "", fmt.Errorf("authenticate: missing app credentials")
	}
	checksum := GenerateChecksum(authAppID, authSecret, requestToken)

	payload := fmt.Sprintf(`{
		"checkSum": "%s",
		"checksum": "%s",
		"token": "%s",
		"appId": "%s"
	}`, checksum, checksum, requestToken, authAppID)

	responseBody, err := c.request("/auth/app/authenticate-token", "POST", []byte(payload))
	if err != nil {
		log.Error().Err(err).Msg("Failed to authenticate")
		// WAVE9-B (P1-166): endpoint context on transport errors.
		return "", fmt.Errorf("authenticate /auth/app/authenticate-token: %w", err)
	}

	var authResponse AuthResponse
	if err := json.Unmarshal(responseBody, &authResponse); err != nil {
		log.Error().Err(err).Msg("Failed to parse authentication response")
		return "", fmt.Errorf("authenticate /auth/app/authenticate-token decode: %w", err)
	}

	if authResponse.Status != "success" {
		return "", fmt.Errorf("authentication failed: %s", authResponse.Status)
	}
	if authResponse.Data.Token == "" {
		return "", fmt.Errorf("authentication failed: empty token in success response")
	}

	// Update client token after authentication (WAVE9-A Lock: orders vs readers).
	c.mu.Lock()
	c.Config.Token = authResponse.Data.Token
	if authResponse.Data.RefreshToken != "" {
		c.Config.RefreshToken = authResponse.Data.RefreshToken
	}
	c.mu.Unlock()

	c.debugf("Authentication successful", func(e *zerolog.Event) {
		e.Str("userID", authResponse.Data.UserID)
	})
	return authResponse.Data.Token, nil
}

// Login prompts the user to log in manually and enter the request token.
//
// This function prints a login URL and asks the user to enter the request token
// to complete the authentication process.
//
// WARNING (WAVE9-B, P1-162): this function OWNS stdin — it blocks on
// fmt.Scanln with no timeout. Never call it from a service/bridge process;
// use AutoLogin (TOTP) or Authenticate with a request token obtained
// out-of-band. Services calling Login hang forever on stdin EOF/retry.
//
// Returns an error (WAVE9-B): scan failures and Authenticate failures
// propagate so automated flows can branch instead of assuming success.
func (c *Client) Login() error {
	c.mu.RLock()
	loginAppID := c.Config.AppID
	c.mu.RUnlock()
	loginURL := fmt.Sprintf("https://app.arrow.trade/app/login?appId=%s", loginAppID)
	fmt.Println("Please visit the following URL to log in and retrieve your request token:")
	fmt.Println(loginURL)
	fmt.Println("After logging in, enter the request token below:")

	var requestToken string
	fmt.Print("Enter Request Token: ")
	if _, err := fmt.Scanln(&requestToken); err != nil {
		log.Error().Err(err).Msg("Login request-token scan failed")
		return fmt.Errorf("login scan request token: %w", err)
	}

	if _, err := c.Authenticate(requestToken); err != nil {
		log.Error().Err(err).Msg("Login authentication failed")
		return err
	}

	fmt.Println("Authentication successful.")
	return nil
}

// LoginContext authenticates a caller-supplied request token with
// cancellation: unlike Login it touches stdin never — a cancelled context
// aborts before the Authenticate step. Prefer AutoLogin for automated flows.
// (WAVE9-B, P1-162.)
func (c *Client) LoginContext(ctx context.Context, requestToken string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := c.Authenticate(requestToken); err != nil {
		return err
	}
	return nil
}

// AutoLogin handles the entire authentication flow automatically using credentials.
//
// This function logs in a user programmatically by sending the credentials,
// performing 2FA verification using TOTP, extracting the request token, and
// exchanging it for an access token.
//
// Parameters:
//   - username: The user's registered ID or email.
//   - password: The user's password.
//   - totpSecret: The TOTP secret key used to generate 2FA codes.
//
// Returns:
//   - An error if authentication fails; otherwise, nil.
func (c *Client) AutoLogin(username, password, totpSecret string) error {
	loginURL := "https://api.arrow.trade/auth/app/login"

	// WAVE9-A: snapshot AppID under RLock.
	c.mu.RLock()
	autoAppID := c.Config.AppID
	c.mu.RUnlock()

	// Step 1: Send Login Request
	payload := fmt.Sprintf(`{
		"userID": "%s",
		"password": "%s",
		"captchaValue": "",
		"captchaID": null,
		"appID": "%s",
		"isAppLogin": true
	}`, username, password, autoAppID)

	resp, err := c.rawRequest(loginURL, "POST", []byte(payload))
	if err != nil {
		log.Error().Err(err).Msg("Login request failed")
		return &AuthError{Stage: "login", Err: err}
	}

	var loginResp struct {
		Data struct {
			RequestID string `json:"requestId"` // Temporary request ID for 2FA validation.
		} `json:"data"`
	}

	if err := json.Unmarshal(resp, &loginResp); err != nil {
		log.Error().Err(err).Msg("Failed to parse login response")
		return &AuthError{Stage: "login", Err: err}
	}

	if loginResp.Data.RequestID == "" {
		return &AuthError{Stage: "login", Err: fmt.Errorf("empty requestId from login response")}
	}

	// Step 2: Generate TOTP Code
	passcode, err := generateTOTP(totpSecret)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate TOTP code")
		return &AuthError{Stage: "totp", Err: err}
	}

	// Step 3: Validate 2FA
	totpPayload := fmt.Sprintf(`{
		"code": "%s",
		"requestId": "%s",
		"userID": "%s"
	}`, passcode, loginResp.Data.RequestID, username)

	resp, err = c.rawRequest("https://edge.arrow.trade/auth/validate-2fa", "POST", []byte(totpPayload))
	if err != nil {
		log.Error().Err(err).Msg("2FA validation failed")
		return &AuthError{Stage: "totp", Err: err}
	}

	var totpResp struct {
		Data struct {
			RedirectURL string `json:"redirectUrl"` // URL containing the request token.
		} `json:"data"`
	}

	if err := json.Unmarshal(resp, &totpResp); err != nil {
		log.Error().Err(err).Msg("Failed to parse 2FA response")
		return &AuthError{Stage: "redirect", Err: err}
	}

	// Step 4: Extract Request Token from Redirect URL
	parsedURL, err := url.Parse(totpResp.Data.RedirectURL)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse redirect URL")
		return &AuthError{Stage: "redirect", Err: err}
	}

	requestToken := parsedURL.Query().Get("request-token")
	if requestToken == "" {
		return &AuthError{Stage: "redirect", Err: fmt.Errorf("no request-token in redirect URL")}
	}

	// Step 5: Authenticate and Get Access Token
	if _, err = c.Authenticate(requestToken); err != nil {
		log.Error().Err(err).Msg("Authentication failed")
		return &AuthError{Stage: "authenticate", Err: err}
	}
	fmt.Println("AutoLogin successful.")
	return nil
}

// AuthError distinguishes AutoLogin failure stages (WAVE9-B, P1-163/164):
// bad-creds ("login"), bad-TOTP ("totp"), network/redirect ("redirect"),
// broker rejection ("authenticate"). Callers switch on Stage instead of
// parsing message text.
type AuthError struct {
	Stage string
	Err   error
}

func (e *AuthError) Error() string { return "autologin " + e.Stage + ": " + e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

// generateTOTP generates a TOTP (Time-based One-Time Password) code using a given secret.
//
// This function generates a 6-digit TOTP code that is valid for 30 seconds.
//
// Parameters:
//   - secret: The TOTP secret key.
//
// Returns:
//   - A string containing the generated TOTP code if successful.
//   - An error if TOTP generation fails.
func generateTOTP(secret string) (string, error) {
	return totp.GenerateCodeCustom(
		secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    6,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
}
