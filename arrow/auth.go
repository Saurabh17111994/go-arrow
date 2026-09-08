// auth.go
package arrow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// AuthResponse represents the structure of the authentication response from the API.
type AuthResponse struct {
	Status  string `json:"status"`  // API response status (e.g., "success" or "error").
	Message string `json:"message"` // Server failure reason (P1-161).
	Error   string `json:"error"`   // Alternate failure reason (P1-161).
	Data    struct {
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

	// R-099: json.Marshal — raw Sprintf interpolation produced invalid JSON
	// when credentials contained quotes, backslashes, or control characters.
	payloadBody := struct {
		CheckSum string `json:"checkSum"`
		Checksum string `json:"checksum"`
		Token    string `json:"token"`
		AppID    string `json:"appID"`
	}{
		CheckSum: checksum, Checksum: checksum, Token: requestToken, AppID: authAppID,
	}
	payload, err := json.Marshal(payloadBody)
	if err != nil {
		return "", fmt.Errorf("marshal authenticate payload: %w", err)
	}

	responseBody, err := c.request("/auth/app/authenticate-token", "POST", payload)
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

	// R-100: a "success" status without a token is NOT a successful
	// authentication — treat it as an error so callers never proceed with an
	// empty credential. Server reason included (P1-161).
	if authResponse.Status != "success" || authResponse.Data.Token == "" {
		return "", fmt.Errorf("authentication failed: status=%s message=%s error=%s token_empty=%t",
			authResponse.Status, truncStr(authResponse.Message, 200),
			truncStr(authResponse.Error, 200), authResponse.Data.Token == "")
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
// R-239: returns an error so automated flows can branch on failure instead of
// assuming the interactive login succeeded.
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
	// P1-163: the interactive login page stays on the fixed app host — it is
	// a human browser URL, not API traffic, so BaseURL must not rewrite it.
	// P1-293: AppID is a query value — escape reserved characters.
	loginURL := fmt.Sprintf("https://app.arrow.trade/app/login?appId=%s", url.QueryEscape(loginAppID))
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
	// WAVE9-A: snapshot config under RLock.
	c.mu.RLock()
	autoAppID := c.Config.AppID
	authBase := strings.TrimSuffix(strings.TrimSpace(c.Config.BaseURL), "/")
	c.mu.RUnlock()
	// P1-163/165: auth endpoints derive from BaseURL so staging/mock can
	// redirect the full login flow; production default keeps api.arrow.trade
	// (BROKER-MD-001 live evidence 2026-08-13) since Config.BaseURL defaults
	// to the edge host only for API traffic — auth callers set BaseURL to
	// the auth host when a non-production flow is needed.
	if authBase == "" {
		authBase = "https://api.arrow.trade"
	}
	loginURL := authBase + "/auth/app/login"
	validateURL := authBase + "/auth/validate-2fa"

	// Step 1: Send Login Request (R-099: json.Marshal, never raw interpolation)
	loginBody := struct {
		UserID       string `json:"userID"`
		Password     string `json:"password"`
		CaptchaValue string `json:"captchaValue"`
		CaptchaID    any    `json:"captchaID"`
		AppID        string `json:"appID"`
		IsAppLogin   bool   `json:"isAppLogin"`
	}{
		UserID: username, Password: password, CaptchaID: nil,
		AppID: autoAppID, IsAppLogin: true,
	}
	loginPayload, err := json.Marshal(loginBody)
	if err != nil {
		return fmt.Errorf("marshal login payload: %w", err)
	}
	resp, err := c.rawRequest(loginURL, "POST", loginPayload)
	if err != nil {
		log.Error().Err(err).Msg("Login request failed")
		return &AuthError{Stage: "login", Err: err}
	}

	var loginResp struct {
		Status  string `json:"status"`
		Message string `json:"message"` // P1-164: server rejection reason.
		Error   string `json:"error"`   // P1-164: alternate reason field.
		Data    struct {
			RequestID string `json:"requestId"` // Temporary request ID for 2FA validation.
		} `json:"data"`
	}

	if err := json.Unmarshal(resp, &loginResp); err != nil {
		log.Error().Err(err).Msg("Failed to parse login response")
		return &AuthError{Stage: "login", Err: err}
	}

	// R-100: a missing requestId would send a broken 2FA request — fail fast.
	if loginResp.Data.RequestID == "" {
		return &AuthError{Stage: "login", Err: fmt.Errorf(
			"empty requestId from login response (status=%s message=%s error=%s)",
			loginResp.Status, truncStr(loginResp.Message, 200), truncStr(loginResp.Error, 200))}
	}

	// Step 2: Generate TOTP Code
	passcode, err := generateTOTP(totpSecret)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate TOTP code")
		return &AuthError{Stage: "totp", Err: err}
	}

	// Step 3: Validate 2FA (R-099: json.Marshal)
	totpBody := struct {
		Code      string `json:"code"`
		RequestID string `json:"requestId"`
		UserID    string `json:"userID"`
	}{
		Code: passcode, RequestID: loginResp.Data.RequestID, UserID: username,
	}
	totpPayload, err := json.Marshal(totpBody)
	if err != nil {
		return fmt.Errorf("marshal 2fa payload: %w", err)
	}
	resp, err = c.rawRequest(validateURL, "POST", totpPayload)
	if err != nil {
		log.Error().Err(err).Msg("2FA validation failed")
		return &AuthError{Stage: "totp", Err: err}
	}

	var totpResp struct {
		Status  string `json:"status"`
		Message string `json:"message"` // P1-166: bad-TOTP rejection reason.
		Error   string `json:"error"`   // P1-166: alternate reason field.
		Data    struct {
			RedirectURL string `json:"redirectUrl"` // URL containing the request token.
		} `json:"data"`
	}

	if err := json.Unmarshal(resp, &totpResp); err != nil {
		log.Error().Err(err).Msg("Failed to parse 2FA response")
		return &AuthError{Stage: "redirect", Err: err}
	}

	// Step 4: Extract Request Token from Redirect URL
	// P1-167: an empty redirect (2FA rejection/contract change) is a
	// distinct failure from a present URL missing the token; only query
	// form (?request-token=) is supported — fragment form (#...) is not
	// observed on this endpoint and fails as missing-token.
	if totpResp.Data.RedirectURL == "" {
		return &AuthError{Stage: "redirect", Err: fmt.Errorf(
			"empty redirectUrl in 2fa response (status=%s message=%s error=%s)",
			totpResp.Status, truncStr(totpResp.Message, 200), truncStr(totpResp.Error, 200))}
	}
	parsedURL, err := url.Parse(totpResp.Data.RedirectURL)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse redirect URL")
		return &AuthError{Stage: "redirect", Err: err}
	}

	requestToken := parsedURL.Query().Get("request-token")
	// R-100: never authenticate with an empty token — the old code silently
	// proceeded and the Authenticate call failed opaquely.
	if requestToken == "" {
		return &AuthError{Stage: "redirect", Err: fmt.Errorf("no request-token in redirect URL")}
	}

	// Step 5: Authenticate and Get Access Token
	if _, err = c.Authenticate(requestToken); err != nil {
		log.Error().Err(err).Msg("Authentication failed")
		return &AuthError{Stage: "authenticate", Err: err}
	}
	// P1-294 NOT APPLIED as asked: downstream pins this stderr line
	// (ingestion/bridge run logs + 2040158 kept it deliberately). debugf
	// already logs the same event for quiet callers; removing the line
	// would silently break the pinned run-log contract.
	fmt.Fprintln(os.Stderr, "arrow-auth: AutoLogin successful.")
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

// truncStr caps server-provided reason strings in errors (P1-161/164/166).
func truncStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

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
