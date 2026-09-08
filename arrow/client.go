// client.go
package arrow

import (
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// Config holds the SDK configuration settings.
type Config struct {
	AppID        string // Application ID for API authentication.
	AppSecret    string // Application secret key for API authentication.
	Token        string // Authentication token for API requests.
	BaseURL      string // Base URL of the Arrow API.
	RefreshToken string // Token used to refresh authentication when expired.
	Debug        bool   // Enables verbose SDK debug logs when true.
	// HistoricalBaseURL is the host for GET /candle endpoints (R-104). It is
	// honored like BaseURL instead of being hardcoded, defaulting to the Arrow
	// production historical host.
	HistoricalBaseURL string
}

// Client is the main struct for interacting with the Arrow API.
//
// It contains the configuration settings and an HTTP client for making API requests.
//
// (WAVE9-F: P1-296 — request/rawRequest/rawRequestAuth were triplicated
// acquire/do/status/copy blocks; all three now funnel through doRequest.
// P1-034: Config/HTTPClient stay exported for the vendored bridge contract,
// but concurrent mutation bypasses the mutex — prefer SetToken/GetToken and
// treat Config as read-only after NewClient. Client must not be copied
// after first use: it contains a sync.RWMutex.)
type Client struct {
	Config     Config           // Configuration settings for the API client.
	HTTPClient *fasthttp.Client // HTTP client for executing requests.
	mu         sync.RWMutex
}

// NewClient initializes a new SDK client with the provided application credentials.
//
// Parameters:
//   - appID: The application ID used for authentication.
//   - appSecret: The application secret key used for authentication.
//
// Returns:
//   - A pointer to a newly created Client instance.
func NewClient(appID, appSecret string) *Client {
	return &Client{
		Config: Config{
			AppID:             appID,
			AppSecret:         appSecret,
			BaseURL:           "https://edge.arrow.trade",
			HistoricalBaseURL: "https://historical-api.arrow.trade",
		},
		HTTPClient: &fasthttp.Client{
			// R-138: no ReadTimeout/WriteTimeout previously — a stalled
			// endpoint blocked the caller indefinitely (at startup this hung
			// main inside AutoLogin/GetUserDetails).
			ReadTimeout:         15 * time.Second,
			WriteTimeout:        15 * time.Second,
			MaxIdleConnDuration: 60 * time.Second,
		},
	}
}

// request sends an HTTP API request to the Arrow server and retrieves the response.
//
// This function constructs an HTTP request with the required authentication headers
// and executes it using the `fasthttp` client.
//
// Parameters:
//   - endpoint: The API endpoint (relative to BaseURL) to send the request to.
//   - method: The HTTP method ("GET" or "POST").
//   - payload: The request body (for POST requests).
//
// Returns:
//   - A byte slice containing the response body if successful.
//   - An error if the request fails.
func (c *Client) request(endpoint string, method string, payload []byte) ([]byte, error) {
	// WAVE9-A (P1-031/035): copy auth fields under RLock so a concurrent
	// SetToken (Lock) cannot interleave the read.
	c.mu.RLock()
	baseURL, appID, token := c.Config.BaseURL, c.Config.AppID, c.Config.Token
	c.mu.RUnlock()
	url := baseURL + endpoint
	c.debugf("Making request", func(e *zerolog.Event) {
		e.Str("url", url).Str("method", method)
	})

	return c.doRequest(url, method, payload, appID, token, true)
}

// rawRequest sends an HTTP request to a fully specified URL and retrieves the response.
//
// Unlike `request()`, this function allows specifying an absolute URL rather than an endpoint.
//
// Parameters:
//   - url: The full API URL to send the request to.
//   - method: The HTTP method ("GET" or "POST").
//   - payload: The request body (for POST requests).
//
// Returns:
//   - A byte slice containing the response body if successful.
//   - An error if the request fails.
func (c *Client) rawRequest(url string, method string, payload []byte) ([]byte, error) {
	c.debugf("Making raw request", func(e *zerolog.Event) {
		e.Str("url", url).Str("method", method)
	})

	return c.doRequest(url, method, payload, "", "", false)
}

// rawRequestAuth is like rawRequest but sets appId and token headers (required by historical-api.arrow.trade).
func (c *Client) rawRequestAuth(fullURL string, method string, payload []byte) ([]byte, error) {
	c.debugf("Making raw request (auth)", func(e *zerolog.Event) {
		e.Str("url", fullURL).Str("method", method)
	})

	// WAVE9-A: snapshot auth under RLock (SetToken races this path).
	c.mu.RLock()
	authAppID, authToken := c.Config.AppID, c.Config.Token
	c.mu.RUnlock()
	return c.doRequest(fullURL, method, payload, authAppID, authToken, true)
}

// doRequest is the single acquire/do/status/copy funnel shared by
// request/rawRequest/rawRequestAuth. (WAVE9-F: P1-296.)
//
// Non-2xx responses return *StatusError carrying the code plus a truncated
// body excerpt, so callers can switch on 401 vs 429 vs 5xx for re-auth vs
// retry. (WAVE9-F: P1-168.)
func (c *Client) doRequest(url, method string, payload []byte, appID, token string, withAuth bool) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetRequestURI(url)
	if withAuth {
		req.Header.Set("appId", appID)
		req.Header.Set("token", token)
	}
	req.Header.SetMethod(method)
	if len(payload) > 0 {
		req.Header.SetContentType("application/json")
		req.SetBody(payload)
	}

	// P1-169: a nil HTTPClient (zero-value Client) previously panicked in
	// fasthttp; fail with a diagnosable error instead.
	hc := c.HTTPClient
	if hc == nil {
		return nil, fmt.Errorf("arrow client: nil HTTPClient (use NewClient)")
	}
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Execute the request using the fasthttp client.
	if err := hc.Do(req, resp); err != nil {
		log.Error().Err(err).Msg("API request failed")
		return nil, err
	}
	if resp.StatusCode() >= fasthttp.StatusBadRequest {
		return nil, newStatusError(resp.StatusCode(), resp.Body())
	}

	// The response buffer is pooled — copy before release.
	return append([]byte(nil), resp.Body()...), nil
}

// statusBodyMax is the excerpt cap for error bodies carried by StatusError.
const statusBodyMax = 512

// StatusError is a typed non-2xx HTTP failure from the Arrow API.
// Callers can errors.As-switch on StatusCode (401 re-auth vs 429 backoff vs
// 5xx retry) instead of string-matching a collapsed fmt.Errorf.
type StatusError struct {
	StatusCode int
	Body       string // truncated to statusBodyMax bytes
}

func newStatusError(code int, body []byte) *StatusError {
	b := append([]byte(nil), body...)
	if len(b) > statusBodyMax {
		b = b[:statusBodyMax]
	}
	return &StatusError{StatusCode: code, Body: string(b)}
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("arrow: request failed with status %d", e.StatusCode)
	}
	return fmt.Sprintf("arrow: request failed with status %d: %s", e.StatusCode, e.Body)
}

// SetToken updates the authentication token dynamically.
//
// This function allows updating the API token at runtime without needing to recreate the client.
//
// Parameters:
//   - token: The new authentication token.
func (c *Client) SetToken(token string) {
	// WAVE9-A (P1-031): Lock the write — orders vs RLock readers
	// (request/rawRequestAuth/dial paths + GetToken/GetRefreshToken).
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Config.Token = token
}

// SetDebug enables or disables verbose SDK logging.
func (c *Client) SetDebug(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Config.Debug = enabled
}

// IsDebug returns whether verbose SDK logging is enabled.
func (c *Client) IsDebug() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Config.Debug
}

func (c *Client) debugf(msg string, addFields func(*zerolog.Event)) {
	if !c.IsDebug() {
		return
	}
	e := log.Debug()
	if addFields != nil {
		addFields(e)
	}
	e.Msg(msg)
}

// GetToken retrieves the current authentication token.
//
// This function returns the current API token used for authentication.
//
// Returns:
//   - The current authentication token.
func (c *Client) GetToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Config.Token
}

// GetRefreshToken gets the refresh token of the user.
//
// This function allows to get the refresh token at runtime which can be used to create new Token.
//
// Returns:
//   - refreshToken: The refresh token.
func (c *Client) GetRefreshToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Config.RefreshToken
}
