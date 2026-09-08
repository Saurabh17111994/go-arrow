package arrow

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	orderStreamURL = "wss://order-updates.arrow.trade"
	dataStreamURL  = "wss://ds.arrow.trade"
)

// defaultStreamReadDeadlineMs bounds how long ReadTicks/ReadUpdates block
// in ReadMessage with no frame. Idle symbols must not require reconnect:
// a read timeout continues the loop; only non-timeout errors (or ctx
// cancellation) terminate the stream. (WAVE9-D, P1-046.)
const defaultStreamReadDeadlineMs = 30000

// dialStream is the single dial funnel for the three sockets. Dial errors
// previously discarded the HTTP response (auth rejections lost their status)
// and returned the raw gorilla error; the wrapper reports host + status
// only — the query carries appID/token and must never enter an error string.
// (WAVE9-D, P1-045 dial half.)
func dialStream(rawurl string) (*websocket.Conn, error) {
	conn, resp, err := websocket.DefaultDialer.Dial(rawurl, nil)
	if err != nil {
		host := rawurl
		if u, perr := url.Parse(rawurl); perr == nil && u.Host != "" {
			host = u.Scheme + "://" + u.Host
		}
		if resp != nil {
			if resp.Body != nil {
				resp.Body.Close()
			}
			return nil, fmt.Errorf("dial %s: %s: %w", host, resp.Status, err)
		}
		return nil, fmt.Errorf("dial %s: %w", host, err)
	}
	return conn, nil
}

// isReadTimeout reports whether a ReadMessage error is a read-deadline
// expiry (idle feed), as opposed to a fatal transport error.
func isReadTimeout(err error) bool {
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

// StreamMode is the subscription mode for the token-based market WebSocket (wss://ds.arrow.trade).
// Inbound ticks are binary, big-endian int fields, with lengths 13 / 17 / 93 / 241 by mode (aligned with Arrow’s JS/Python clients).
// REST /info/quote uses a smaller set; see InfoQuoteMode in quote.go.
type StreamMode string

const (
	StreamModeLTP   StreamMode = "ltp"
	StreamModeLTPC  StreamMode = "ltpc"
	StreamModeQuote StreamMode = "quote"
	StreamModeFull  StreamMode = "full"
)

type DepthLevel struct {
	Quantity int64 `json:"quantity"`
	Price    int32 `json:"price"`
	Orders   int16 `json:"orders"`
}

type MarketTick struct {
	Token             int32        `json:"token"`
	Mode              StreamMode   `json:"mode"`
	LTP               int32        `json:"ltp"`
	Close             int32        `json:"close"`
	NetChange         float64      `json:"netChange"`
	ChangeFlag        int8         `json:"changeFlag"`
	LTQ               int32        `json:"ltq"`
	AvgPrice          int32        `json:"avgPrice"`
	TotalBuyQuantity  int64        `json:"totalBuyQuantity"`
	TotalSellQuantity int64        `json:"totalSellQuantity"`
	Open              int32        `json:"open"`
	High              int32        `json:"high"`
	Low               int32        `json:"low"`
	Volume            int64        `json:"volume"`
	LTT               int32        `json:"ltt"`
	Time              int32        `json:"time"`
	OI                int64        `json:"oi"`
	OIDayHigh         int64        `json:"oiDayHigh"`
	OIDayLow          int64        `json:"oiDayLow"`
	LowerLimit        int32        `json:"lowerLimit"`
	UpperLimit        int32        `json:"upperLimit"`
	Bids              []DepthLevel `json:"bids"`
	Asks              []DepthLevel `json:"asks"`
}

type DataStream struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (c *Client) ConnectDataStream() (*DataStream, error) {
	// WAVE9-A: snapshot auth under RLock (SetToken races dial).
	c.mu.RLock()
	dsAppID, dsToken := c.Config.AppID, c.Config.Token
	c.mu.RUnlock()
	q := url.Values{}
	q.Set("appID", dsAppID)
	q.Set("token", dsToken)
	u := fmt.Sprintf("%s?%s", dataStreamURL, q.Encode())
	// WAVE9-D: dialStream reports host + HTTP status, never credentials.
	conn, err := dialStream(u)
	if err != nil {
		return nil, err
	}
	return &DataStream{conn: conn}, nil
}

func (s *DataStream) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *DataStream) Subscribe(mode StreamMode, tokens []int32) error {
	return s.sendSubMessage("sub", mode, tokens)
}

func (s *DataStream) Unsubscribe(mode StreamMode, tokens []int32) error {
	return s.sendSubMessage("unsub", mode, tokens)
}

func (s *DataStream) sendSubMessage(code string, mode StreamMode, tokens []int32) error {
	msg := map[string]any{
		"code":       code,
		"mode":       mode,
		string(mode): tokens,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s == nil || s.conn == nil {
		// WAVE9-D (P1-199 analogue): nil conn/stream is a caller bug —
		// error, never panic.
		return fmt.Errorf("data stream %s: nil connection", code)
	}
	// WAVE9-D (P1-045): a wedged TCP connection must not block writes
	// forever — HFT already sets a 10s write deadline; do the same here.
	if err := s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("data stream %s set deadline: %w", code, err)
	}
	if err := s.conn.WriteJSON(msg); err != nil {
		return fmt.Errorf("data stream %s write: %w", code, err)
	}
	return nil
}

// ReadTicks reads and parses market-tick payloads until ctx is done or the
// socket errors fatally. A read-deadline expiry (idle feed, no ticks for
// 30s) continues the loop — an idle symbol must not require a full
// reconnect; only non-timeout errors (or ctx cancellation) terminate.
// (WAVE9-D, P1-046.) Text frames (e.g. JSON error/keepalive) are ignored:
// only binary frames reach ParseMarketTick. (WAVE9-D, P1-199.)
func (s *DataStream) ReadTicks(ctx context.Context, onTick func(MarketTick), onError func(error)) {
	if s == nil || s.conn == nil {
		if onError != nil {
			onError(fmt.Errorf("data stream read: nil stream/connection"))
		}
		return
	}
	// Prompt ctx unblock: close the connection when ctx fires so
	// ReadMessage returns instead of stalling up to the read deadline.
	stop := context.AfterFunc(ctx, func() {
		if s != nil && s.conn != nil {
			_ = s.conn.UnderlyingConn().Close()
		}
	})
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(defaultStreamReadDeadlineMs * time.Millisecond))
		mt, payload, err := s.conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isReadTimeout(err) {
				continue
			}
			if onError != nil && !errors.Is(err, websocket.ErrCloseSent) {
				onError(err)
			}
			return
		}
		if mt != websocket.BinaryMessage {
			continue
		}
		if len(payload) < 13 {
			// Heartbeats / control payloads (e.g. 1 byte) — ignore.
			continue
		}
		tick, err := ParseMarketTick(payload)
		if err != nil {
			if onError != nil {
				onError(err)
			}
			continue
		}
		onTick(tick)
	}
}

func ParseMarketTick(data []byte) (MarketTick, error) {
	switch len(data) {
	case 13:
		return parseLTP(data), nil
	case 17:
		return parseLTPC(data), nil
	case 93:
		return parseQuote(data), nil
	case 241:
		return parseFull(data), nil
	default:
		return MarketTick{}, fmt.Errorf("unsupported market tick payload size: %d", len(data))
	}
}

func parseLTP(data []byte) MarketTick {
	return MarketTick{
		Token: beI32(data[0:4]),
		LTP:   beI32(data[4:8]),
		Mode:  StreamModeLTP,
	}
}

func parseLTPC(data []byte) MarketTick {
	ltp := beI32(data[4:8])
	closePx := beI32(data[13:17])
	tick := MarketTick{
		Token:      beI32(data[0:4]),
		LTP:        ltp,
		Close:      closePx,
		Mode:       StreamModeLTPC,
		ChangeFlag: int8(data[8]),
	}
	if closePx != 0 {
		tick.NetChange = float64(ltp-closePx) * 100 / float64(closePx)
	}
	return tick
}

func parseQuote(data []byte) MarketTick {
	tick := parseLTPC(data)
	tick.Mode = StreamModeQuote
	tick.LTQ = beI32(data[13:17])
	tick.AvgPrice = beI32(data[17:21])
	tick.TotalBuyQuantity = beI64(data[21:29])
	tick.TotalSellQuantity = beI64(data[29:37])
	tick.Open = beI32(data[37:41])
	tick.High = beI32(data[41:45])
	tick.Close = beI32(data[45:49])
	tick.Low = beI32(data[49:53])
	tick.Volume = beI64(data[53:61])
	tick.LTT = beI32(data[61:65])
	tick.Time = beI32(data[65:69])
	tick.OI = beI64(data[69:77])
	tick.OIDayHigh = beI64(data[77:85])
	tick.OIDayLow = beI64(data[85:93])
	if tick.Close != 0 {
		tick.NetChange = float64(tick.LTP-tick.Close) * 100 / float64(tick.Close)
	}
	return tick
}

func parseFull(data []byte) MarketTick {
	tick := parseQuote(data)
	tick.Mode = StreamModeFull
	tick.LowerLimit = beI32(data[93:97])
	tick.UpperLimit = beI32(data[97:101])
	tick.Bids = make([]DepthLevel, 0, 5)
	tick.Asks = make([]DepthLevel, 0, 5)
	for i := 0; i < 10; i++ {
		offset := 101 + i*14
		level := DepthLevel{
			Quantity: beI64(data[offset : offset+8]),
			Price:    beI32(data[offset+8 : offset+12]),
			Orders:   int16(binary.BigEndian.Uint16(data[offset+12 : offset+14])),
		}
		if i < 5 {
			tick.Bids = append(tick.Bids, level)
		} else {
			tick.Asks = append(tick.Asks, level)
		}
	}
	return tick
}

type OrderStream struct {
	conn *websocket.Conn
}

func (c *Client) ConnectOrderStream() (*OrderStream, error) {
	// WAVE9-A: snapshot auth under RLock (SetToken races dial).
	c.mu.RLock()
	osAppID, osToken := c.Config.AppID, c.Config.Token
	c.mu.RUnlock()
	q := url.Values{}
	q.Set("appID", osAppID)
	q.Set("token", osToken)
	u := fmt.Sprintf("%s?%s", orderStreamURL, q.Encode())
	// WAVE9-D: dialStream reports host + HTTP status, never credentials.
	conn, err := dialStream(u)
	if err != nil {
		return nil, err
	}
	return &OrderStream{conn: conn}, nil
}

func (s *OrderStream) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *OrderStream) ReadUpdates(ctx context.Context, onUpdate func(map[string]any), onError func(error)) {
	if s == nil || s.conn == nil {
		if onError != nil {
			onError(fmt.Errorf("order stream read: nil stream/connection"))
		}
		return
	}
	// Prompt ctx unblock: close the connection when ctx fires so
	// ReadMessage returns instead of stalling up to the read deadline.
	stop := context.AfterFunc(ctx, func() {
		if s != nil && s.conn != nil {
			_ = s.conn.UnderlyingConn().Close()
		}
	})
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Read deadline so ctx cancellation unblocks promptly; idle
		// timeouts continue, fatal errors terminate. (WAVE9-D, P1-046.)
		_ = s.conn.SetReadDeadline(time.Now().Add(defaultStreamReadDeadlineMs * time.Millisecond))
		mt, payload, err := s.conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isReadTimeout(err) {
				continue
			}
			if onError != nil && !errors.Is(err, websocket.ErrCloseSent) {
				onError(err)
			}
			return
		}
		if mt != websocket.TextMessage {
			continue
		}
		payload = trimNulls(payload)
		if len(payload) == 0 {
			continue
		}
		var update map[string]any
		if err := json.Unmarshal(payload, &update); err != nil {
			// WAVE9-D (P1-202): report corrupt/non-JSON text instead of
			// dropping it silently — a protocol change is then visible
			// via onError rather than indistinguishable from keepalive.
			if onError != nil {
				onError(fmt.Errorf("order update: non-JSON text frame (%d bytes): %w", len(payload), err))
			}
			continue
		}
		onUpdate(update)
	}
}

// trimNulls strips leading NUL padding and trailing NUL/whitespace so
// padded frames still parse. (WAVE9-D, P1-202 writer half.)
func trimNulls(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == 0 || b[len(b)-1] == ' ' || b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

type ArrowStreams struct {
	Client        *Client
	OrderStream   *OrderStream
	DataStream    *DataStream
	HFTDataStream *HFTDataStream // set by NewStreamsWithHFT when used; optional (see hft_stream.go)
}

// NewStreamsOrderOnly connects only the order-updates WebSocket (wss://order-updates.arrow.trade).
func (c *Client) NewStreamsOrderOnly() (*ArrowStreams, error) {
	orderStream, err := c.ConnectOrderStream()
	if err != nil {
		return nil, err
	}
	return &ArrowStreams{
		Client:      c,
		OrderStream: orderStream,
		DataStream:  nil,
	}, nil
}

func (c *Client) NewStreams() (*ArrowStreams, error) {
	orderStream, err := c.ConnectOrderStream()
	if err != nil {
		return nil, err
	}
	dataStream, err := c.ConnectDataStream()
	if err != nil {
		_ = orderStream.Close()
		return nil, err
	}
	return &ArrowStreams{
		Client:      c,
		OrderStream: orderStream,
		DataStream:  dataStream,
	}, nil
}

// NewStreamsWithHFT connects order updates (wss://order-updates.arrow.trade) and the HFT market socket (wss://socket.arrow.trade).
// It does not open the standard token data stream (wss://ds.arrow.trade); use NewStreams for order + standard market data.
func (c *Client) NewStreamsWithHFT() (*ArrowStreams, error) {
	orderStream, err := c.ConnectOrderStream()
	if err != nil {
		return nil, err
	}
	hft, err := c.ConnectHFTDataStream()
	if err != nil {
		_ = orderStream.Close()
		return nil, err
	}
	return &ArrowStreams{
		Client:        c,
		OrderStream:   orderStream,
		DataStream:    nil,
		HFTDataStream: hft,
	}, nil
}

// Close releases every open socket, preserving every close failure.
// (WAVE9-D, P1-302: errors.Join instead of first-error-wins.)
func (s *ArrowStreams) Close() error {
	var errs []error
	if s.OrderStream != nil {
		if err := s.OrderStream.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.DataStream != nil {
		if err := s.DataStream.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.HFTDataStream != nil {
		if err := s.HFTDataStream.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func beI32(data []byte) int32 {
	return int32(binary.BigEndian.Uint32(data))
}

func beI64(data []byte) int64 {
	return int64(binary.BigEndian.Uint64(data))
}

// defaultKeepAliveIntervalMs documents the broker keepalive expectation.
// P1-047 broker unknown: confirm the interval Arrow expects on
// wss://ds.arrow.trade + wss://socket.arrow.trade before tuning this.
const defaultKeepAliveIntervalMs = 30000

// StartKeepAlive is the legacy package-level keepalive. It is kept for
// compatibility but new code MUST use (DataStream).StartKeepAlive: the
// package function takes a raw *websocket.Conn and writes concurrently
// with sendSubMessage (which holds mu), violating gorilla/websocket's
// one-concurrent-writer rule. (WAVE9-D, P1-047.)
func StartKeepAlive(ctx context.Context, conn *websocket.Conn, interval time.Duration) {
	if conn == nil {
		return
	}
	if interval <= 0 {
		interval = defaultKeepAliveIntervalMs * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte("PONG")); err != nil {
				return
			}
		}
	}
}

// StartKeepAlive sends periodic PONG frames on the stream's own write mutex,
// so keepalive and Subscribe/Unsubscribe never write concurrently.
// A failed write (or ctx cancellation) stops the loop and reports the error
// via onError instead of ticking forever on a dead socket.
// (WAVE9-D, P1-047 fix.)
func (s *DataStream) StartKeepAlive(ctx context.Context, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		interval = defaultKeepAliveIntervalMs * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			if s == nil || s.conn == nil {
				s.mu.Unlock()
				return
			}
			_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := s.conn.WriteMessage(websocket.TextMessage, []byte("PONG"))
			s.mu.Unlock()
			if err != nil {
				if onError != nil {
					onError(fmt.Errorf("keepalive write: %w", err))
				}
				return
			}
		}
	}
}
