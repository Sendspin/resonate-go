// ABOUTME: WebSocket client for Sendspin Protocol communication
// ABOUTME: Handles connection, handshake, and message routing
package protocol

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// BinaryMessageHeaderSize is the size of binary message header (type byte + timestamp)
	BinaryMessageHeaderSize = 1 + 8 // 9 bytes: 1 byte type + 8 byte timestamp

	// AudioChunkMessageType is the binary message type ID for audio chunks.
	// Per spec: Player role binary messages use IDs 4-7 (bits 000001xx), slot 0 is audio.
	AudioChunkMessageType = 4

	// Artwork binary message type IDs per spec: Artwork role uses 8-11, one per channel.
	// ArtworkChannel0MessageType is channel 0; channels 1-3 use 9, 10, 11 respectively.
	ArtworkChannel0MessageType = 8
	ArtworkChannel1MessageType = 9
	ArtworkChannel2MessageType = 10
	ArtworkChannel3MessageType = 11

	// ArtworkChannelCount is the maximum number of artwork channels the spec allocates binary IDs for.
	ArtworkChannelCount = 4
)

// Heartbeat parameters. Vars (not consts) so tests can override with shorter
// values; production code never mutates them.
//
//	pingPeriod: how often we send a control Ping to the server.
//	pongWait:   read deadline; reset on every Pong arrival.
//	writeWait:  bound on each WriteControl call so a slow socket doesn't
//	            block the ping goroutine forever.
//
// Invariant: pingPeriod < pongWait. Otherwise the deadline can expire
// before our next ping has a chance to elicit a pong.
var (
	pingPeriod = 30 * time.Second
	pongWait   = 60 * time.Second
	writeWait  = 10 * time.Second
)

type Config struct {
	ServerAddr          string
	ClientID            string
	Name                string
	Version             int
	DeviceInfo          DeviceInfo
	PlayerV1Support     PlayerV1Support
	ArtworkV1Support    *ArtworkV1Support
	VisualizerV1Support *VisualizerV1Support

	// SupportedRoles overrides the auto-built role list in the client/hello
	// message. When nil or empty, handshake() builds the list from the V1
	// support fields above (player@v1 + metadata@v1 always, plus artwork@v1
	// and visualizer@v1 when their support structs are set). Set this to
	// advertise a specific subset — e.g. []string{"metadata@v1"} for a
	// metadata-only client, or []string{"controller@v1"} for controller
	// scenarios where advertising player@v1 would incorrectly activate
	// the audio stream.
	SupportedRoles []string
}

type Client struct {
	config Config
	conn   *websocket.Conn
	mu     sync.RWMutex

	AudioChunks   chan AudioChunk
	ArtworkChunks chan ArtworkChunk
	ControlMsgs   chan PlayerCommand
	TimeSyncResp  chan ServerTime
	StreamStart   chan StreamStart
	StreamClear   chan StreamClear
	StreamEnd     chan StreamEnd
	ServerState   chan ServerStateMessage
	GroupUpdate   chan GroupUpdate

	// serverHello holds the parsed server/hello message received during
	// handshake. Nil until Start()/Connect() completes successfully.
	serverHello *ServerHello

	// rawServerHello holds the raw JSON envelope bytes of the server/hello
	// message, useful for conformance testing and protocol debugging where
	// the exact wire representation matters.
	rawServerHello []byte

	connected bool
	ctx       context.Context
	cancel    context.CancelFunc
}

type AudioChunk struct {
	Timestamp int64 // Microseconds, server clock
	Data      []byte
}

// ArtworkChunk is an incoming binary artwork frame routed from the artwork@v1 role.
type ArtworkChunk struct {
	Channel   int   // 0-3; derived from the binary message type minus ArtworkChannel0MessageType
	Timestamp int64 // Microseconds, server clock
	Data      []byte
}

func NewClient(config Config) *Client {
	return newClient(config)
}

// NewClientFromConn wraps an already-established websocket connection. Use
// this for server-initiated scenarios: the caller has accepted an incoming
// connection on a listening socket and now needs the library to run the
// client-side protocol (handshake, message loop, channel routing) over it.
//
// Unlike NewClient+Connect, the returned client is NOT yet running — call
// Start to perform the handshake and launch the read loop.
//
// The caller transfers ownership of conn to the client; Close will close it.
func NewClientFromConn(config Config, conn *websocket.Conn) *Client {
	c := newClient(config)
	c.conn = conn
	c.connected = true
	return c
}

func newClient(config Config) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config:        config,
		AudioChunks:   make(chan AudioChunk, 100),
		ArtworkChunks: make(chan ArtworkChunk, 10),
		ControlMsgs:   make(chan PlayerCommand, 10),
		TimeSyncResp:  make(chan ServerTime, 10),
		StreamStart:   make(chan StreamStart, 1),
		StreamClear:   make(chan StreamClear, 10),
		StreamEnd:     make(chan StreamEnd, 1),
		ServerState:   make(chan ServerStateMessage, 10),
		GroupUpdate:   make(chan GroupUpdate, 10),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Connect dials the configured server, runs the handshake, and starts the
// message read loop. Use NewClientFromConn + Start when you already have
// an accepted connection (server-initiated scenarios).
func (c *Client) Connect() error {
	u := url.URL{Scheme: "ws", Host: c.config.ServerAddr, Path: "/sendspin"}
	log.Printf("Connecting to %s", u.String())

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.connected = true
	c.mu.Unlock()

	return c.Start()
}

// Start runs the client/hello handshake and launches the background read
// loop. The connection must already be set via NewClientFromConn or Connect.
// Calling Start more than once on the same client is undefined.
func (c *Client) Start() error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return fmt.Errorf("no connection: use NewClientFromConn or Connect before Start")
	}

	conn.SetReadLimit(1 << 20) // 1MB

	if err := c.handshake(); err != nil {
		c.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Snapshot the heartbeat vars on Start's goroutine so the values we
	// pass to pingLoop and the PongHandler are read here, not from the
	// goroutines we're about to spawn. Tests mutate these package-level
	// vars between test cases; the snapshot establishes a happens-before
	// from the mutation site to the goroutine read, which the race
	// detector requires.
	pp, pw, ww := pingPeriod, pongWait, writeWait

	// Install PongHandler that resets the read deadline. The handler runs
	// synchronously from ReadMessage's goroutine, so SetReadDeadline is
	// safe to call from here.
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pw))
	})

	// Initial deadline. If the server never pongs, ReadMessage in
	// readMessages will hit this deadline and exit, triggering Close().
	if err := conn.SetReadDeadline(time.Now().Add(pw)); err != nil {
		c.Close()
		return fmt.Errorf("set read deadline: %w", err)
	}

	go c.readMessages()
	go c.pingLoop(pp, ww)

	return nil
}

// pingLoop sends a periodic WebSocket control ping. The server's pong
// reply arrives via the PongHandler installed in Start, which resets
// the read deadline. Exits on context cancel or write failure; on
// write failure we just return — readMessages's defer is responsible
// for the Close, so calling it from here would race that path.
//
// The period and write deadline are passed as args (rather than read
// from the package vars) so the read happens-before the goroutine
// launch; tests that mutate the package vars between cases stay clean
// under -race.
func (c *Client) pingLoop(period, writeDeadline time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			conn := c.conn
			if conn == nil {
				c.mu.Unlock()
				return
			}
			err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeDeadline))
			c.mu.Unlock()
			if err != nil {
				// Write failure on a control frame means the connection
				// is going down. Don't bother retrying — readMessages
				// will hit the read deadline and tear down.
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) handshake() error {
	roles := c.buildSupportedRoles()

	hello := ClientHello{
		ClientID:            c.config.ClientID,
		Name:                c.config.Name,
		Version:             c.config.Version,
		SupportedRoles:      roles,
		DeviceInfo:          &c.config.DeviceInfo,
		ArtworkV1Support:    c.config.ArtworkV1Support,
		VisualizerV1Support: c.config.VisualizerV1Support,
	}
	// Only advertise player@v1_support when player@v1 is in the role list.
	// Strict peers (aiosendspin) reject a client/hello that carries a
	// player@v1_support block without a matching role because the schema
	// marks supported_formats as non-nullable, and a zero-value Go
	// PlayerV1Support encodes its nil slice as JSON null.
	if containsRole(roles, "player@v1") {
		hello.PlayerV1Support = &c.config.PlayerV1Support
	}

	msg := Message{
		Type:    "client/hello",
		Payload: hello,
	}

	if err := c.sendJSON(msg); err != nil {
		return fmt.Errorf("failed to send client/hello: %w", err)
	}

	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read server/hello: %w", err)
	}
	c.conn.SetReadDeadline(time.Time{}) // Clear deadline

	var serverMsg Message
	if err := json.Unmarshal(data, &serverMsg); err != nil {
		return fmt.Errorf("failed to parse server/hello: %w", err)
	}

	if serverMsg.Type != "server/hello" {
		return fmt.Errorf("expected server/hello, got %s", serverMsg.Type)
	}

	// Parse the server hello payload into a typed struct and cache both
	// the parsed form and the raw envelope bytes for later retrieval via
	// ServerHello() / RawServerHello().
	payloadBytes, err := json.Marshal(serverMsg.Payload)
	if err != nil {
		return fmt.Errorf("failed to re-marshal server/hello payload: %w", err)
	}
	var parsedHello ServerHello
	if err := json.Unmarshal(payloadBytes, &parsedHello); err != nil {
		return fmt.Errorf("failed to decode server/hello payload: %w", err)
	}

	c.mu.Lock()
	c.serverHello = &parsedHello
	c.rawServerHello = append([]byte(nil), data...)
	c.mu.Unlock()

	log.Printf("Handshake complete with server")

	// Send initial state per spec (client/state with nested player object)
	state := ClientStateMessage{
		Player: &PlayerState{
			State:  "synchronized",
			Volume: 100,
			Muted:  false,
		},
	}

	stateMsg := Message{
		Type:    "client/state",
		Payload: state,
	}

	if err := c.sendJSON(stateMsg); err != nil {
		return fmt.Errorf("failed to send initial state: %w", err)
	}

	return nil
}

// ServerHello returns the parsed server/hello message received during
// handshake, or nil if handshake has not yet completed. Safe for concurrent
// reads; callers should not mutate the returned struct.
func (c *Client) ServerHello() *ServerHello {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serverHello
}

// RawServerHello returns the raw JSON envelope bytes of the server/hello
// message received during handshake, or nil if handshake has not yet
// completed. Useful for conformance testing and protocol debugging where
// the exact wire representation matters. Returns a fresh copy; callers
// may mutate it without affecting the client.
func (c *Client) RawServerHello() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.rawServerHello == nil {
		return nil
	}
	out := make([]byte, len(c.rawServerHello))
	copy(out, c.rawServerHello)
	return out
}

// Send writes a typed envelope to the connected peer. The message is
// wrapped as {"type": msgType, "payload": payload} and sent as a text
// WebSocket frame. Use this for protocol messages the library does not
// yet have a dedicated sender for (e.g. client/command in controller
// scenarios).
func (c *Client) Send(msgType string, payload any) error {
	return c.sendJSON(Message{Type: msgType, Payload: payload})
}

// containsRole reports whether the given role is in the list.
func containsRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// buildSupportedRoles returns the role list for the client/hello message.
// An explicit Config.SupportedRoles wins when set, since the caller is
// telling us exactly which roles to advertise (metadata-only, controller,
// etc.). Otherwise we build the default list from the V1 support fields:
// player@v1 and metadata@v1 are always advertised for backwards
// compatibility, and artwork@v1 / visualizer@v1 join the list when their
// support structs are set.
func (c *Client) buildSupportedRoles() []string {
	if len(c.config.SupportedRoles) > 0 {
		return c.config.SupportedRoles
	}
	roles := []string{"player@v1", "metadata@v1", "controller@v1"}
	if c.config.ArtworkV1Support != nil {
		roles = append(roles, "artwork@v1")
	}
	if c.config.VisualizerV1Support != nil {
		roles = append(roles, "visualizer@v1")
	}
	return roles
}

func (c *Client) sendJSON(msg Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected || c.conn == nil {
		return fmt.Errorf("not connected")
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	defer c.conn.SetWriteDeadline(time.Time{})

	return c.conn.WriteJSON(msg)
}

func (c *Client) readMessages() {
	defer c.Close()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		messageType, data, err := c.conn.ReadMessage()
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		if messageType == websocket.BinaryMessage {
			c.handleBinaryMessage(data)
		} else if messageType == websocket.TextMessage {
			c.handleJSONMessage(data)
		} else {
			log.Printf("Unknown WebSocket message type: %d", messageType)
		}
	}
}

func (c *Client) handleBinaryMessage(data []byte) {
	if len(data) < BinaryMessageHeaderSize {
		log.Printf("Invalid binary message: too short")
		return
	}

	msgType := data[0]
	timestamp := int64(binary.BigEndian.Uint64(data[1:BinaryMessageHeaderSize]))
	payload := data[BinaryMessageHeaderSize:]

	switch {
	case msgType == AudioChunkMessageType:
		chunk := AudioChunk{Timestamp: timestamp, Data: payload}
		select {
		case c.AudioChunks <- chunk:
		case <-c.ctx.Done():
		default:
			// Audio is real-time data. Drop the oldest queued chunk rather than
			// blocking the WebSocket reader, which also dispatches clock-sync,
			// heartbeat, and control messages.
			select {
			case <-c.AudioChunks:
			default:
			}
			select {
			case c.AudioChunks <- chunk:
			case <-c.ctx.Done():
			default:
			}
		}
	case msgType >= ArtworkChannel0MessageType && msgType <= ArtworkChannel3MessageType:
		select {
		case c.ArtworkChunks <- ArtworkChunk{
			Channel:   int(msgType) - ArtworkChannel0MessageType,
			Timestamp: timestamp,
			Data:      payload,
		}:
		case <-c.ctx.Done():
		}
	default:
		log.Printf("Unknown binary message type: %d", msgType)
	}
}

// handleJSONMessage routes JSON messages per spec
func (c *Client) handleJSONMessage(data []byte) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("Failed to parse JSON message: %v", err)
		return
	}

	payloadBytes, err := json.Marshal(msg.Payload)
	if err != nil {
		log.Printf("Failed to marshal payload for %s: %v", msg.Type, err)
		return
	}

	switch msg.Type {
	case "server/command":
		var cmdMsg ServerCommandMessage
		if err := json.Unmarshal(payloadBytes, &cmdMsg); err != nil {
			log.Printf("Failed to parse server/command: %v", err)
			return
		}
		if cmdMsg.Player != nil {
			select {
			case c.ControlMsgs <- *cmdMsg.Player:
			case <-c.ctx.Done():
			default:
				log.Printf("ControlMsgs channel full, dropping command")
			}
		}

	case "server/time":
		var timeMsg ServerTime
		if err := json.Unmarshal(payloadBytes, &timeMsg); err != nil {
			log.Printf("Failed to parse server/time: %v", err)
			return
		}
		select {
		case c.TimeSyncResp <- timeMsg:
		case <-c.ctx.Done():
		}

	case "stream/start":
		var start StreamStart
		if err := json.Unmarshal(payloadBytes, &start); err != nil {
			log.Printf("Failed to parse stream/start: %v", err)
			return
		}
		select {
		case c.StreamStart <- start:
		case <-c.ctx.Done():
		}

	case "stream/clear":
		var clear StreamClear
		if err := json.Unmarshal(payloadBytes, &clear); err != nil {
			log.Printf("Failed to parse stream/clear: %v", err)
			return
		}
		select {
		case c.StreamClear <- clear:
		case <-c.ctx.Done():
		}

	case "stream/end":
		var end StreamEnd
		if err := json.Unmarshal(payloadBytes, &end); err != nil {
			log.Printf("Failed to parse stream/end: %v", err)
			return
		}
		select {
		case c.StreamEnd <- end:
		case <-c.ctx.Done():
		}

	case "server/state":
		var state ServerStateMessage
		if err := json.Unmarshal(payloadBytes, &state); err != nil {
			log.Printf("Failed to parse server/state: %v", err)
			return
		}
		if state.Metadata != nil {
			log.Printf("Metadata: %v - %v (%v)",
				derefString(state.Metadata.Artist),
				derefString(state.Metadata.Title),
				derefString(state.Metadata.Album))
		}
		select {
		case c.ServerState <- state:
		case <-time.After(100 * time.Millisecond):
			log.Printf("Server state channel full, dropping message")
		}

	case "group/update":
		var update GroupUpdate
		if err := json.Unmarshal(payloadBytes, &update); err != nil {
			log.Printf("Failed to parse group/update: %v", err)
			return
		}
		log.Printf("Group update: id=%v, state=%v",
			derefString(update.GroupID),
			derefString(update.PlaybackState))
		select {
		case c.GroupUpdate <- update:
		case <-time.After(100 * time.Millisecond):
			log.Printf("Group update channel full, dropping message")
		}

	default:
		log.Printf("Unknown message type: %s", msg.Type)
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// SendState sends a client/state message per spec
func (c *Client) SendState(state PlayerState) error {
	msg := Message{
		Type: "client/state",
		Payload: ClientStateMessage{
			Player: &state,
		},
	}
	return c.sendJSON(msg)
}

// SendGoodbye sends a client/goodbye message before disconnecting
func (c *Client) SendGoodbye(reason string) error {
	msg := Message{
		Type: "client/goodbye",
		Payload: ClientGoodbye{
			Reason: reason,
		},
	}
	return c.sendJSON(msg)
}

// SendRequestFormat sends a stream/request-format message asking the server to
// switch the player stream to a different codec/format. Zero-valued fields are
// omitted, asking the server to keep the current value. The server responds
// with a new stream/start.
func (c *Client) SendRequestFormat(player RequestFormatPlayer) error {
	msg := Message{
		Type: "stream/request-format",
		Payload: StreamRequestFormat{
			Player: &player,
		},
	}
	return c.sendJSON(msg)
}

func (c *Client) SendTimeSync(t1 int64) error {
	msg := Message{
		Type: "client/time",
		Payload: ClientTime{
			ClientTransmitted: t1,
		},
	}
	return c.sendJSON(msg)
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		c.connected = false
		c.cancel()
		c.conn.Close()
		log.Printf("Connection closed")
	}
}

// Done returns a channel that is closed when the client connection is lost.
func (c *Client) Done() <-chan struct{} {
	return c.ctx.Done()
}

func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}
