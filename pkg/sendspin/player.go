// ABOUTME: High-level Player API for Sendspin streaming
// ABOUTME: Composes Receiver + audio output with optional ProcessCallback
package sendspin

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	stdsync "sync"
	"time"

	"github.com/Sendspin/sendspin-go/pkg/audio"
	"github.com/Sendspin/sendspin-go/pkg/audio/decode"
	"github.com/Sendspin/sendspin-go/pkg/audio/output"
	"github.com/Sendspin/sendspin-go/pkg/protocol"
	sendspinsync "github.com/Sendspin/sendspin-go/pkg/sync"
)

// ReconnectConfig controls automatic reconnect behavior after the protocol
// connection drops. When Enabled is false (the zero value), Player behaves
// as a one-shot: a lost connection stays lost.
type ReconnectConfig struct {
	Enabled      bool
	InitialDelay time.Duration // default 500ms
	MaxDelay     time.Duration // default 30s
	Multiplier   float64       // default 2.0
	MaxAttempts  int           // 0 = infinite (default)

	// Rediscover is an optional callback invoked before each reconnect
	// attempt. Returning a non-empty address overrides the configured
	// ServerAddr for that attempt. Use this to re-run mDNS discovery when
	// the server may have moved. Errors are logged and the attempt falls
	// back to the last known address.
	Rediscover func(ctx context.Context) (string, error)
}

// PlayerConfig holds player configuration
type PlayerConfig struct {
	// ServerAddr is the server address (host:port)
	ServerAddr string

	PlayerName string

	// Volume is the initial volume (0-100)
	Volume int

	// BufferMs is the playback buffer size in milliseconds (default: 500)
	BufferMs int

	// StaticDelayMs shifts every scheduled play time forward by this many
	// milliseconds. Used to compensate for hardware that introduces a fixed
	// downstream latency (Bluetooth sinks, AVRs with DSP, some USB DACs).
	// Default 0 means no shift.
	StaticDelayMs int

	// PreferredCodec reorders the advertised format list so the server
	// picks this codec first. Values: "pcm" (default), "opus", "flac".
	PreferredCodec string

	// BufferCapacity is the buffer_capacity (bytes) advertised to the
	// server in client/hello. The server uses this to pace how far ahead
	// it sends audio. Default: 1048576 (1MB).
	BufferCapacity int

	// ClientID is the already-resolved client_id to advertise in client/hello.
	// Required — callers should compute this once at startup (typically via
	// ResolveClientID) and reuse the same value across reconnects.
	ClientID string

	// AudioDevice selects a specific playback device by name (as reported by
	// output.ListPlaybackDevices). Empty = let miniaudio pick the default.
	// Open fails loudly if a non-empty name doesn't match an available device.
	AudioDevice string

	// MaxSampleRate caps the highest SampleRate advertised to the server.
	// 0 = auto-probe the AudioDevice for its native ceiling on first Connect.
	// Setting either MaxSampleRate or MaxBitDepth to a non-zero value disables
	// auto-probe entirely (replace semantics — explicit user choice wins, even
	// if it raises the cap above what the probe would have found). Use the
	// override when the auto-probe is wrong, as on Pi3 where ALSA reports the
	// bcm2835 onboard headphones accept 192k/24 but the hardware can't
	// actually drain it.
	MaxSampleRate int
	// MaxBitDepth caps the highest BitDepth advertised to the server.
	// 0 = auto-probe. See MaxSampleRate for override semantics.
	MaxBitDepth int

	DeviceInfo DeviceInfo

	OnMetadata func(Metadata)

	OnStateChange func(PlayerState)

	OnError func(error)

	// Output overrides the default audio output backend.
	// When nil, a malgo-backed output is created on stream start.
	Output output.Output

	// DecoderFactory overrides the default decoder selection.
	// When nil, the default codec switch (PCM, Opus, FLAC) is used.
	DecoderFactory func(audio.Format) (decode.Decoder, error)

	// ProcessCallback is called with decoded samples before they are written to output.
	// Must not block. Runs on the audio consumption goroutine.
	ProcessCallback func([]int32)

	// Reconnect controls automatic reconnection behavior when the protocol
	// connection drops. Disabled by default.
	Reconnect ReconnectConfig
}

type DeviceInfo struct {
	ProductName     string
	Manufacturer    string
	SoftwareVersion string
}

type Metadata struct {
	Title       string
	Artist      string
	Album       string
	AlbumArtist string
	ArtworkURL  string
	Track       int
	Year        int
	Duration    int    // seconds
	Repeat      string // "off", "one", "all" (from controller state per spec#81)
	Shuffle     bool   // shuffle enabled (from controller state per spec#81)
}

type PlayerState struct {
	State      string // "idle", "playing", "paused"
	Volume     int
	Muted      bool
	Codec      string
	SampleRate int
	Channels   int
	BitDepth   int
	Connected  bool
}

type PlayerStats struct {
	Received    int64
	Played      int64
	Dropped     int64
	BufferDepth int // milliseconds
	SyncRTT     int64
	SyncQuality sendspinsync.Quality
}

// Player provides high-level audio playback from Sendspin servers.
// It composes a Receiver (connect/sync/decode/schedule) with an audio output backend.
type Player struct {
	config       PlayerConfig
	receiver     *Receiver
	output       output.Output
	state        PlayerState
	stateMu      stdsync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	capsResolved bool // probe runs once at first Connect; reconnects reuse the cached caps
}

func NewPlayer(config PlayerConfig) (*Player, error) {
	if config.Volume == 0 {
		config.Volume = 100
	}
	if config.BufferMs == 0 {
		config.BufferMs = 500
	}
	if config.Reconnect.Enabled {
		if config.Reconnect.InitialDelay <= 0 {
			config.Reconnect.InitialDelay = 500 * time.Millisecond
		}
		if config.Reconnect.MaxDelay <= 0 {
			config.Reconnect.MaxDelay = 30 * time.Second
		}
		if config.Reconnect.Multiplier <= 1.0 {
			config.Reconnect.Multiplier = 2.0
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Player{
		config: config,
		output: config.Output,
		ctx:    ctx,
		cancel: cancel,
		state: PlayerState{
			State:     "idle",
			Volume:    config.Volume,
			Muted:     false,
			Connected: false,
		},
	}, nil
}

func (p *Player) Connect() error {
	recv, err := p.buildReceiver(p.config.ServerAddr)
	if err != nil {
		return err
	}
	if err := recv.Connect(); err != nil {
		return err
	}

	p.stateMu.Lock()
	p.receiver = recv
	p.state.Connected = true
	p.stateMu.Unlock()

	p.notifyStateChange()

	go p.consumeAudio(recv)

	if p.config.Reconnect.Enabled {
		go p.runReconnectLoop(recv)
	}

	return nil
}

func (p *Player) buildReceiver(addr string) (*Receiver, error) {
	p.ensureCapsResolved()
	return NewReceiver(ReceiverConfig{
		ServerAddr:     addr,
		PlayerName:     p.config.PlayerName,
		BufferMs:       p.config.BufferMs,
		StaticDelayMs:  p.config.StaticDelayMs,
		PreferredCodec: p.config.PreferredCodec,
		BufferCapacity: p.config.BufferCapacity,
		MaxSampleRate:  p.config.MaxSampleRate,
		MaxBitDepth:    p.config.MaxBitDepth,
		ClientID:       p.config.ClientID,
		DeviceInfo:     p.config.DeviceInfo,
		DecoderFactory: p.config.DecoderFactory,
		OnMetadata:     p.config.OnMetadata,
		OnStreamStart:  p.onStreamStart,
		OnStreamEnd:    p.onStreamEnd,
		OnError:        p.config.OnError,
		OnCommand: func(cmd protocol.PlayerCommand) {
			switch cmd.Command {
			case "volume":
				p.SetVolume(cmd.Volume)
			case "mute":
				p.Mute(cmd.Mute)
			}
		},
	})
}

// ensureCapsResolved decides MaxSampleRate / MaxBitDepth on first call and
// caches the decision so subsequent reconnects reuse the same caps without
// re-probing miniaudio.
//
// Replace semantics: any explicit non-zero override on either field skips
// the probe entirely, so users who want to raise the cap above the device's
// reported ceiling can. Probe failures are logged and treated as "no cap" —
// we'd rather advertise too much (and let the device-stall path complain)
// than refuse to start when the malgo backend is unavailable (e.g. CI).
//
// When config.Output is non-nil, the caller has substituted their own output
// (test doubles, custom backends), and probing the malgo default device
// wouldn't tell us anything useful — skip in that case too.
func (p *Player) ensureCapsResolved() {
	if p.capsResolved {
		return
	}
	p.capsResolved = true

	if p.config.MaxSampleRate != 0 || p.config.MaxBitDepth != 0 {
		log.Printf("Output capability cap: %d Hz / %d-bit (source: config)",
			p.config.MaxSampleRate, p.config.MaxBitDepth)
		return
	}
	if p.config.Output != nil {
		return
	}

	rate, depth, err := output.QueryDeviceCapabilities(p.config.AudioDevice)
	if err != nil {
		log.Printf("Output capability probe failed (%v); advertising full format list", err)
		return
	}
	if rate == 0 && depth == 0 {
		log.Printf("Output capability probe returned no native formats; advertising full format list")
		return
	}
	p.config.MaxSampleRate = rate
	p.config.MaxBitDepth = depth
	log.Printf("Output capability cap: %d Hz / %d-bit (source: probe)", rate, depth)
}

// runReconnectLoop supervises the active receiver and rebuilds it with
// exponential backoff whenever its Done channel closes. Exits when the
// Player context is cancelled.
func (p *Player) runReconnectLoop(initial *Receiver) {
	current := initial
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-current.Done():
		}

		// Connection lost. Enter reconnecting state and back off.
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		p.stateMu.Lock()
		p.state.Connected = false
		p.state.State = "reconnecting"
		p.stateMu.Unlock()
		p.notifyStateChange()

		next, ok := p.reconnectWithBackoff()
		if !ok {
			return
		}
		current = next

		p.stateMu.Lock()
		p.receiver = current
		p.state.Connected = true
		p.stateMu.Unlock()

		p.notifyStateChange()

		go p.consumeAudio(current)
	}
}

func (p *Player) reconnectWithBackoff() (*Receiver, bool) {
	cfg := p.config.Reconnect
	delay := cfg.InitialDelay
	attempt := 0

	for {
		attempt++
		if cfg.MaxAttempts > 0 && attempt > cfg.MaxAttempts {
			p.notifyError(fmt.Errorf("reconnect: gave up after %d attempts", cfg.MaxAttempts))
			return nil, false
		}

		// Jittered sleep (±20%).
		jittered := jitter(delay, 0.2)
		log.Printf("Reconnect attempt %d in %v", attempt, jittered)
		select {
		case <-p.ctx.Done():
			return nil, false
		case <-time.After(jittered):
		}

		addr := p.config.ServerAddr
		if cfg.Rediscover != nil {
			discovered, err := cfg.Rediscover(p.ctx)
			if err != nil {
				log.Printf("Reconnect: rediscover failed: %v (using last known addr %s)", err, addr)
			} else if discovered != "" {
				addr = discovered
			}
		}

		recv, err := p.buildReceiver(addr)
		if err == nil {
			if err = recv.Connect(); err == nil {
				log.Printf("Reconnect: connected to %s on attempt %d", addr, attempt)
				return recv, true
			}
		}
		log.Printf("Reconnect attempt %d to %s failed: %v", attempt, addr, err)

		delay = time.Duration(float64(delay) * cfg.Multiplier)
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
		}
	}
}

func jitter(d time.Duration, frac float64) time.Duration {
	if d <= 0 {
		return d
	}
	delta := (rand.Float64()*2 - 1) * frac
	return time.Duration(float64(d) * (1 + delta))
}

func (p *Player) onStreamStart(format audio.Format) {
	p.stateMu.Lock()
	if p.output == nil {
		p.output = output.NewMalgo(p.config.AudioDevice)
	}
	o := p.output
	p.stateMu.Unlock()

	if o == nil {
		return
	}

	if err := o.Open(format.SampleRate, format.Channels, format.BitDepth); err != nil {
		p.notifyError(fmt.Errorf("failed to initialize output: %w", err))
		return
	}

	p.stateMu.Lock()
	vol := p.state.Volume
	mut := p.state.Muted
	p.state.Codec = format.Codec
	p.state.SampleRate = format.SampleRate
	p.state.Channels = format.Channels
	p.state.BitDepth = format.BitDepth
	p.state.State = "playing"
	p.stateMu.Unlock()

	o.SetVolume(vol)
	o.SetMuted(mut)
	p.notifyStateChange()
}

func (p *Player) onStreamEnd() {
	p.stateMu.Lock()
	p.state.State = "idle"
	p.stateMu.Unlock()
	p.notifyStateChange()
}

func (p *Player) consumeAudio(recv *Receiver) {
	for {
		select {
		case buf, ok := <-recv.Output():
			if !ok {
				return
			}

			if p.config.ProcessCallback != nil {
				p.config.ProcessCallback(buf.Samples)
			}

			if p.output != nil {
				if err := p.output.Write(buf.Samples); err != nil {
					p.notifyError(fmt.Errorf("playback error: %w", err))
				}
			}

		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Player) Play() error {
	p.stateMu.Lock()
	connected := p.state.Connected
	p.stateMu.Unlock()

	if !connected {
		return fmt.Errorf("not connected")
	}
	p.stateMu.Lock()
	p.state.State = "playing"
	p.stateMu.Unlock()
	p.notifyStateChange()
	return p.sendState()
}

func (p *Player) Pause() error {
	p.stateMu.Lock()
	if !p.state.Connected {
		p.stateMu.Unlock()
		return fmt.Errorf("not connected")
	}
	p.state.State = "paused"
	p.stateMu.Unlock()
	p.notifyStateChange()
	return p.sendState()
}

func (p *Player) Stop() error {
	p.stateMu.Lock()
	if !p.state.Connected {
		p.stateMu.Unlock()
		return fmt.Errorf("not connected")
	}
	p.state.State = "idle"
	p.stateMu.Unlock()
	p.notifyStateChange()
	return p.sendState()
}

// SetVolume sets the volume (0-100)
func (p *Player) SetVolume(volume int) error {
	if volume < 0 {
		volume = 0
	}
	if volume > 100 {
		volume = 100
	}
	p.stateMu.Lock()
	muted := p.state.Muted
	if !muted {
		p.state.Volume = volume
	}
	o := p.output
	r := p.receiver
	connected := p.state.Connected
	p.stateMu.Unlock()

	// While muted the volume change is ignored for state and output alike;
	// applying it to only one of them would leave the output gain diverging
	// from the volume the server displays (silent audio after unmute).
	if o != nil && !muted {
		o.SetVolume(volume)
	}

	if r != nil && connected {
		p.sendState()
	}

	p.notifyStateChange()
	return nil
}

func (p *Player) Mute(muted bool) error {
	p.stateMu.Lock()
	p.state.Muted = muted
	vol := p.state.Volume
	o := p.output
	r := p.receiver
	connected := p.state.Connected
	p.stateMu.Unlock()

	if o != nil {
		o.SetMuted(muted)
		if !muted {
			// Resync the output gain with the stored volume on unmute:
			// SetVolume drops volume changes that arrive while muted, so
			// the output may hold a stale value.
			o.SetVolume(vol)
		}
	}

	if r != nil && connected {
		p.sendState()
	}

	p.notifyStateChange()
	return nil
}

func (p *Player) Status() PlayerState {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.state
}

func (p *Player) Stats() PlayerStats {
	stats := PlayerStats{}

	p.stateMu.Lock()
	r := p.receiver
	p.stateMu.Unlock()

	if r != nil {
		rs := r.Stats()
		stats.Received = rs.Received
		stats.Played = rs.Played
		stats.Dropped = rs.Dropped
		stats.BufferDepth = rs.BufferDepth
		stats.SyncRTT = rs.SyncRTT
		stats.SyncQuality = rs.SyncQuality
	}

	return stats
}

func (p *Player) Close() error {
	p.cancel()

	p.stateMu.Lock()
	r := p.receiver
	o := p.output
	p.stateMu.Unlock()

	if r != nil {
		r.Close()
	}

	if o != nil {
		o.Close()
	}

	p.stateMu.Lock()
	p.state.Connected = false
	p.state.State = "idle"
	p.stateMu.Unlock()
	p.notifyStateChange()

	return nil
}

// SendCommand sends a controller command to the server (e.g., "play",
// "pause", "next", "previous"). This is how a player requests playback
// control — the server decides whether to act on it.
func (p *Player) SendCommand(command string) error {
	p.stateMu.Lock()
	r := p.receiver
	p.stateMu.Unlock()

	if r == nil || r.client == nil {
		return fmt.Errorf("not connected")
	}
	payload := map[string]interface{}{
		"controller": map[string]interface{}{
			"command": command,
		},
	}
	return r.client.Send("client/command", payload)

}

// FormatRequest describes a stream/request-format ask. Any zero-valued field is
// omitted, asking the server to keep the current value for it.
type FormatRequest struct {
	Codec      string // "pcm", "opus", "flac"
	Channels   int
	SampleRate int
	BitDepth   int
}

// RequestFormat asks the server to switch the player stream to a different
// format — for example dropping to a lower bitrate codec under network or CPU
// pressure. The server responds by starting a new stream in the chosen format.
// Returns an error if not connected.
func (p *Player) RequestFormat(req FormatRequest) error {
	p.stateMu.Lock()
	r := p.receiver
	p.stateMu.Unlock()

	if r == nil || r.client == nil {
		return fmt.Errorf("not connected")
	}
	return r.client.SendRequestFormat(protocol.RequestFormatPlayer{
		Codec:      req.Codec,
		Channels:   req.Channels,
		SampleRate: req.SampleRate,
		BitDepth:   req.BitDepth,
	})

}

// EnterExternalSource announces that this player is now driven by an external
// system and is not participating in Sendspin playback, by sending client/state
// with state "external_source". A conformant server moves the client to a solo
// stopped group and ends its active streams (stream/end); the embedder owns
// whatever local audio the external source produces. Call ExitExternalSource to
// rejoin normal playback.
func (p *Player) EnterExternalSource() error {
	p.stateMu.Lock()
	r := p.receiver
	p.stateMu.Unlock()

	if r == nil || r.client == nil {
		return fmt.Errorf("not connected")
	}
	if err := r.client.SendState(protocol.PlayerState{State: "external_source"}); err != nil {
		return err
	}
	p.stateMu.Lock()
	p.state.State = "external_source"
	p.stateMu.Unlock()
	p.notifyStateChange()
	return nil

}

// ExitExternalSource leaves external-source mode and rejoins normal Sendspin
// playback by re-sending the synchronized client/state. A conformant server
// returns the client to its previous group and resumes streaming.
func (p *Player) ExitExternalSource() error {
	p.stateMu.Lock()
	r := p.receiver
	p.stateMu.Unlock()

	if r == nil || r.client == nil {
		return fmt.Errorf("not connected")
	}
	if err := p.sendState(); err != nil {
		return err
	}
	p.stateMu.Lock()
	p.state.State = "idle"
	p.stateMu.Unlock()
	p.notifyStateChange()
	return nil

}

func (p *Player) sendState() error {
	p.stateMu.Lock()
	r := p.receiver
	s := p.state
	p.stateMu.Unlock()

	if r == nil || r.client == nil {
		return nil
	}
	return r.client.SendState(protocol.PlayerState{
		State:  "synchronized",
		Volume: s.Volume,
		Muted:  s.Muted,
	})
}

func (p *Player) notifyStateChange() {
	p.stateMu.Lock()
	s := p.state
	p.stateMu.Unlock()
	if p.config.OnStateChange != nil {
		p.config.OnStateChange(s)
	}
}

func (p *Player) notifyError(err error) {
	if p.config.OnError != nil {
		p.config.OnError(err)
	} else {
		log.Printf("Player error: %v", err)
	}
}
