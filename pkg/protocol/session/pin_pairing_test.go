// ABOUTME: Go-to-Go loopback tests for the PIN pairing flows — dynamic and
// ABOUTME: static, full round trip plus wrong-PIN and bad-commit failures.
package session

import "testing"

// pinPairingHarness runs a server-side and client-side PIN attempt against
// each other over an encrypted loopback keyed on the Sentinel PSK (PIN
// pairing starts Sentinel-keyed), driving each side in its own goroutine.
type pinResult struct {
	serverSess *ServerSession
	serverErr  error
	clientSess *ClientSession
	clientErr  error
}

func runPINPairing(t *testing.T, serverCfg PINPairingServerConfig, clientCfg PINPairingClientConfig, clientHello ClientHello) pinResult {
	t.Helper()
	serverConn, clientConn := loopback(t)

	res := make(chan pinResult, 1)
	srvOut := make(chan struct {
		s *ServerSession
		e error
	}, 1)

	go func() {
		sess, err := EstablishServer(serverConn, ServerConfig{
			ServerName:         "pin-server",
			PSKCategory:        PSKSentinel,
			InitialActivities:  []Activity{ActivityPairing},
			SelectedPairMethod: serverCfg.Method,
		})
		if err != nil {
			srvOut <- struct {
				s *ServerSession
				e error
			}{nil, err}
			return
		}
		after, err := sess.CompletePINPairing(serverCfg)
		srvOut <- struct {
			s *ServerSession
			e error
		}{after, err}
	}()

	clientSess, err := EstablishClient(clientConn, ClientConfig{Hello: clientHello, PSKCategory: PSKSentinel})
	var out pinResult
	if err != nil {
		out.clientErr = err
	} else {
		after, perr := clientSess.RunPINPairing(clientCfg)
		out.clientSess, out.clientErr = after, perr
	}
	srv := <-srvOut
	out.serverSess, out.serverErr = srv.s, srv.e
	res <- out
	return <-res
}

func pinClientHello(methods ...PairMethodDescriptor) ClientHello {
	h := testHello(false)
	h.SupportedPairMethods = methods
	return h
}

func TestPINPairing_DynamicFullRoundTrip(t *testing.T) {
	const pinLen = 6
	clientStore := NewMemoryPairingStore()
	serverStore := NewMemoryPairingStore()

	resultingHello := testHello(false)
	resultingHello.TrustLevel = TrustUser

	// The operator waits to see the PIN on the client's out-channel before
	// typing it into the server; model that with a channel so ProvidePIN
	// blocks until EmitPIN fires.
	pinCh := make(chan string, 1)
	res := runPINPairing(t,
		PINPairingServerConfig{
			Method:         PairMethodDynamicPIN,
			PairingCounter: 1,
			PINLength:      pinLen,
			ProvidePIN:     func() (string, error) { return <-pinCh, nil },
			Persist:        serverStore.PutRecord,
			Resulting:      ServerConfig{ServerName: "pin-server", InitialActivities: []Activity{ActivityPlayback}},
		},
		PINPairingClientConfig{
			Method:         PairMethodDynamicPIN,
			PairingCounter: 1,
			MinPINLength:   pinLen,
			EmitPIN:        func(p string) { pinCh <- p },
			Persist:        clientStore.PutRecord,
			ResultingHello: resultingHello,
		},
		pinClientHello(PairMethodDescriptor{Method: PairMethodDynamicPIN, MinPINLength: pinLen}),
	)

	if res.serverErr != nil {
		t.Fatalf("server: %v", res.serverErr)
	}
	if res.clientErr != nil {
		t.Fatalf("client: %v", res.clientErr)
	}
	assertPairedBothSides(t, res, serverStore, clientStore)
}

func TestPINPairing_StaticFullRoundTrip(t *testing.T) {
	const staticPIN = "13572468"
	clientStore := NewMemoryPairingStore()
	serverStore := NewMemoryPairingStore()

	resultingHello := testHello(false)
	resultingHello.TrustLevel = TrustUser

	res := runPINPairing(t,
		PINPairingServerConfig{
			Method:         PairMethodStaticPIN,
			PairingCounter: 1,
			ProvidePIN:     func() (string, error) { return staticPIN, nil },
			Persist:        serverStore.PutRecord,
			Resulting:      ServerConfig{ServerName: "pin-server", InitialActivities: []Activity{ActivityPlayback}},
		},
		PINPairingClientConfig{
			Method:         PairMethodStaticPIN,
			PairingCounter: 1,
			StaticPIN:      staticPIN,
			Persist:        clientStore.PutRecord,
			ResultingHello: resultingHello,
		},
		pinClientHello(PairMethodDescriptor{Method: PairMethodStaticPIN}),
	)

	if res.serverErr != nil {
		t.Fatalf("server: %v", res.serverErr)
	}
	if res.clientErr != nil {
		t.Fatalf("client: %v", res.clientErr)
	}
	assertPairedBothSides(t, res, serverStore, clientStore)
}

func TestPINPairing_WrongStaticPINAborts(t *testing.T) {
	res := runPINPairing(t,
		PINPairingServerConfig{
			Method:         PairMethodStaticPIN,
			PairingCounter: 1,
			ProvidePIN:     func() (string, error) { return "11111111", nil }, // operator types wrong
			Persist:        NewMemoryPairingStore().PutRecord,
			Resulting:      ServerConfig{ServerName: "pin-server", InitialActivities: []Activity{ActivityPlayback}},
		},
		PINPairingClientConfig{
			Method:         PairMethodStaticPIN,
			PairingCounter: 1,
			StaticPIN:      "99999999", // device's real PIN
			Persist:        NewMemoryPairingStore().PutRecord,
			ResultingHello: testHello(false),
		},
		pinClientHello(PairMethodDescriptor{Method: PairMethodStaticPIN}),
	)

	// The client verifies server_kc first and fails, aborting pin_mismatch;
	// the server sees the abort.
	assertPairAbort(t, res.clientErr, AbortPINMismatch)
	if res.serverErr == nil {
		t.Error("server completed pairing with a mismatched PIN")
	}
}

func TestPINPairing_PINLengthUnacceptableAborts(t *testing.T) {
	res := runPINPairing(t,
		PINPairingServerConfig{
			Method:         PairMethodDynamicPIN,
			PairingCounter: 1,
			PINLength:      4, // below the client's floor
			ProvidePIN:     func() (string, error) { return "0000", nil },
			Persist:        NewMemoryPairingStore().PutRecord,
			Resulting:      ServerConfig{ServerName: "pin-server", InitialActivities: []Activity{ActivityPlayback}},
		},
		PINPairingClientConfig{
			Method:         PairMethodDynamicPIN,
			PairingCounter: 1,
			MinPINLength:   6, // requires at least 6
			Persist:        NewMemoryPairingStore().PutRecord,
			ResultingHello: testHello(false),
		},
		pinClientHello(PairMethodDescriptor{Method: PairMethodDynamicPIN, MinPINLength: 6}),
	)
	assertPairAbort(t, res.clientErr, AbortPINLengthUnacceptable)
}

func assertPairedBothSides(t *testing.T, res pinResult, serverStore, clientStore *MemoryPairingStore) {
	t.Helper()
	if res.serverSess == nil || res.clientSess == nil {
		t.Fatal("pairing produced no post-session")
	}
	if res.serverSess.Hello.TrustLevel != TrustUser {
		t.Errorf("server post-pairing trust = %q, want user", res.serverSess.Hello.TrustLevel)
	}
	sr := serverStore.Records()
	cr := clientStore.Records()
	if len(sr) != 1 || len(cr) != 1 {
		t.Fatalf("records: server=%d client=%d", len(sr), len(cr))
	}
	if sr[0].PSK != cr[0].PSK {
		t.Error("server and client persisted different PSKs")
	}
	// The re-keyed channel carries traffic.
	if err := res.clientSess.SendGoodbye(GoodbyeShutdown); err != nil {
		t.Fatal(err)
	}
	if _, _, err := res.serverSess.Conn.ReadMessage(); err != nil {
		t.Fatalf("post-pairing read: %v", err)
	}
}

func assertPairAbort(t *testing.T, err error, reason string) {
	t.Helper()
	abort, ok := err.(*PairAbortError)
	if !ok {
		t.Fatalf("error = %v, want *PairAbortError(%s)", err, reason)
	}
	if abort.Reason != reason {
		t.Errorf("abort reason = %q, want %q", abort.Reason, reason)
	}
}

// Ensures a full PIN run yields the same ISK-derived record on both sides for
// a range of lengths (guards the derive/clamp/sid plumbing).
func TestPINPairing_DynamicVariousLengths(t *testing.T) {
	for _, pinLen := range []int{4, 8, 12} {
		var emittedLen int
		serverStore := NewMemoryPairingStore()
		clientStore := NewMemoryPairingStore()
		resultingHello := testHello(false)
		resultingHello.TrustLevel = TrustUser
		pinCh := make(chan string, 1)

		res := runPINPairing(t,
			PINPairingServerConfig{
				Method: PairMethodDynamicPIN, PairingCounter: 1, PINLength: pinLen,
				ProvidePIN: func() (string, error) { return <-pinCh, nil },
				Persist:    serverStore.PutRecord,
				Resulting:  ServerConfig{ServerName: "s", InitialActivities: []Activity{ActivityPlayback}},
			},
			PINPairingClientConfig{
				Method: PairMethodDynamicPIN, PairingCounter: 1, MinPINLength: 4,
				EmitPIN: func(p string) { emittedLen = len(p); pinCh <- p },
				Persist: clientStore.PutRecord, ResultingHello: resultingHello,
			},
			pinClientHello(PairMethodDescriptor{Method: PairMethodDynamicPIN, MinPINLength: 4}),
		)
		if res.serverErr != nil || res.clientErr != nil {
			t.Fatalf("len %d: server=%v client=%v", pinLen, res.serverErr, res.clientErr)
		}
		if emittedLen != pinLen {
			t.Errorf("len %d: emitted %d digits", pinLen, emittedLen)
		}
		if serverStore.Records()[0].PSK != clientStore.Records()[0].PSK {
			t.Errorf("len %d: PSK mismatch", pinLen)
		}
	}
}
