/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/poly1305"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tai64n"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// countingEndpoint is an endpoint for countingBind. It is comparable, so a bind
// can route on identity the way a real Bind routes on an address.
type countingEndpoint uint16

func (e countingEndpoint) ClearSrc()           {}
func (e countingEndpoint) SrcToString() string { return "" }
func (e countingEndpoint) DstToString() string { return fmt.Sprintf("127.0.0.1:%d", uint16(e)) }
func (e countingEndpoint) DstToBytes() []byte  { return []byte{byte(e)} }
func (e countingEndpoint) DstIP() netip.Addr   { return netip.AddrFrom4([4]byte{127, 0, 0, 1}) }
func (e countingEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type bindCounters struct {
	initiations atomic.Int64
	responses   atomic.Int64
	transport   atomic.Int64
}

// countingBind is a loopback Bind that counts what each side sends, so a test
// can assert that a rejected input produced no reply.
type countingBind struct {
	rx, tx     *chan []byte
	target     countingEndpoint
	openPort   uint16
	counters   bindCounters
	mu         sync.Mutex
	closeChans chan struct{}
}

var _ conn.Bind = (*countingBind)(nil)

func newCountingBinds() ([2]*countingBind, func()) {
	arx := make(chan []byte, 8192)
	brx := make(chan []byte, 8192)
	binds := [2]*countingBind{
		{rx: &arx, tx: &brx, target: 1, openPort: 2},
		{rx: &brx, tx: &arx, target: 2, openPort: 1},
	}
	cleanup := func() {
		for _, b := range binds {
			b.Close()
		}
	}
	return binds, cleanup
}

func (b *countingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	b.closeChans = make(chan struct{})
	closed := b.closeChans
	b.mu.Unlock()
	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-closed:
			return 0, net.ErrClosed
		case rx := <-*b.rx:
			sizes[0] = copy(bufs[0], rx)
			eps[0] = b.target
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{recv}, b.openPort, nil
}

func (b *countingBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closeChans != nil {
		select {
		case <-b.closeChans:
		default:
			close(b.closeChans)
		}
	}
	return nil
}

func (b *countingBind) SetMark(mark uint32) error { return nil }

func (b *countingBind) BatchSize() int { return 1 }

func (b *countingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return countingEndpoint(addr.Port()), nil
}

func (b *countingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if ep != b.target {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	closed := b.closeChans
	b.mu.Unlock()
	for _, buf := range bufs {
		if len(buf) >= 4 {
			switch binary.LittleEndian.Uint32(buf[:4]) {
			case MessageInitiationType:
				b.counters.initiations.Add(1)
			case MessageResponseType:
				b.counters.responses.Add(1)
			case MessageTransportType:
				b.counters.transport.Add(1)
			}
		}
		bc := make([]byte, len(buf))
		copy(bc, buf)
		select {
		case <-closed:
			return net.ErrClosed
		case *b.tx <- bc:
		}
	}
	return nil
}

// genCountingTestPair mirrors genTestPair, but on a Bind that records traffic
// per direction.
func genCountingTestPair(tb testing.TB) (pair testPair, binds [2]*countingBind) {
	tb.Helper()
	cfg, endpointCfg := genConfigs(tb)
	var cleanup func()
	binds, cleanup = newCountingBinds()
	tb.Cleanup(cleanup)
	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		p.dev = NewDevice(p.tun.TUN(), binds[i], NewLogger(LogLevelError, fmt.Sprintf("dev%d: ", i)))
		if err := p.dev.IpcSet(cfg[i]); err != nil {
			tb.Fatalf("failed to configure device %d: %v", i, err)
		}
		if err := p.dev.Up(); err != nil {
			tb.Fatalf("failed to bring up device %d: %v", i, err)
		}
		endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], p.dev.net.port)
	}
	for i := range pair {
		if err := pair[i].dev.IpcSet(endpointCfg[i]); err != nil {
			tb.Fatalf("failed to configure device endpoint %d: %v", i, err)
		}
		tb.Cleanup(pair[i].dev.Close)
	}
	return
}

// onlyPeer returns the sole peer of a single-peer test device.
func onlyPeer(tb testing.TB, dev *Device) *Peer {
	tb.Helper()
	dev.peers.RLock()
	defer dev.peers.RUnlock()
	if len(dev.peers.keyMap) != 1 {
		tb.Fatalf("expected exactly one peer, got %d", len(dev.peers.keyMap))
	}
	for _, peer := range dev.peers.keyMap {
		return peer
	}
	return nil
}

// forgetSentTimestamp makes the peer behave like an implementation that has no
// monotonic sender-side timestamping: the next initiation is stamped with the
// wall clock as it is now, even if that is behind what the peer last sent.
func forgetSentTimestamp(peer *Peer) {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentTimestamp = tai64n.Timestamp{}
	peer.handshake.mutex.Unlock()
}

// handshakeSnapshot reads the replay-relevant handshake state under its lock.
func handshakeSnapshot(peer *Peer) (last tai64n.Timestamp, rollback bool) {
	peer.handshake.mutex.RLock()
	defer peer.handshake.mutex.RUnlock()
	return peer.handshake.lastTimestamp, peer.handshake.clockRollback
}

// pretendPeerClockWasAhead models the moment before a clock step: it is as if
// the initiator's clock had once been far ahead, and the responder accepted an
// initiation stamped at that time. The responder's high-water mark is set to a
// wall clock reading "ahead" into the future, so every timestamp the initiator
// produces afterwards with the real wall clock is necessarily behind it. That is
// exactly the state the responder's replay check reads, and exactly what a real
// deployment reaches after its clock steps back.
func pretendPeerClockWasAhead(t *testing.T, responder *Peer, ahead time.Duration) tai64n.Timestamp {
	t.Helper()
	mark := tai64n.FromTime(time.Now().Add(ahead))
	responder.handshake.mutex.Lock()
	responder.handshake.lastTimestamp = mark
	responder.handshake.clockRollback = false
	responder.handshake.mutex.Unlock()
	return mark
}

// waitOutHandshakeRate keeps consecutive initiations far enough apart that the
// peer's 20-per-second flood limiter does not stand in for the replay check.
func waitOutHandshakeRate() {
	time.Sleep(HandshakeInitationRate + 30*time.Millisecond)
}

// waitForResponses polls until the response counter reaches want, so a test
// does not have to guess how long the handshake worker will take.
func waitForResponses(t *testing.T, counters *bindCounters, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for counters.responses.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for response %d", want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestInitiationTimestampSurvivesClockRollback covers the sender-side half: if
// the wall clock steps backwards, two initiations created one after the other
// must still carry strictly increasing timestamps, so a peer that keeps the old
// high-water mark does not reject them as replays.
func TestInitiationTimestampSurvivesClockRollback(t *testing.T) {
	dev1, dev2 := randDevice(t), randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	peerOnDev2, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peerOnDev1, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peerOnDev2.Start()
	peerOnDev1.Start()

	// The responder's high-water mark is far in the future: this is the state
	// reached when the initiator's clock was ahead and the responder accepted
	// an initiation stamped then. Every stamp the initiator sends now via the
	// real wall clock is behind that mark, which is exactly the rollback case.
	mark := pretendPeerClockWasAhead(t, peerOnDev2, 300*time.Second)

	msg, err := dev1.CreateMessageInitiation(peerOnDev1)
	assertNil(t, err)
	if peer := dev2.ConsumeMessageInitiation(msg); peer == nil {
		t.Fatal("initiation with a timestamp behind the high-water mark was rejected despite the sender-side fix")
	}
	mark2, rollback := handshakeSnapshot(peerOnDev2)
	if mark2 != mark {
		t.Fatalf("responder high-water mark moved: %v -> %v", mark, mark2)
	}
	if !rollback {
		t.Fatal("responder did not record that it accepted a behind-the-mark initiation")
	}
}

// TestInitiationStampsAreStrictlyIncreasing checks the sender-side invariant in
// isolation, without a responder: consecutive initiations from one peer always
// carry a strictly greater timestamp, even though the wall clock may produce the
// same whitened value twice in a row.
func TestInitiationStampsAreStrictlyIncreasing(t *testing.T) {
	dev1, dev2 := randDevice(t), randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	peerOnDev1, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peerOnDev1.Start()

	var previous tai64n.Timestamp
	for i := 0; i < 32; i++ {
		msg, err := dev1.CreateMessageInitiation(peerOnDev1)
		assertNil(t, err)
		var stamp tai64n.Timestamp
		peerOnDev1.handshake.mutex.RLock()
		stamp = peerOnDev1.handshake.lastSentTimestamp
		peerOnDev1.handshake.mutex.RUnlock()
		if i > 0 && !stamp.After(previous) {
			t.Fatalf("initiation %d stamp %v is not after the previous %v", i, stamp, previous)
		}
		previous = stamp
		_ = msg
	}
}

// TestInitiationFromPeerWithoutSenderFixAccepted covers a peer that does not
// extrapolate: it stamps the stepped-back wall clock verbatim. The initiation is
// authentic and has never been consumed, so the responder must accept it and
// answer, rather than silently dropping it as a replay until the clock catches
// up.
func TestInitiationFromPeerWithoutSenderFixAccepted(t *testing.T) {
	dev1, dev2 := randDevice(t), randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	peerOnDev2, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peerOnDev1, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peerOnDev2.Start()
	peerOnDev1.Start()

	// The responder's mark sits in what is now the initiator's future: from the
	// initiator's point of view its clock was stepped back.
	mark := pretendPeerClockWasAhead(t, peerOnDev2, 300*time.Second)

	// A peer without the sender-side fix stamps the passed wall clock verbatim.
	forgetSentTimestamp(peerOnDev1)
	msg, err := dev1.CreateMessageInitiation(peerOnDev1)
	assertNil(t, err)

	peer := dev2.ConsumeMessageInitiation(msg)
	if peer == nil {
		t.Fatal("authentic initiation stamped behind the high-water mark was dropped as a replay")
	}
	mark2, rollback := handshakeSnapshot(peerOnDev2)
	if !rollback {
		t.Fatal("responder did not record that it accepted an initiation from a clock that stepped back")
	}
	// The high-water mark must not be lowered: it is what identifies later
	// replays and what tells us when the peer's clock has caught up again.
	if mark2 != mark {
		t.Fatalf("responder lowered its high-water mark: %v -> %v", mark, mark2)
	}

	// The tunnel is usable: the responder derived a response for this
	// initiation, so the sender can complete the handshake.
	if peer.handshake.state != handshakeInitiationConsumed {
		t.Fatalf("handshake state = %v, want %v", peer.handshake.state, handshakeInitiationConsumed)
	}
	// And the responder answered: CreateMessageResponse succeeds only for a
	// consumed initiation.
	if _, err := dev2.CreateMessageResponse(peer); err != nil {
		t.Fatalf("responder failed to create a response: %v", err)
	}
}

// TestInitiationReplayRejectedAfterClockRollback pins the other half of the
// contract: the acceptance above is for initiations that were never seen. A
// byte-for-byte replay of an initiation that was already consumed is still
// dropped, even when the timestamp looks acceptable.
func TestInitiationReplayRejectedAfterClockRollback(t *testing.T) {
	dev1, dev2 := randDevice(t), randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	peerOnDev2, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peerOnDev1, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peerOnDev2.Start()
	peerOnDev1.Start()

	pretendPeerClockWasAhead(t, peerOnDev2, 300*time.Second)

	// An initiation behind the mark is accepted once...
	forgetSentTimestamp(peerOnDev1)
	msg, err := dev1.CreateMessageInitiation(peerOnDev1)
	assertNil(t, err)
	if peer := dev2.ConsumeMessageInitiation(msg); peer == nil {
		t.Fatal("authentic initiation behind the high-water mark was rejected")
	}
	waitOutHandshakeRate()

	// ...but replaying it is not.
	if peer := dev2.ConsumeMessageInitiation(msg); peer != nil {
		t.Fatal("a replayed initiation was accepted")
	}
}

// TestInitiationReplayRejectedAfterHandshakeReset makes sure the replay record
// is not lost when the handshake state is torn down (peer stop/start, private
// key change): a captured initiation must not become usable again.
func TestInitiationReplayRejectedAfterHandshakeReset(t *testing.T) {
	dev1, dev2 := randDevice(t), randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	peerOnDev2, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peerOnDev1, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peerOnDev2.Start()
	peerOnDev1.Start()

	msg, err := dev1.CreateMessageInitiation(peerOnDev1)
	assertNil(t, err)
	if peer := dev2.ConsumeMessageInitiation(msg); peer == nil {
		t.Fatal("first initiation was not accepted")
	}

	// Simulate the responder's handshake state being reset.
	peerOnDev2.handshake.mutex.Lock()
	peerOnDev2.handshake.Clear()
	peerOnDev2.handshake.mutex.Unlock()
	waitOutHandshakeRate()

	if peer := dev2.ConsumeMessageInitiation(msg); peer != nil {
		t.Fatal("a replayed initiation was accepted after the handshake state was reset")
	}
}

// TestUnauthenticatedInitiationGetsNoReply checks that an input which fails
// authentication produces no response on the wire, and does not move the replay
// state. The packet is given a valid mac1 so that it reaches the deep check; it
// is the authenticated ciphertext that is wrong.
func TestUnauthenticatedInitiationGetsNoReply(t *testing.T) {
	pair, _ := genCountingTestPair(t)
	pair.Send(t, Ping, nil)

	initiator := onlyPeer(t, pair[1].dev)
	responder := onlyPeer(t, pair[0].dev)

	msg, err := pair[1].dev.CreateMessageInitiation(initiator)
	assertNil(t, err)
	packet := make([]byte, MessageInitiationSize)
	if err := msg.marshal(packet); err != nil {
		t.Fatal(err)
	}
	// Valid mac1, invalid payload: flip a byte inside the encrypted timestamp.
	packet[8+NoisePublicKeySize+NoisePublicKeySize+poly1305.TagSize] ^= 0xff
	initiator.cookieGenerator.AddMacs(packet)

	baseline, _ := handshakeSnapshot(responder)

	counters := &pair[0].dev.net.bind.(*countingBind).counters
	responsesBefore := counters.responses.Load()

	buf := pair[0].dev.GetMessageBuffer()
	copy(buf[:], packet)
	pair[0].dev.queue.handshake.c <- QueueHandshakeElement{
		msgType:  MessageInitiationType,
		packet:   buf[:len(packet)],
		endpoint: countingEndpoint(pair[0].dev.net.bind.(*countingBind).target),
		buffer:   buf,
	}
	waitOutHandshakeRate()

	if got := counters.responses.Load(); got != responsesBefore {
		t.Fatalf("responder sent %d response(s) to an input that failed authentication", got-responsesBefore)
	}
	after, rollback := handshakeSnapshot(responder)
	if after != baseline || rollback {
		t.Fatal("responder changed its replay state for an input that failed authentication")
	}
}

// forceNewHandshake makes the next packet need a fresh handshake, and models a
// peer that does not extrapolate its timestamp (it stamps the wall clock
// verbatim, now behind the responder's mark set by pretendPeerClockWasAhead).
func forceNewHandshake(t *testing.T, initiator *Peer) {
	t.Helper()
	// Let the responder's flood limiter (one initiation per 20 ms) expire, so
	// the next initiation is judged by the replay/timestamp rules rather than
	// dropped as a burst.
	waitOutHandshakeRate()
	initiator.ExpireCurrentKeypairs()
	// ExpireCurrentKeypairs resets the send throttle; forget the timestamp after
	// it so nothing re-seeds it.
	forgetSentTimestamp(initiator)
}

// TestTunnelRecoversFromClockRollback is the end-to-end case from the field: a
// session is up, the initiator's clock steps backwards, and the next handshake
// must still complete so the tunnel keeps carrying traffic.
func TestTunnelRecoversFromClockRollback(t *testing.T) {
	pair, _ := genCountingTestPair(t)

	// Establish a session in the forward direction (device 1 initiates).
	pair.Send(t, Ping, nil)

	initiator := onlyPeer(t, pair[1].dev)
	responder := onlyPeer(t, pair[0].dev)

	// The responder's mark for us is 300 s in its future: our clock is behind.
	pretendPeerClockWasAhead(t, responder, 300*time.Second)
	forceNewHandshake(t, initiator)

	// Traffic must still flow. Before the fix the responder dropped every
	// initiation from the stepped-back clock, so this timed out.
	pair.Send(t, Ping, nil)

	_, rollback := handshakeSnapshot(responder)
	if !rollback {
		t.Fatal("responder never observed the clock rollback; the recovery path was not exercised")
	}
	if got := initiator.timers.handshakeAttempts.Load(); got != 0 {
		t.Fatalf("initiator handshake attempts = %d, want 0 after a completed handshake", got)
	}
}

// TestTunnelRecoversWithRetriesExhausted covers the tail of the failure: the
// initiator had already burned through its retry budget, gave up, and flushed
// the queued packets. New traffic must still bring the tunnel back rather than
// leaving it silently dead.
func TestTunnelRecoversWithRetriesExhausted(t *testing.T) {
	pair, _ := genCountingTestPair(t)
	pair.Send(t, Ping, nil)

	initiator := onlyPeer(t, pair[1].dev)
	responder := onlyPeer(t, pair[0].dev)

	// Reproduce the give-up: attempts past the limit, then the timeout handler
	// flushes the staged queue.
	waitOutHandshakeRate()
	initiator.timers.handshakeAttempts.Store(MaxTimerHandshakes + 1)
	expiredRetransmitHandshake(initiator)
	if got := len(initiator.queue.staged); got != 0 {
		t.Fatalf("staged queue not flushed on give-up: %d", got)
	}

	pretendPeerClockWasAhead(t, responder, 300*time.Second)
	forceNewHandshake(t, initiator)

	// New traffic must restart the handshake rather than staying dark.
	pair.Send(t, Ping, nil)

	if got := initiator.timers.handshakeAttempts.Load(); got != 0 {
		t.Fatalf("initiator handshake attempts = %d, want 0 after recovery", got)
	}
	_, rollback := handshakeSnapshot(responder)
	if !rollback {
		t.Fatal("responder never observed the clock rollback; the recovery path was not exercised")
	}
}

// TestInitiationReplayAfterRecoveryRejected is the wire-level replay check: once
// a session has been re-established after a rollback, replaying the initiation
// that re-established it must not produce a second response.
func TestInitiationReplayAfterRecoveryRejected(t *testing.T) {
	pair, _ := genCountingTestPair(t)
	pair.Send(t, Ping, nil)

	initiator := onlyPeer(t, pair[1].dev)
	responder := onlyPeer(t, pair[0].dev)
	pretendPeerClockWasAhead(t, responder, 300*time.Second)
	forgetSentTimestamp(initiator)

	msg, err := pair[1].dev.CreateMessageInitiation(initiator)
	assertNil(t, err)
	packet := make([]byte, MessageInitiationSize)
	if err := msg.marshal(packet); err != nil {
		t.Fatal(err)
	}
	initiator.cookieGenerator.AddMacs(packet)

	counters := &pair[0].dev.net.bind.(*countingBind).counters
	ep := countingEndpoint(pair[0].dev.net.bind.(*countingBind).target)

	inject := func() {
		buf := pair[0].dev.GetMessageBuffer()
		copy(buf[:], packet)
		pair[0].dev.queue.handshake.c <- QueueHandshakeElement{
			msgType:  MessageInitiationType,
			packet:   buf[:len(packet)],
			endpoint: ep,
			buffer:   buf,
		}
	}

	// A response already went out establishing the session, so compare against
	// the count after the first delivery of this particular initiation.
	waitOutHandshakeRate()
	before := counters.responses.Load()
	inject()
	waitForResponses(t, counters, before+1)
	afterFirst := counters.responses.Load()
	if afterFirst != before+1 {
		t.Fatalf("first delivery produced %d response(s), want 1", afterFirst-before)
	}

	waitOutHandshakeRate()
	inject()
	waitOutHandshakeRate()
	if got := counters.responses.Load(); got != afterFirst {
		t.Fatalf("replaying an already-answered initiation produced %d extra response(s)", got-afterFirst)
	}
}
