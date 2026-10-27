package test

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-openvpn/proto"
)

const (
	expiredSessionRenegotiationInterval = 2 * time.Second
	expiredSessionHandWindow            = 2 * time.Second
	expiredSessionServerPingRestart     = 3 * time.Second
	expiredSessionPushedPingInterval    = time.Second
	expiredSessionPushedPingRestart     = 3 * time.Second
)

type offlineExpiryReconnectOptions struct {
	clientPingRestartDisabled bool
	pushKeepalive             bool
}

// OpenVPN's default --reneg-sec is 3600s. While the network is down across
// that point, tls_process starts a soft reset whose new key_state must
// negotiate within --hand-window. tls_multi_process then treats TM_ACTIVE
// S_ERROR as a session reinit (new HARD_RESET / session id). This test
// compresses that 1h expiry into a few seconds: blackhole the link past
// renegotiation plus the handshake window, let the server forget the client
// via ping-restart, restore the link, and require the tunnel to carry data
// again. Client ping-restart is disabled so recovery cannot hide behind
// keepalive; it has to come from the failed soft reset.
func TestClientReconnectsAfterOfflineRenegotiationExpiry(t *testing.T) {
	t.Parallel()
	runOfflineExpiryReconnect(t, offlineExpiryReconnectOptions{clientPingRestartDisabled: true})
}

// Production servers typically push keepalive 10 120. That arms client
// ping-restart independently of reneg-sec. An in-flight soft reset does
// not suppress ping-restart, and outgoing control retransmits only stamp
// lastOutbound, so a blackhole longer than ping-restart recovers even
// without the failed-soft-reset restart. This variant uses a scaled-down
// push (ping 1 / ping-restart 3) to lock that path in.
func TestClientReconnectsAfterOfflineOutageWithPushedKeepalive(t *testing.T) {
	t.Parallel()
	runOfflineExpiryReconnect(t, offlineExpiryReconnectOptions{pushKeepalive: true})
}

func runOfflineExpiryReconnect(t *testing.T, options offlineExpiryReconnectOptions) {
	t.Helper()
	listenAddress := reserveListenAddressForProtocol(t, "udp")

	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelServerContext()
	serverOptions := ServerOptions{
		Context:   serverContext,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "udp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Timing: ServerTimingOptions{
			RenegotiationDisabled: true,
			PingRestart:           expiredSessionServerPingRestart,
		},
		Tunnel: ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
			Topology:     "subnet",
		},
	}
	if options.pushKeepalive {
		serverOptions.Push = ServerPushOptions{
			PingInterval:        expiredSessionPushedPingInterval,
			PingIntervalEnabled: true,
			PingRestart:         expiredSessionPushedPingRestart,
			PingRestartEnabled:  true,
		}
	}
	server, err := NewServer(serverOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}

	relayAddress, relay := startDropRelay(t, listenAddress)

	eventCh := make(chan TunnelConfigurationEvent, 8)
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, relayAddress, "udp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: ClientPullOptions{Enabled: true},
		Timing: ClientTimingOptions{
			RenegotiationInterval: expiredSessionRenegotiationInterval,
			HandWindow:            expiredSessionHandWindow,
			PingRestartDisabled:   options.clientPingRestartDisabled,
		},
		OnTunnelConfiguration: func(event TunnelConfigurationEvent) error {
			eventCh <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}

	firstEvent := waitForSupervisorTunnelConfigurationEvent(t, eventCh, 10*time.Second)
	if firstEvent.Reason != TunnelConfigurationEventInitial {
		t.Fatalf("unexpected first event reason: %s", firstEvent.Reason)
	}
	if options.pushKeepalive {
		configuration := client.TunnelConfiguration()
		if configuration.PingRestart != expiredSessionPushedPingRestart {
			t.Fatalf("expected pushed ping-restart %v, got %v", expiredSessionPushedPingRestart, configuration.PingRestart)
		}
	}
	err = tryEchoClientThroughServer(client, server, []byte("before-expiry"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	relay.resetHardResetCount()
	relay.setDrop(true)
	time.Sleep(expiredSessionRenegotiationInterval + expiredSessionHandWindow + expiredSessionServerPingRestart + time.Second)
	relay.setDrop(false)

	reconnected := waitForSupervisorTunnelConfigurationEvent(t, eventCh, 25*time.Second)
	if reconnected.Reason != TunnelConfigurationEventInitial {
		t.Fatalf("expected a new HARD_RESET session after the expired renegotiation, got %s", reconnected.Reason)
	}
	if relay.clientHardResets() == 0 {
		t.Fatal("the client never sent P_CONTROL_HARD_RESET after the link came back; it stayed on the dead session")
	}
	err = tryEchoClientThroughServer(client, server, []byte("after-expiry"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
}

type dropRelay struct {
	drop           atomic.Bool
	hardResetCount atomic.Uint32
}

func (r *dropRelay) setDrop(drop bool) {
	r.drop.Store(drop)
}

func (r *dropRelay) resetHardResetCount() {
	r.hardResetCount.Store(0)
}

func (r *dropRelay) clientHardResets() uint32 {
	return r.hardResetCount.Load()
}

func (r *dropRelay) noteOutgoing(rawPacket []byte) {
	if len(rawPacket) == 0 || r.drop.Load() {
		return
	}
	switch proto.Opcode(rawPacket[0] >> 3) {
	case proto.OpcodeControlHardResetClientV1, proto.OpcodeControlHardResetClientV2, proto.OpcodeControlHardResetClientV3:
		r.hardResetCount.Add(1)
	}
}

func startDropRelay(t *testing.T, serverAddress string) (string, *dropRelay) {
	t.Helper()
	clientFacing, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverUDP, err := net.ResolveUDPAddr("udp", serverAddress)
	if err != nil {
		_ = clientFacing.Close()
		t.Fatal(err)
	}
	serverFacing, err := net.DialUDP("udp", nil, serverUDP)
	if err != nil {
		_ = clientFacing.Close()
		t.Fatal(err)
	}
	relay := &dropRelay{}
	var clientAddress atomic.Value
	t.Cleanup(func() {
		_ = clientFacing.Close()
		_ = serverFacing.Close()
	})
	go func() {
		buffer := make([]byte, 65535)
		for {
			readCount, address, readErr := clientFacing.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			clientAddress.Store(address)
			packet := append([]byte(nil), buffer[:readCount]...)
			relay.noteOutgoing(packet)
			if relay.drop.Load() {
				continue
			}
			_, _ = serverFacing.Write(packet)
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			readCount, readErr := serverFacing.Read(buffer)
			if readErr != nil {
				return
			}
			if relay.drop.Load() {
				continue
			}
			storedAddress := clientAddress.Load()
			if storedAddress == nil {
				continue
			}
			address, _ := storedAddress.(net.Addr)
			if address == nil {
				continue
			}
			_, _ = clientFacing.WriteTo(buffer[:readCount], address)
		}
	}()
	return clientFacing.LocalAddr().String(), relay
}
