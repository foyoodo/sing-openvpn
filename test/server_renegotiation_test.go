package test

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-openvpn/proto"
)

type observedAuthCredentials struct {
	username string
	password string
}

func TestTLSServerInitiatedRenegotiationKeepsDataFlowing(t *testing.T) {
	t.Parallel()
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	credentialEvents := make(chan observedAuthCredentials, 8)

	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancelServerContext()
	renegotiationInterval := 2 * time.Second
	server, err := NewServer(ServerOptions{
		Context:   serverContext,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "udp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Authentication: ServerAuthenticationOptions{Authenticator: func(_ context.Context, username string, password string) error {
			select {
			case credentialEvents <- observedAuthCredentials{username: username, password: password}:
			default:
			}
			if username == "test-user" && password == "test-password" {
				return nil
			}
			return ErrAuthenticationFailed
		}},
		Timing: ServerTimingOptions{RenegotiationInterval: renegotiationInterval},
		Tunnel: ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
			Topology:     "subnet",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}

	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "udp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Authentication: ClientAuthenticationOptions{Username: "test-user", Password: "test-password"},
		Pull:           ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 10*time.Second)
	waitForObservedCredentials(t, credentialEvents, "test-user", "test-password", 10*time.Second)

	err = tryEchoClientThroughServer(client, server, []byte("pre-reneg"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	driveEchoUntilObservedCredentials(t, client, server, credentialEvents, "test-user", "test-password", 60*time.Second)
	err = tryEchoClientThroughServer(client, server, []byte("post-reneg"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
}

func driveEchoUntilObservedCredentials(
	t *testing.T,
	client *Client,
	server *Server,
	credentialEvents <-chan observedAuthCredentials,
	expectedUsername string,
	expectedPassword string,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case credentials := <-credentialEvents:
			if credentials.username == expectedUsername && credentials.password == expectedPassword {
				return
			}
		default:
		}
		err := tryEchoClientThroughServer(client, server, []byte("drive-reneg"), 2*time.Second)
		if err != nil {
			time.Sleep(interopPollInterval)
			continue
		}
	}
	t.Fatalf("timed out waiting for observed credentials username=%q password=%q", expectedUsername, expectedPassword)
}

func waitForObservedCredentials(t *testing.T, credentialEvents <-chan observedAuthCredentials, expectedUsername string, expectedPassword string, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case credentials := <-credentialEvents:
			if credentials.username == expectedUsername && credentials.password == expectedPassword {
				return
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for observed credentials username=%q password=%q", expectedUsername, expectedPassword)
		}
	}
}

// A server-initiated soft reset must be answered with P_CONTROL_SOFT_RESET_V1
// before the reliable control stream carries a TLS record.
func TestTLSClientAnswersServerSoftResetBeforeControl(t *testing.T) {
	t.Parallel()
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancelServerContext()
	server, err := NewServer(ServerOptions{
		Context:   serverContext,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "udp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Timing: ServerTimingOptions{RenegotiationInterval: 2 * time.Second},
		Tunnel: ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
			Topology:     "subnet",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}
	relayAddress, observations := startControlObservationRelay(t, listenAddress)

	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 90*time.Second)
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
		Pull:   ClientPullOptions{Enabled: true},
		Timing: ClientTimingOptions{RenegotiationDisabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 10*time.Second)
	waitForClientSoftResetReply(t, observations, 20*time.Second)
}

type observedControlPacket struct {
	fromClient bool
	packet     *proto.Packet
}

type controlObservationRelay struct {
	access       sync.Mutex
	observations []observedControlPacket
}

func (r *controlObservationRelay) record(fromClient bool, rawPacket []byte) {
	if len(rawPacket) == 0 {
		return
	}
	opcode := proto.Opcode(rawPacket[0] >> 3)
	if opcode != proto.OpcodeControlSoftResetV1 && opcode != proto.OpcodeControlV1 {
		return
	}
	packet, err := proto.ParsePacket(rawPacket)
	if err != nil {
		return
	}
	r.access.Lock()
	r.observations = append(r.observations, observedControlPacket{fromClient: fromClient, packet: packet})
	r.access.Unlock()
}

func waitForClientSoftResetReply(t *testing.T, relay *controlObservationRelay, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if relay.sawSoftResetReply() {
			return
		}
		time.Sleep(interopPollInterval)
	}
	t.Fatal("timed out waiting for a client soft reset with reliable id 0 and a following control record")
}

func (r *controlObservationRelay) sawSoftResetReply() bool {
	r.access.Lock()
	defer r.access.Unlock()
	var serverSoftReset *proto.Packet
	acknowledged := false
	sawControl := false
	for _, observation := range r.observations {
		packet := observation.packet
		if !observation.fromClient && packet.Opcode == proto.OpcodeControlSoftResetV1 && packet.KeyID != 0 {
			if serverSoftReset == nil {
				serverSoftReset = packet
			}
			continue
		}
		if serverSoftReset == nil || !observation.fromClient || packet.KeyID != serverSoftReset.KeyID {
			continue
		}
		if packet.Opcode == proto.OpcodeControlSoftResetV1 && packet.ID == 0 {
			for _, packetID := range packet.AcknowledgmentIDs {
				if packetID == serverSoftReset.ID {
					acknowledged = true
					break
				}
			}
		}
		if packet.Opcode == proto.OpcodeControlV1 && packet.ID >= 1 {
			sawControl = true
		}
	}
	return acknowledged && sawControl
}

func startControlObservationRelay(t *testing.T, serverAddress string) (string, *controlObservationRelay) {
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
	relay := &controlObservationRelay{}
	var clientAddress net.Addr
	var clientAddressAccess sync.Mutex
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
			clientAddressAccess.Lock()
			clientAddress = address
			clientAddressAccess.Unlock()
			packet := append([]byte(nil), buffer[:readCount]...)
			relay.record(true, packet)
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
			clientAddressAccess.Lock()
			address := clientAddress
			clientAddressAccess.Unlock()
			if address == nil {
				continue
			}
			packet := append([]byte(nil), buffer[:readCount]...)
			relay.record(false, packet)
			_, _ = clientFacing.WriteTo(packet, address)
		}
	}()
	return clientFacing.LocalAddr().String(), relay
}
