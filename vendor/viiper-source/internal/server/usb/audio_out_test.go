package usb

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	usbdesc "github.com/DualSenseClient/VIIPER/usb"
	"github.com/DualSenseClient/VIIPER/virtualbus"
	"github.com/stretchr/testify/require"
)

func TestIsoOutSkipsPaddingAndCopiesScratchBuffer(t *testing.T) {
	input := []byte{1, 0, 2, 0, 3, 0, 4, 0, 255, 127, 255, 127, 255, 127, 255, 127, 5, 0, 6, 0, 7, 0, 8, 0}
	descriptors := isoReq(8, 8)
	binary.BigEndian.PutUint32(descriptors[16:20], 16)
	got, actuals, err := compactIsoOut(input, descriptors, 2)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0}, got)
	require.Equal(t, []uint32{8, 8}, actuals)
	input[0] = 99
	require.Equal(t, byte(1), got[0])
}

func TestIsoOutRejectsInvalidPacketBounds(t *testing.T) {
	for _, offset := range []uint32{4, 40, 0xfffffff8} {
		descriptors := isoReq(8, 8)
		binary.BigEndian.PutUint32(descriptors[16:20], offset)
		_, _, err := compactIsoOut(make([]byte, 24), descriptors, 2)
		require.Error(t, err)
	}
}

type orderedAudioDevice struct {
	entered  chan struct{}
	release  chan struct{}
	received chan byte
}

func (d *orderedAudioDevice) GetDescriptor() *usbdesc.Descriptor    { return mixedEndpointDescriptor() }
func (d *orderedAudioDevice) GetDeviceSpecificArgs() map[string]any { return nil }
func (d *orderedAudioDevice) HandleTransfer(ctx context.Context, ep, dir uint32, out []byte) []byte {
	if out[0] == 1 {
		close(d.entered)
		select {
		case <-d.release:
		case <-ctx.Done():
			return nil
		}
	}
	d.received <- out[0]
	return nil
}

func TestIsoOutCannotOvertakeAnEarlierAudioCallback(t *testing.T) {
	d := &orderedAudioDevice{make(chan struct{}), make(chan struct{}), make(chan byte, 2)}
	var release sync.Once
	unblock := func() { release.Do(func() { close(d.release) }) }
	t.Cleanup(unblock)
	bus := virtualbus.New(9821)
	defer bus.Close()
	_, err := bus.Add(d)
	require.NoError(t, err)
	server := New(ServerConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	require.NoError(t, server.AddBus(bus))
	host, peer := net.Pipe()
	defer host.Close()
	defer peer.Close()
	go func() { _ = server.handleUrbStream(peer, d) }()
	go func() { _, _ = io.Copy(io.Discard, host) }()
	require.NoError(t, host.SetWriteDeadline(time.Now().Add(2*time.Second)))
	submit := func(seq uint32, value byte) {
		header := make([]byte, 48)
		for offset, value := range map[int]uint32{0: 1, 4: seq, 16: 1, 24: 8, 32: 1} {
			binary.BigEndian.PutUint32(header[offset:offset+4], value)
		}
		packet := append(header, []byte{value, 0, 0, 0, 0, 0, 0, 0}...)
		packet = append(packet, isoReq(8)...)
		_, err := host.Write(packet)
		require.NoError(t, err)
	}
	submit(1, 1)
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("first audio packet not delivered")
	}
	submit(2, 2)
	select {
	case <-d.received:
		t.Fatal("second audio packet overtook the first")
	case <-time.After(25 * time.Millisecond):
	}
	unblock()
	for _, want := range []byte{1, 2} {
		select {
		case got := <-d.received:
			require.Equal(t, want, got)
		case <-time.After(time.Second):
			t.Fatal("audio queue stalled")
		}
	}
}
