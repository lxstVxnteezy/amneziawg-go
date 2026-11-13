/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) Unwrap() error {
	return s.err
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// IpcGetOperation implements the WireGuard configuration protocol "get" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcGetOperation(w io.Writer) error {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}
	keyf := func(prefix string, key *[32]byte) {
		buf.Grow(len(key)*2 + 2 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		const hex = "0123456789abcdef"
		for i := 0; i < len(key); i++ {
			buf.WriteByte(hex[key[i]>>4])
			buf.WriteByte(hex[key[i]&0xf])
		}
		buf.WriteByte('\n')
	}
	boolf := func(prefix string, val bool) {
		buf.Grow(3 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		if val {
			buf.WriteByte('1')
		} else {
			buf.WriteByte('0')
		}
		buf.WriteByte('\n')

	}

	func() {
		// lock required resources

		device.net.RLock()
		defer device.net.RUnlock()

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		device.peers.RLock()
		defer device.peers.RUnlock()

		device.headerProtection.RLock()
		defer device.headerProtection.RUnlock()

		// serialize device related values

		if !device.staticIdentity.privateKey.IsZero() {
			keyf("private_key", (*[32]byte)(&device.staticIdentity.privateKey))
		}

		if device.net.port != 0 {
			sendf("listen_port=%d", device.net.port)
		}

		if device.net.fwmark != 0 {
			sendf("fwmark=%d", device.net.fwmark)
		}

		if count := device.junk.count.Load(); count != 0 {
			sendf("jc=%d", count)
		}

		if min := device.junk.min.Load(); min != 0 {
			sendf("jmin=%d", min)
		}

		if max := device.junk.max.Load(); max != 0 {
			sendf("jmax=%d", max)
		}

		if padding := device.paddings.init.Load(); padding != 0 {
			sendf("s1=%d", padding)
		}

		if padding := device.paddings.response.Load(); padding != 0 {
			sendf("s2=%d", padding)
		}

		if padding := device.paddings.cookie.Load(); padding != 0 {
			sendf("s3=%d", padding)
		}

		if padding := device.paddings.transport.Load(); padding != 0 {
			sendf("s4=%d", padding)
		}

		if header := device.headers.init.Load(); !header.IsZero() {
			sendf("h1=%s", header.ToString())
		}

		if header := device.headers.response.Load(); !header.IsZero() {
			sendf("h2=%s", header.ToString())
		}

		if header := device.headers.cookie.Load(); !header.IsZero() {
			sendf("h3=%s", header.ToString())
		}

		if header := device.headers.transport.Load(); !header.IsZero() {
			sendf("h4=%s", header.ToString())
		}

		for i := range device.ipackets {
			if ipacket := device.ipackets[i].Load(); ipacket != nil {
				sendf("i%d=%s", i+1, ipacket.Spec)
			}
		}

		if !device.headerProtection.key.IsZero() {
			keyf("header_protection_key", (*[32]byte)(&device.headerProtection.key))
		}

		if addition := device.contentPaddingAddition.Load(); !addition.IsZero() {
			sendf("content_padding_addition=%s", addition.ToString())
		}

		if timing := device.timings.rekeyAfterTimeSec.Load(); !timing.IsZero() {
			sendf("rekey_after_time=%s", timing.ToString())
		}
		if timing := device.timings.rekeyTimeoutSec.Load(); !timing.IsZero() {
			sendf("rekey_timeout=%s", timing.ToString())
		}
		if timing := device.timings.rejectAfterTimeSec.Load(); !timing.IsZero() {
			sendf("reject_after_time=%s", timing.ToString())
		}
		if timing := device.timings.keepaliveTimeoutSec.Load(); !timing.IsZero() {
			sendf("keepalive_timeout=%s", timing.ToString())
		}
		if rang := device.timings.maxHandshakeAttemps.Load(); !rang.IsZero() {
			sendf("max_handshake_attempts=%s", rang.ToString())
		}
		boolf("random_trailers", device.randomTrailers.Load())
		boolf("disable_cookies", device.disableCookies.Load())
		if rang := device.portRotation.Load(); !rang.IsZero() {
			sendf("port_rotation=%s", rang.ToString())
		}
		if target, ok := device.fallbackTarget(); ok {
			sendf("fallback=%s", target)
		}
		sendf("diag_version=1") // see diag.go; ignored by amneziawg-tools
		for _, line := range device.diagSourceLines() {
			sendf("%s", line)
		}

		for _, peer := range device.peers.keyMap {
			// Serialize peer state.
			peer.handshake.mutex.RLock()
			keyf("public_key", (*[32]byte)(&peer.handshake.remoteStatic))
			keyf("preshared_key", (*[32]byte)(&peer.handshake.presharedKey))
			peer.handshake.mutex.RUnlock()
			sendf("protocol_version=1")
			peer.endpoint.Lock()
			if peer.endpoint.val != nil {
				sendf("endpoint=%s", peer.endpoint.val.DstToString())
			}
			peer.endpoint.Unlock()

			nano := peer.lastHandshakeNano.Load()
			secs := nano / time.Second.Nanoseconds()
			nano %= time.Second.Nanoseconds()

			sendf("last_handshake_time_sec=%d", secs)
			sendf("last_handshake_time_nsec=%d", nano)
			sendf("tx_bytes=%d", peer.txBytes.Load())
			sendf("rx_bytes=%d", peer.rxBytes.Load())
			sendf("diag_handshake_inits=%d", peer.diag.initsReceived.Load())
			sendf("diag_last_init_sec=%d", unixSec(peer.diag.lastInit.Load()))
			sendf("diag_handshake_responses=%d", peer.diag.responsesSent.Load())
			sendf("diag_last_transport_sec=%d", unixSec(peer.diag.lastTransport.Load()))
			sendf("diag_session_start_sec=%d", unixSec(peer.diag.transportStart.Load()))

			if keepalive := peer.persistentKeepaliveInterval.Load(); !keepalive.IsZero() {
				sendf("persistent_keepalive_interval=%s", keepalive.ToString())
			}

			device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
				sendf("allowed_ip=%s", prefix.String())
				return true
			})
		}
	}()

	// send lines (does not require resource locks)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output: %w", err)
	}

	return nil
}

// IpcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcSetOperation(r io.Reader) (err error) {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			device.log.Errorf("%v", err)
		}
	}()

	ipcDev := new(ipcSetDevice)
	ipcDev.fromDevice(device)
	peer := new(ipcSetPeer)
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			if err := ipcDev.mergeWithDevice(device); err != nil {
				return err
			}
			peer.handlePostConfig()
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(
				ipc.IpcErrorProtocol,
				"failed to parse line %q",
				line,
			)
		}

		if key == "public_key" {
			if deviceConfig {
				// The device section is complete: validate and apply it
				// before touching any peer.
				deviceConfig = false
				if err := ipcDev.mergeWithDevice(device); err != nil {
					return err
				}
			}
			peer.handlePostConfig()
			// Load/create the peer we are now configuring.
			err := device.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = device.handleDeviceLine(ipcDev, key, value)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	if err := ipcDev.mergeWithDevice(device); err != nil {
		return err
	}
	peer.handlePostConfig()

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

func (device *Device) handleDeviceLine(ipcDev *ipcSetDevice, key, value string) error {
	switch key {
	case "private_key":
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating private key")
			device.SetPrivateKey(sk)
			return nil
		})

	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
		}

		ipcDev.later(func() error {
			// update port and rebind
			device.log.Verbosef("UAPI: Updating listen port")

			device.net.Lock()
			device.net.port = uint16(port)
			device.net.portExplicit = port != 0
			device.net.Unlock()

			if err := device.BindUpdate(); err != nil {
				return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set listen_port: %w", err)
			}
			return nil
		})

	case "fwmark":
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark: %w", err)
		}

		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating fwmark")
			if err := device.BindSetMark(uint32(mark)); err != nil {
				return ipcErrorf(ipc.IpcErrorPortInUse, "failed to update fwmark: %w", err)
			}
			return nil
		})

	case "replace_peers":
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set replace_peers, invalid value: %v",
				value,
			)
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Removing all peers")
			device.RemoveAllPeers()
			return nil
		})

	case "jc":
		jc, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jc: %w", err)
		}

		ipcDev.junk.count = uint32(jc)

	case "jmin":
		jmin, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jmin: %w", err)
		}

		ipcDev.junk.min = uint32(jmin)

	case "jmax":
		jmax, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jmax: %w", err)
		}

		ipcDev.junk.max = uint32(jmax)

	case "s1":
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s1: %w", err)
		}
		ipcDev.paddings.init = uint32(padding)

	case "s2":
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s2: %w", err)
		}
		ipcDev.paddings.response = uint32(padding)

	case "s3":
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s3: %w", err)
		}
		ipcDev.paddings.cookie = uint32(padding)

	case "s4":
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s4: %w", err)
		}
		ipcDev.paddings.transport = uint32(padding)

	case "h1":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H1: %w", err)
		}
		ipcDev.headers.init = rang

	case "h2":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H2: %w", err)
		}
		ipcDev.headers.response = rang

	case "h3":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H3: %w", err)
		}
		ipcDev.headers.cookie = rang

	case "h4":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H4: %w", err)
		}
		ipcDev.headers.transport = rang

	case "i1":
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I1: %w", err)
		}
		ipcDev.later(func() error {
			device.ipackets[0].Store(chain)
			return nil
		})

	case "i2":
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I2: %w", err)
		}
		ipcDev.later(func() error {
			device.ipackets[1].Store(chain)
			return nil
		})

	case "i3":
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I3: %w", err)
		}
		ipcDev.later(func() error {
			device.ipackets[2].Store(chain)
			return nil
		})

	case "i4":
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I4: %w", err)
		}
		ipcDev.later(func() error {
			device.ipackets[3].Store(chain)
			return nil
		})

	case "i5":
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I5: %w", err)
		}
		ipcDev.later(func() error {
			device.ipackets[4].Store(chain)
			return nil
		})

	case "header_protection_key":
		var key HeaderCipherKey
		err := key.FromHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set header_protection_key: %w", err)
		}
		ipcDev.headerProtectionKey = key

	case "content_padding_addition":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse content_padding_addition: %w", err)
		}

		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating content padding addition")
			device.contentPaddingAddition.Store(rang)
			return nil
		})

	case "rekey_after_time":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse rekey after time: %w", err)
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating rekey after time")
			device.timings.rekeyAfterTimeSec.Store(rang)
			return nil
		})

	case "rekey_timeout":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse rekey timeout: %w", err)
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating rekey timeout")
			device.timings.rekeyTimeoutSec.Store(rang)
			return nil
		})

	case "reject_after_time":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse reject after time: %w", err)
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating reject after time")
			device.timings.rejectAfterTimeSec.Store(rang)
			return nil
		})

	case "keepalive_timeout":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse keepalive timeout: %w", err)
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating keepalive timeout")
			device.timings.keepaliveTimeoutSec.Store(rang)
			return nil
		})

	case "max_handshake_attempts":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse max handshake attempts: %w", err)
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating max handshake attempts")
			device.timings.maxHandshakeAttemps.Store(rang)
			return nil
		})

	case "random_trailers":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse random trailers: %w", err)
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating random trailers")
			device.randomTrailers.Store(val)
			return nil
		})

	case "disable_cookies":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse disable cookies: %w", err)
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating disable cookies")
			device.disableCookies.Store(val)
			return nil
		})

	case "fallback":
		// UDP server that gets every non-AWG datagram, e.g. 127.0.0.1:8443
		// (a real HTTP/3 site); "off" or empty disables
		var target netip.AddrPort
		if value != "" && value != "off" {
			t, err := netip.ParseAddrPort(value)
			if err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse fallback (want ip:port): %w", err)
			}
			target = t
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating fallback")
			device.SetFallback(target)
			return nil
		})

	case "port_rotation":
		// seconds between local port changes, e.g. "120-300"; "0" disables
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse port_rotation: %w", err)
		}
		if !rang.IsZero() && rang.Lo() < minPortRotationSec {
			return ipcErrorf(ipc.IpcErrorInvalid, "port_rotation must be at least %d seconds", minPortRotationSec)
		}
		ipcDev.later(func() error {
			device.log.Verbosef("UAPI: Updating port rotation")
			device.portRotation.Store(rang)
			device.kickPortRotation()
			return nil
		})

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*Peer        // Peer is the current peer being operated on
	dummy   bool // dummy reports whether this peer is a temporary, placeholder peer
	created bool // new reports whether this is a newly created peer
	pkaOn   bool // pkaOn reports whether the peer had the persistent keepalive turn on
}

func (peer *ipcSetPeer) handlePostConfig() {
	if peer.Peer == nil || peer.dummy {
		return
	}
	if peer.created {
		peer.endpoint.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	if peer.device.isUp() {
		peer.Start()
		if peer.pkaOn {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
}

func (device *Device) handlePublicKeyLine(
	peer *ipcSetPeer,
	value string,
) error {
	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}

	// Ignore peer with the same public key as this device.
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
	}

	peer.created = peer.Peer == nil
	if peer.created {
		peer.Peer, err = device.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer: %w", err)
		}
		device.log.Verbosef("%v - UAPI: Created", peer.Peer)
	}
	return nil
}

func (device *Device) handlePeerLine(
	peer *ipcSetPeer,
	key, value string,
) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set update only, invalid value: %v",
				value,
			)
		}
		if peer.created && !peer.dummy {
			device.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !peer.dummy {
			device.log.Verbosef("%v - UAPI: Removing", peer.Peer)
			device.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true

	case "preshared_key":
		device.log.Verbosef("%v - UAPI: Updating preshared key", peer.Peer)

		peer.handshake.mutex.Lock()
		err := peer.handshake.presharedKey.FromHex(value)
		peer.handshake.mutex.Unlock()

		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}

	case "endpoint":
		device.log.Verbosef("%v - UAPI: Updating endpoint", peer.Peer)
		endpoint, err := device.net.bind.ParseEndpoint(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v: %w", value, err)
		}
		peer.endpoint.Lock()
		defer peer.endpoint.Unlock()
		peer.endpoint.val = endpoint

	case "persistent_keepalive_interval":
		device.log.Verbosef("%v - UAPI: Updating persistent keepalive interval", peer.Peer)

		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set persistent keepalive interval: %w", err)
		}

		old := peer.persistentKeepaliveInterval.Swap(rang)

		// Send immediate keepalive if we're turning it on and before it wasn't on.
		peer.pkaOn = old.IsZero() && !rang.IsZero()

	case "replace_allowed_ips":
		device.log.Verbosef("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to replace allowedips, invalid value: %v",
				value,
			)
		}
		if peer.dummy {
			return nil
		}
		device.allowedips.RemoveByPeer(peer.Peer)

	case "allowed_ip":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		device.log.Verbosef("%v - UAPI: %s allowedip", peer.Peer, verb)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
		}
		if peer.dummy {
			return nil
		}
		if add {
			device.allowedips.Insert(prefix, peer.Peer)
		} else {
			device.allowedips.Remove(prefix, peer.Peer)
		}

	case "protocol_version":
		if value != "1" {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI peer key: %v", key)
	}

	return nil
}

func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(strings.NewReader(uapiConf))
}

func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(buffered.Reader)
		case "get=1\n":
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(
					ipc.IpcErrorInvalid,
					"trailing character in UAPI get: %q",
					nextByte,
				)
				break
			}
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errorf("invalid UAPI operation: %v", op)
			return
		}

		// write status
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
		}
		if status != nil {
			device.log.Errorf("%v", status)
			fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		buffered.Flush()
	}
}

type ipcSetDevice struct {
	junk struct {
		count uint32
		min   uint32
		max   uint32
	}
	headers struct {
		init      UintRange
		response  UintRange
		cookie    UintRange
		transport UintRange
	}
	paddings struct {
		init      uint32
		response  uint32
		cookie    uint32
		transport uint32
	}
	headerProtectionKey HeaderCipherKey

	// apply holds the side effects of the device section. They run only
	// after the whole section has been validated, so a rejected config
	// leaves the device untouched.
	apply  []func() error
	merged bool
}

func (d *ipcSetDevice) later(f func() error) {
	d.apply = append(d.apply, f)
}

func (d *ipcSetDevice) fromDevice(device *Device) {
	device.headerProtection.RLock()
	defer device.headerProtection.RUnlock()

	d.junk.count = device.junk.count.Load()
	d.junk.min = device.junk.min.Load()
	d.junk.max = device.junk.max.Load()

	d.headers.init = device.headers.init.Load()
	d.headers.response = device.headers.response.Load()
	d.headers.cookie = device.headers.cookie.Load()
	d.headers.transport = device.headers.transport.Load()

	d.paddings.init = device.paddings.init.Load()
	d.paddings.response = device.paddings.response.Load()
	d.paddings.cookie = device.paddings.cookie.Load()
	d.paddings.transport = device.paddings.transport.Load()

	d.headerProtectionKey = device.headerProtection.key
}

// mergeWithDevice validates the staged device section and applies it. It must
// run before any peer line is applied: peers are configured right after it.
func (d *ipcSetDevice) mergeWithDevice(device *Device) *IPCError {
	if d.merged {
		return nil
	}
	d.merged = true

	headers := []UintRange{d.headers.init, d.headers.response, d.headers.cookie, d.headers.transport}
	for i := 0; i < len(headers); i++ {
		for j := i + 1; j < len(headers); j++ {
			left := headers[i]
			right := headers[j]

			if left.Overlap(right) {
				return ipcErrorf(ipc.IpcErrorInvalid, "headers must not overlap")
			}
		}
	}

	// Validate everything before storing anything, so a rejected config
	// never leaves the device half-updated.
	if !d.headerProtectionKey.IsZero() {
		paddings := []uint32{d.paddings.init, d.paddings.response, d.paddings.cookie, d.paddings.transport}
		for i, padding := range paddings {
			if padding < HeaderCipherNonceSize {
				return ipcErrorf(ipc.IpcErrorInvalid, "S%d must be at least %d to use headerProtection", i+1, HeaderCipherNonceSize)
			}
		}
	}

	if d.junk.count > 0 {
		if d.junk.min > d.junk.max {
			return ipcErrorf(ipc.IpcErrorInvalid, "jmin (%d) must not be greater than jmax (%d)", d.junk.min, d.junk.max)
		}
		if d.junk.max > MaxSegmentSize {
			return ipcErrorf(ipc.IpcErrorInvalid, "jmax (%d) must not exceed %d", d.junk.max, MaxSegmentSize)
		}
	}

	for _, f := range d.apply {
		if err := f(); err != nil {
			if ipcErr, ok := err.(*IPCError); ok {
				return ipcErr
			}
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
	}

	device.headerProtection.Lock()
	defer device.headerProtection.Unlock()

	// Header protection is switched off before S1-S4 change and switched
	// on after, so a worker that sees the key also sees paddings that can
	// hold its nonce (see RoutineEncryption).
	if d.headerProtectionKey.IsZero() {
		device.headerProtection.active.Store(nil)
	}

	device.log.Verbosef("UAPI: Updating junk count/min/max")
	device.junk.count.Store(d.junk.count)
	device.junk.min.Store(d.junk.min)
	device.junk.max.Store(d.junk.max)

	device.log.Verbosef("UAPI: Updating h1 padding")
	device.headers.init.Store(d.headers.init)

	device.log.Verbosef("UAPI: Updating h2 padding")
	device.headers.response.Store(d.headers.response)

	device.log.Verbosef("UAPI: Updating h3 padding")
	device.headers.cookie.Store(d.headers.cookie)

	device.log.Verbosef("UAPI: Updating h4 padding")
	device.headers.transport.Store(d.headers.transport)

	device.log.Verbosef("UAPI: Updating s1 padding")
	device.paddings.init.Store(d.paddings.init)

	device.log.Verbosef("UAPI: Updating s2 padding")
	device.paddings.response.Store(d.paddings.response)

	device.log.Verbosef("UAPI: Updating s3 padding")
	device.paddings.cookie.Store(d.paddings.cookie)

	device.log.Verbosef("UAPI: Updating s4 padding")
	device.paddings.transport.Store(d.paddings.transport)

	device.log.Verbosef("UAPI: Updating header protection key")
	device.headerProtection.key = d.headerProtectionKey
	if !d.headerProtectionKey.IsZero() {
		key := d.headerProtectionKey
		device.headerProtection.active.Store(&key)
	}

	return nil
}
