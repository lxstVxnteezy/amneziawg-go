# Go Implementation of AmneziaWG

AmneziaWG is a contemporary version of the WireGuard protocol. It's a fork of WireGuard-Go and offers protection against detection by Deep Packet Inspection (DPI) systems. At the same time, it retains the simplified architecture and high performance of the original.

The precursor, WireGuard, is known for its efficiency but had issues with detection due to its distinctive packet signatures.
AmneziaWG addresses this problem by employing advanced obfuscation methods, allowing its traffic to blend seamlessly with regular internet traffic.
As a result, AmneziaWG maintains high performance while adding an extra layer of stealth, making it a superb choice for those seeking a fast and discreet VPN connection.

## Usage

Simply run:

```
$ amneziawg-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/amneziawg/wg0.sock`, which will result in amneziawg-go shutting down.

To run amneziawg-go without forking to the background, pass `-f` or `--foreground`:

```
$ amneziawg-go -f wg0
```
When an interface is running, you may use [`amneziawg-tools `](https://github.com/amnezia-vpn/amneziawg-tools) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; you should run amnezia-wg instead of using default linux kernel module.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.
This runs on MacOS, you should use it from [amneziawg-apple](https://github.com/amnezia-vpn/amneziawg-apple)

### Windows

This runs on Windows, you should use it from [amneziawg-windows](https://github.com/amnezia-vpn/amneziawg-windows), which uses this as a module.


## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://github.com/amnezia-vpn/amneziawg-go
$ cd amneziawg-go
$ make
```

## Config generator (awg-confgen)

`cmd/awg-confgen` generates a matching server config and client configs with every obfuscation feature enabled.

```
$ go run ./cmd/awg-confgen -endpoint vpn.example.com -clients 3
```

It writes `awg-configs/server/awg0.conf` and `awg-configs/clients/clientN.conf`. Options:

| Flag | Default | Meaning |
|------|---------|---------|
| `-endpoint` | — | public IP or hostname of the server (required) |
| `-port` | `443` | server UDP port |
| `-clients` | `1` | number of client configs |
| `-subnet` | `10.66.66.0/24` | tunnel subnet, the server takes the first address |
| `-mtu` | `1280` | tunnel MTU for the server and clients (1280-1420) |
| `-sni` | `-endpoint` if it is a domain, else a popular site | domain put into the QUIC ClientHello of the I-packets |
| `-wan` | from the default route | server uplink interface used for NAT |
| `-disable-cookies` | off | turn off the cookie mechanism; this also removes handshake flood protection |
| `-dns` | `1.1.1.1, 1.0.0.1` | DNS servers for clients |

Each client gets its own I-packets: a real QUIC v1 Initial carrying a Chrome-like TLS ClientHello (GREASE, X25519MLKEM768, shuffled extensions), split across I1 and I2 the way Chrome splits it. The server config has no I-packets, because they are client Initials and the receiving side ignores them anyway.

Pick the SNI so that it resolves to the server: a DPI can compare the SNI of a QUIC Initial with the destination IP, and `www.google.com` on a VPS address is easy to flag. Point a domain of yours at the server and pass it as `-endpoint` (it becomes the SNI) or as `-sni`. With an IP endpoint the generator falls back to a popular site and prints a warning.

Known limitations:

- I-packets are fixed bytes, so the same client sends the same Initial before every handshake (every few minutes). They cannot be randomized per handshake without re-encrypting the Initial. A DPI that remembers Initials can notice the repeats.
- After the Initial, the traffic on the same flow does not look like QUIC: with header protection the first byte is random, so about half the packets break the QUIC short-header fixed bit.
- Clients route `::/0` into the tunnel but the server has no IPv6. IPv6 is blackholed on purpose so it does not leak past the tunnel.

## Configuration

### Data types and definitions

`client-side` means the param is not required to be the same on both server and client, while  
`server-side` means this is mandatory the values are the same on server and on client  

`range,x`, where x is the underlying type of left and right
* Format: "a-b", or "a", or "(off)"
* Example: PersistentKeepalive = 22-30

> [!NOTE]
> If there is no value specified (for any param), AWG treats it as 0

### Header protection [AWG 3+]

Header protection is the mechanism of protecting low-entropy values of packets' headers. The idea is to apply fast encryption to the specific fields which WireGuard does use for authentication and its own encryption. The cipher uses `S1-S4` crypto padding as nonce for each incoming packet.

```
[Device]
+ HeaderProtectionKey: key,string - server-side # the key to be used in header protection
```

> [!TIP]
> Use `awg genkey` to generate header protection key

> [!IMPORTANT]
> Header protection requires `S1-S4` value to be 12 at least

### Content padding [AWG 3+]

```
[Device]
+ ContentPaddingAddition: uint32,range - client-side # the range to be used as a custom padding
```

> [!TIP]
> It's important to specify content padding on both sides. However, this is not strictly required and could be omitted.

### Timings [AWG 3+]

This param could be used to customize default Wireguard's timings

```
[Device]
+ RekeyAfterTime       = "uint32,range - client-side - seconds" # time, after which client tries to handshake
+ RekeyTimeout         = "uint32,range - client-side - seconds" # timeout, after which handshake is repeated
+ RejectAfterTime      = "uint32,range - client-side - seconds" # time, after which client forces handshake, and declines all incoming data
+ KeepaliveTimeout     = "uint32,range - client-side - seconds" # time from last data sending, after which keepalive is sent
+ MaxHandshakeAttempts = "uint32,range - client-side - amount"  # maximum attempts of handshake repetition

[Peer]
M PersistentKeepalive  = "uint32,range - client-side - seconds" # interval of persistent keepalive
```

### Port rotation [client-side, this fork]

The client can periodically move to a new random local UDP port. Every period then looks like a new short flow that starts with the I-packets and junk, instead of one long-lived high-volume flow to the same address, which is what per-flow throttling and statistics key on. Right after the switch a handshake is sent from the new port, so the server follows immediately. The server needs no support for it: to the server this is ordinary WireGuard roaming.

```
[Device]
+ port_rotation = "uint32,range - client-side - seconds" # interval between port changes, at least 10; 0 disables
```

amneziawg-tools does not know this key, so `awg setconf`/`awg-quick` reject it in a config file. When the client runs this amneziawg-go through awg-quick, set it with an environment variable instead:

```
$ sudo AWG_PORT_ROTATION=120-300 WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up client1
```

On Linux awg-quick prefers the amneziawg kernel module when it is loaded, and then this setting has no effect: rotation needs the userspace amneziawg-go. On macOS awg-quick always uses userspace. Applications that embed the module can set `port_rotation` over UAPI.

Notes:
- Rotation is skipped when `ListenPort` is set explicitly, so a server never moves.
- Packets the server sends in the short gap before it learns the new port are lost. TCP resends them.
- Every rotation is a new handshake that resends the same I-packets, so very short intervals make the repeats more visible. A few minutes is a reasonable interval.

### Fallback to a real site [server-side, this fork]

A port that silently drops everything that is not AWG is itself a signal: an active prober can send a QUIC Initial to 443/UDP and conclude "this is not a website". With a fallback the server relays every datagram that is not AWG to another UDP server on the same machine, typically a real HTTP/3 site (Caddy, nginx), and sends its answers back from the AWG port. To a prober the port then behaves like an ordinary HTTP/3 website.

```
[Device]
+ fallback = "ip:port - server-side" # e.g. 127.0.0.1:8443; "off" disables
```

Only datagrams that cannot be AWG are relayed: ones shorter than any AWG message and ones whose type matches none of H1-H4 at the expected S1-S4 size. AWG traffic never reaches the site, and clients need nothing: official apps keep working. The I-packets of your own clients are QUIC Initials too, so they get relayed as well and the site answers them, which is what a real HTTP/3 server would do; clients ignore those answers.

Use the same domain for the site's certificate and for the SNI of the I-packets, so the probe and the clients' Initials agree.

> [!IMPORTANT]
> Any domain works, but a prober can resolve the domain from the certificate (and from the SNI of the I-packets) and compare it with the server's IP. With someone else's domain (`google.com`, `yandex.ru`) they will not match, and you cannot get a valid certificate for it either, so the site answers with a self-signed one. For the disguise to hold up:
> - use your own domain whose A record points to this server, DNS only (no Cloudflare proxy: then the domain resolves to Cloudflare's IPs);
> - give the site a real certificate for that domain (Let's Encrypt; Caddy does it automatically over TCP 443, which AWG does not use);
> - serve the same site over TCP 443 as well, with `Alt-Svc: h3=":443"`, like any HTTP/3 website;
> - put something plausible on it rather than an empty page.
>
> A mismatch between SNI and IP alone is a weak signal (CDNs and shared hosting produce plenty of them), so a borrowed domain still beats silence, but your own domain removes the signal entirely.

As with port rotation, amneziawg-tools rejects the key in a config file; with awg-quick set it in the environment of the server interface:

```
# /etc/systemd/system/awg-quick@awg0.service.d/fallback.conf
[Service]
Environment=AWG_FALLBACK=127.0.0.1:8443
```

At most 1024 remote addresses are relayed at once, each through its own local socket that closes after 60 s of silence. Make the site listen on 127.0.0.1 only, so it is reachable through the AWG port alone.

### Diagnostic counters [server-side, this fork]

The fork counts, from the server's side, how far each client's connection gets, so a failure can be placed before anything is changed:

- per peer: handshake initiations received, responses sent, the last authenticated transport packet (data or keepalive) and the start of the current session;
- per source IP: datagrams that are not AWG with this server's parameters (junk, I-packets, foreign traffic, or AWG with other parameters), handshakes that do not verify (an unknown key, e.g. an outdated config) and data for a session the server does not know (after a restart or a reissue).

They are part of the UAPI `get` output (`diag_version`, `diag_source`, `diag_handshake_inits`, `diag_last_init_sec`, `diag_handshake_responses`, `diag_last_transport_sec`, `diag_session_start_sec`). amneziawg-tools ignores unknown keys, so `awg show` is unaffected; read them from the socket:

```
printf 'get=1\n\n' | nc -U -q1 /var/run/amneziawg/awg0.sock | grep ^diag_
```

The source table keeps at most 1024 addresses. Counters reset when the interface restarts.

### Junk packets

The amount of junk packets specified in `Jc` with a random size between `Jmin` and `Jmax` would be generated and sent prior every handshake

- `Jc: int`, recommended range is 4-12
- `Jmin: int` <= `Jmax:int`

> [!TIP]
> Junk packets do not carry any actual data, so there is no need to specify it on both sides. General recommendation is to use it on the client side only

> [!IMPORTANT]
> If Jmax >= system MTU (not the one specified in AWG), then the system can fracture this packet into fragments, which looks suspicious from the censor side

### Message paddings

- `S1: int` - padding of handshake initial message
- `S2: int` - padding of handshake response message
- `S3: int` - padding of handshake cookie message
- `S4: int` - padding of transport messages

### Message headers

Every message in wireguard has `uint32` type at the beginning of the packet. This field could be controlled by specifying the params below:

- `H1: string` - header range of handshake initial message
- `H2: string` - header range of handshake response message
- `H3: string` - header range of handshake cookie message
- `H4: string` - header range of transport message

Values could be specified as:
- range: `x-y`, x <= y; e.g. `123-456`
- single value `1234`

### Custom signature packets

These packets are being send prior to every handshake, in the same way as Junk packets do. The sending order is `I1`, `I2`, `I3`, `I4`, `I5`. If there is no value specified, the packet is skipped.

- `I1: string`
- `I2: string`
- `I3: string`
- `I4: string`
- `I5: string`

Value is a sequence of tags specified below:
- `<b 0x[seq]>` - static bytes tag. Dumps `[seq]` as-is to the packet. `[seq]` is hex-encoded sequence which represents bytes sequence (2 hex numbers per byte) and is always even-sized
- `<r [size]>` - random bytes tag. Dumps `[size]` amount of randomly-generated bytes to the packet
- `<rd [size]>` - random digits tag. Dumps `[size]` amount of randomly-generated bytes from `[0-9]` set to the packet
- `<rc [size]>` - random chars tag. Dumps `[size]` amount of randomly-generated bytes from `[a-zA-Z] set to the packet
- `<t>` - timestamp tag. Dumps 4-bytes long current system time in UNIX format

> [!TIP]
> Custom signature packets does not carry any actual data, so there is no need to specify it on both sides. General recommendation is to use it on the client side only

> [!IMPORTANT]
> If the final size of any packet exceeds system MTU, it would be fractured into fragments, which looks suspicious
