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

This requires [Go](https://go.dev/) 1.26.11 or newer (the version in `go.mod`; the Dockerfile builds with it as well).

```
$ git clone https://github.com/lxstVxnteezy/amneziawg-go
$ cd amneziawg-go
$ make
```

Upstream is [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go); the module path is unchanged, so other projects pin this fork with a `replace` directive.

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
| `-sni` | `-endpoint` if it is a domain, else none | domain put into the QUIC ClientHello of the I-packets |
| `-wan` | from the default route | server uplink interface used for NAT |
| `-disable-cookies` | off | turn off the cookie mechanism; this also removes handshake flood protection |
| `-dns` | `1.1.1.1, 1.0.0.1` | DNS servers for clients |
| `-fork` | off | clients run this fork: `I1 = <quic sni=...>` (or `<quic>` without SNI), a new QUIC Initial before every handshake instead of fixed bytes (official clients reject it) |

The configs are written with mode 0600 through a temporary file and a rename, so a rerun replaces old configs atomically and also tightens files that had broader permissions. The generator refuses an endpoint or DNS value with a line break, a port outside 1-65535 and a `-wan` that is not a plain interface name (`[a-zA-Z0-9_.@-]`, up to 15 characters), because those values end up in the config and in the server's PostUp/PostDown commands.

Each client gets its own I-packets: a real QUIC v1 Initial carrying a Chrome-like TLS ClientHello (GREASE, X25519MLKEM768, shuffled extensions), split across I1 and I2 the way Chrome splits it. The server config has no I-packets, because they are client Initials and the receiving side ignores them anyway.

Pick the SNI so that it resolves to the server: a DPI can compare the SNI of a QUIC Initial with the destination IP, and `www.google.com` on a VPS address is easy to flag. Point a domain of yours at the server and pass it as `-endpoint` (it becomes the SNI) or as `-sni`. With an IP endpoint and no `-sni` the I-packets carry no SNI at all, as a browser connecting to an IP address does (TLS does not allow an IP in SNI), and the generator prints a warning. A borrowed popular domain is worse than none: it does not resolve to the server.

Known limitations:

- Without `-fork`, I-packets are fixed bytes, so the same client sends the same Initial at the start of every flow (each port rotation or reconnect). A DPI that remembers Initials can notice the repeats. With `-fork` the client builds a new one each time (see "Generated QUIC Initials").
- After the Initial, the traffic on the same flow does not look like QUIC: with header protection the first byte is random, so about half the packets break the QUIC short-header fixed bit.
- Clients route `::/0` into the tunnel but the server has no IPv6. IPv6 is blackholed on purpose so it does not leak past the tunnel.

## Configuration

### Applying a configuration [this fork]

A UAPI `set` is applied as a whole or not at all. Input that cannot be read to the end (a line longer than the reader buffer, a lost connection) or a line without `key=value` is rejected before anything changes, so a truncated config with `replace_peers=true` cannot remove the peers. The Outline integration (`outline/`) also rejects H1-H4, I1-I5, endpoints and AllowedIPs containing a line break, because such a value would add UAPI commands of its own.

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
- Every rotation is a new handshake that resends the I-packets. With fixed ones very short intervals make the repeats more visible; with `<quic sni=...>` every rotation looks like a new connection attempt. A few minutes is a reasonable interval either way.

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

### Split tunneling by domain [client-side, this fork, library]

Package `splittun` wraps the client's TUN and sends chosen sites past the tunnel by domain name, the way Xray-based clients route "geosite" rules, instead of a hand-made list of thousands of addresses in AllowedIPs:

- DNS queries for listed domains (`ru`, `vk.com`, ...; subdomains included) are answered through a direct resolver (Yandex DNS by default), so the answers point at servers near the user; AAAA queries for them get an empty answer, so apps use IPv4.
- The addresses from those answers (and listed networks) are remembered; new TCP and UDP flows to them are terminated in a userspace stack (gVisor) and re-originated by the process outside the tunnel.
- Everything else, other DNS queries included, goes into the tunnel unchanged. A flow keeps its path for its whole life: a connection that started in the tunnel is not moved when its address becomes direct.
- `ParseRules("preset:ru, example.org", "198.51.100.0/24", "77.88.8.8")`; `preset:ru` is the Russian zones (.ru, .su, .рф, .москва) and big Russian services on other zones (VK, Yandex, ...).

- Only A records of the queried name and of its CNAME chain make an address direct; the answer must match the query (name, type, class IN), and anything else in it is ignored. Truncated or failed answers are passed on without adding routes.
- At most 64 direct lookups run at once; extra queries are dropped and the resolver retries them. At most 65536 flows are tracked: new flows are dropped until an entry expires, and active flows are never evicted, so none of them moves to the other path. A direct TCP connection keeps its entry for as long as its relay is alive, even if it is silent for a long time.

The direct connections are made by the process itself, so it must not route into its own tunnel: on Android the VPN excludes the app (`addDisallowedApplication`).

Encrypted DNS would hide the queries: Android's automatic Private DNS tries DNS over TLS to the tunnel's resolver, and Chrome's automatic secure DNS upgrades 1.1.1.1 to DNS over HTTPS. Pass the tunnel's DNS servers as `Config.Resolvers`: TCP to them on 853 and 443 is answered with a reset and UDP on those ports is dropped, so both fall back to plain DNS. Private DNS set to a specific hostname, and apps with their own DoH server, still bypass the interception; their traffic to listed sites goes through the tunnel.

### Diagnostic counters [server-side, this fork]

The fork counts, from the server's side, how far each client's connection gets, so a failure can be placed before anything is changed:

- per peer: handshake initiations received, responses sent, the last authenticated transport packet (data or keepalive) and the start of the current session;
- per source IP: datagrams that are not AWG with this server's parameters (junk, I-packets, foreign traffic, or AWG with other parameters), handshakes that do not verify (an unknown key, e.g. an outdated config) and data for a session the server does not know (after a restart or a reissue).

They are part of the UAPI `get` output (`diag_version`, `diag_source`, `diag_handshake_inits`, `diag_last_init_sec`, `diag_handshake_responses`, `diag_last_transport_sec`, `diag_session_start_sec`). amneziawg-tools ignores unknown keys, so `awg show` is unaffected; read them from the socket:

```
printf 'get=1\n\n' | nc -U -q1 /var/run/amneziawg/awg0.sock | grep ^diag_
```

The source table keeps at most 1024 addresses. Counters reset when the interface restarts.

### QUIC shape of packets [both sides, this fork, automatic]

A flow that begins with a QUIC Initial has to go on looking like QUIC. In AmneziaWG the first byte of every later packet comes from the random S1-S4 prefix (or is random junk), so half of them read as QUIC long headers with a random version, which no QUIC endpoint sends. A DPI that follows the flow as QUIC sees through the disguise at the first such packet.

When the disguise is QUIC, the fork makes the first byte of junk, handshake, cookie and transport packets a QUIC short header byte (`0b01xxxxxx`: short header, fixed bit set). It turns on by itself when:

- an I-packet is a QUIC Initial: the `<quic>` tag or a fixed `<b 0x...>` Initial (client);
- non-AWG datagrams go to a fallback site (server);
- the device listens on UDP 443 (server).

Nothing else changes on the wire and the receiver never reads these bits, so a shaping side works with any peer, official or fork. With an S prefix of 0 (AWG 1.x levels) there is nothing to shape. Two of the 96 bits of the header protection nonce become fixed; 94 stay random.

This removes the cheapest tell, not every one: the server still does not answer the Initial the way an HTTP/3 server would, and a stateful parser can notice that.

### Junk packets

The amount of junk packets specified in `Jc` with a random size between `Jmin` and `Jmax` would be generated and sent prior every handshake that starts a flow (see "Only at the start of a flow")

- `Jc: int`, accepted range is 0–256, recommended range is 4–12
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

This fork rejects an `S4` larger than the transport buffer can carry (65535 minus the 32-byte transport header and tag on Linux, macOS and Android; less on Windows and iOS, whose buffers are smaller).

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

These packets are being send prior to every handshake that starts a flow, in the same way as Junk packets do. The sending order is `I1`, `I2`, `I3`, `I4`, `I5`. If there is no value specified, the packet is skipped.

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
- `<quic sni=[domain]>`, `<quic>` - generated QUIC Initial flight, with or without SNI [client-side, this fork]. See below

`<r>`, `<rc>`, `<rd>` and `<dz>` take a size from 0 to 65535; this fork rejects anything else when the config is applied (a negative size used to crash the device at the first handshake). The tags of one I-packet together must not exceed 65535 bytes either: `<r 65535><r 1>` is rejected.

#### Only at the start of a flow [this fork]

A real QUIC client sends its Initial once, when a connection starts, and never again on the same 4-tuple. Upstream sends I1-I5 and junk with every handshake: every two minutes and on every retry, in the middle of a running flow, which no browser does. This fork sends them only with a handshake that starts a flow:

- the local socket is new (startup, rebind, `port_rotation`) or the peer's address changed;
- the peer has not answered since the last disguised handshake (the flow never got going);
- nothing went either way for 30 s (Chrome's QUIC idle timeout; NATs and middleboxes may have forgotten the flow).

Any other handshake is a rekey inside a live flow and goes out bare, like the rest of the flow (QUIC-shaped when the shape is on). Only the sending side changes: receivers skip I-packets and junk and never require them, so this works with official servers and clients. With `port_rotation` every rotation starts a new flow, so each flow begins with its own Initial.

With a QUIC disguise (the shape is on and there are I-packets) two more things follow a browser:

- **Retries are QUIC retransmissions.** When the handshake gets no answer, a browser does not start a new connection every 5 s: it resends the same ClientHello under the same connection ID, in packets with the next packet numbers, when its probe timeout fires (1, 2, 4, 8 s). Handshake retries follow that schedule: sends at 0, 1, 3, 7 s, then a new attempt with a new connection ID at 15 s. A `<quic>` tag is retransmitted properly; fixed bytes (`<b 0x...>`) repeat as they are. The device gives up after the usual number of retries, which now takes about 70 s instead of 90.
- **Junk waits for the answer.** A browser is silent between its Initial and the server's reply, so a burst right after the Initial is a tell. The junk of a new flow goes out after the handshake response, where a browser sends its Handshake and first 1-RTT packets. For official clients the generator should set `Jc = 0` in a QUIC profile instead.

I1-I5 can be changed on a running device without a data race: each of them is replaced atomically. They are replaced one by one, so a handshake sent during the change may carry some old and some new I-packets; the next one has only the new set.

#### Generated QUIC Initials [client-side, this fork]

```
I1 = <quic sni=vpn.example.com>
I1 = <quic sni=vpn.example.com classic>
I1 = <quic>
```

Before every handshake that starts a flow the device builds a new QUIC v1 client Initial flight: a fresh connection ID, TLS random and key shares, a Chrome-like ClientHello (GREASE, shuffled extensions, X25519MLKEM768) for the domain, encrypted with the Initial keys of that connection ID as RFC 9001 requires. A post-quantum ClientHello does not fit one datagram, so the flight is two datagrams, like Chrome's; `classic` drops the post-quantum key share (older Chrome) and fits one. A fixed `<b 0x...>` Initial resends the same bytes, connection ID included, before every handshake, which a DPI that remembers Initials can notice; this one is a new connection attempt every time.

- The tag must be the only one of its I-packet. Other I-packets may follow it.
- Only the sending side needs this fork: the server never parses I-packets (it drops them, or relays them to the fallback site when one is set). amneziawg-tools passes the value through unchanged, so it works with `awg-quick` too. Official AmneziaWG clients reject the tag, so use it only in configs for clients on this fork.
- `awg-confgen -fork` writes it instead of fixed bytes. The configs then also fit a QR code: fixed Initials take about 5 KB.
- Pick the SNI as for fixed Initials: a domain that resolves to the server. Without a domain write `<quic>`: the ClientHello then has no `server_name` extension, which is what a browser sends to an IP address. `sni=` with an empty value is rejected, so a generator that lost its domain fails loudly.

> [!TIP]
> Custom signature packets does not carry any actual data, so there is no need to specify it on both sides. General recommendation is to use it on the client side only

> [!IMPORTANT]
> If the final size of any packet exceeds system MTU, it would be fractured into fragments, which looks suspicious
