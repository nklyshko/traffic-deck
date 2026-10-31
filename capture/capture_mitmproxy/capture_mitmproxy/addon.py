"""mitmproxy addon that streams decoded flows to the gateway.

Loaded into mitmproxy with `mitmdump -s addon.py` (the `trafficdeck-capture-mitmproxy` launcher
does this). mitmproxy terminates TLS, so flows arrive fully decoded; this addon pushes
them to the gateway's IngestService.PushFlows for live view + persistence — no pcap,
no key.log (the supplied RECORD path).

WireGuard mode is just `--mode wireguard`: same addon, the device routes traffic
through mitmproxy's WireGuard server instead of a system proxy.

Config via env (set by the launcher): GATEWAY_ADDR, CAPTURE_LABEL, CAPTURE_METADATA.
"""

from __future__ import annotations

import io
import ipaddress
import json
import logging
import os
import time
import uuid
import zlib
from collections import Counter

import grpc
from mitmproxy import connection, ctx, dns, http, tcp, udp
from mitmproxy.net.dns import response_codes as dns_rcodes
from mitmproxy.net.dns import types as dns_types

from mitmproxy.proxy import layer as proxy_layer

# Not defined here: mitmproxy loads this file as a script under a module name it never
# registers in sys.modules, and a dataclass looks its module up there — so a dataclass in
# this file fails to load.
from capture_mitmproxy.hostnames import DnsNames, Hostname
from capture_mitmproxy.socks_upstream import looks_like_socks5, SocksUpstreamLayer

from capture_sdk import metadata_keys as mk
from capture_sdk.proto import common_pb2 as cp
from capture_sdk.proto import ingest_pb2 as ip
from capture_sdk.proto import ingest_pb2_grpc as ig

# Bound each push so a slow/unreachable gateway can't wedge a hook — and, importantly,
# can't block mitmproxy's shutdown on the first Ctrl+C.
PUSH_TIMEOUT = 5.0

def _s(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def _peer(addr) -> str:
    if not addr:
        return ""
    host, port = addr[0], addr[1]
    return f"{host}:{port}"


def _norm_proto(v: str) -> str:
    return {"HTTP/2.0": "HTTP/2", "HTTP/3.0": "HTTP/3"}.get(v, v or "HTTP/1.1")


#: Cap on a single body pushed to the gateway. A malicious response can be a compression
#: bomb (a kilobyte of gzip → gigabytes), and the whole body is embedded in the proto, so
#: an uncapped one both pressures this proxy's memory and, past the gateway's 256 MiB gRPC
#: limit, fails to send and loses the flow. A body cut here keeps its first _MAX_BODY_BYTES,
#: is named in the flow's body.truncated metadata, and is logged.
_MAX_BODY_BYTES = 64 * 1024 * 1024

log = logging.getLogger(__name__)  # mitmproxy shows stdlib logging in its event log


def _bounded_decode(raw: bytes, enc: str, cap: int) -> bytes | None:
    """Undo one Content-Encoding without ever producing more than `cap` bytes — the decoded
    prefix when the body is larger. None for an encoding not decoded here (a chain such as
    "gzip, br", or something new), which is kept as it came, as mitmproxy itself would.

    Bounded on purpose: mitmproxy's get_content() inflates the whole body first, so capping
    after it did not stop a compression bomb from exhausting this proxy's memory."""
    if enc in ("gzip", "x-gzip"):
        return zlib.decompressobj(47).decompress(raw, cap)  # 47: gzip or zlib header
    if enc == "deflate":  # zlib-wrapped per RFC 9110, raw deflate from some servers
        try:
            return zlib.decompressobj(zlib.MAX_WBITS).decompress(raw, cap)
        except zlib.error:
            return zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw, cap)
    if enc == "br":
        import brotli  # a mitmproxy dependency

        d = brotli.Decompressor()
        out = bytearray(d.process(raw, output_buffer_limit=cap))
        while len(out) < cap and not d.is_finished():
            more = d.process(b"", output_buffer_limit=cap - len(out))
            if not more:
                break
            out += more
        return bytes(out[:cap])
    if enc == "zstd":
        import zstandard  # a mitmproxy dependency

        reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(raw), read_across_frames=True)
        return reader.read(cap)
    return None


def _content(msg) -> tuple[bytes, bool]:
    """Best-effort decoded body bytes (decompressed), capped at _MAX_BODY_BYTES; falls back
    to raw/empty. The flag says the body was longer than the cap and was cut."""
    raw = msg.raw_content or b""  # None for a streamed body
    enc = _wire_encoding(msg)
    if raw and enc:
        try:
            # One byte past the cap tells a body that fits exactly from one that was cut.
            decoded = _bounded_decode(raw, enc, _MAX_BODY_BYTES + 1)
        except Exception:  # noqa: BLE001 (not actually in that encoding: keep the wire bytes)
            decoded = None
        if decoded:
            return decoded[:_MAX_BODY_BYTES], len(decoded) > _MAX_BODY_BYTES
    return raw[:_MAX_BODY_BYTES], len(raw) > _MAX_BODY_BYTES


def _note_truncated(md, side: str, what: str) -> None:
    sides = [x for x in md.get(mk.BODY_TRUNCATED, "").split(",") if x]
    if side not in sides:
        md[mk.BODY_TRUNCATED] = ",".join(sides + [side])
    log.warning("%s: %s cut to its first %d MiB (body.truncated)", what, side, _MAX_BODY_BYTES >> 20)


def _wire_encoding(msg) -> str:
    """The transport encoding the body had on the wire ("gzip", "br"…), "" if none.

    Recorded alongside the (decoded) bytes _content returns, so a reader is told what
    they were rather than having to trust the header — which stays on the flow either
    way and can name an encoding the body was not actually sent in. "identity" is
    spelled-out absence.
    """
    enc = (msg.headers.get("content-encoding", "") or "").strip().lower()
    return "" if enc == "identity" else enc


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _sni(flow) -> str:
    """The TLS SNI the client sent: on the client connection when mitmproxy terminated TLS,
    on the server connection's when it only forwarded it."""
    for conn in (flow.client_conn, flow.server_conn):
        if sni := getattr(conn, "sni", None):
            return _s(sni)
    return ""


def _conn_id(client) -> str:
    """The connection id a flow is grouped by (connection_id, the viewer's conn column):
    mitmproxy's client connection, which every request, stream or lookup on it shares."""
    return (getattr(client, "id", "") or "")[:8]


def _address_hostname(addr, names: DnsNames | None = None, opened: float = 0) -> Hostname:
    """The name a connection's address gives: the target a regular proxy's CONNECT or
    absolute URL named ("connect"), else what the device's DNS said the IP is ("dns"),
    else the IP itself."""
    host = _s(addr[0]) if addr else ""
    if host and not _is_ip(host):
        return Hostname(host, "connect")
    if host and names and (named := names.lookup(host.strip("[]"), opened)):
        return named
    return Hostname(host, "ip")


def http_hostname(flow: http.HTTPFlow, names: DnsNames | None = None) -> Hostname:
    """The best name for an HTTP flow's server.

    In WireGuard and transparent mode `request.host` is only the IP connected to, so the
    name the client asked for comes first: the Host header (HTTP/1.x) or :authority
    (HTTP/2, HTTP/3), then the TLS SNI, then the device's DNS answer for the IP.
    """
    req = flow.request
    if req.host_header:
        return Hostname(req.pretty_host, "authority" if req.is_http2 or req.is_http3 else "host")
    if sni := _sni(flow):
        return Hostname(sni, "sni")
    return _address_hostname((req.host, req.port), names, flow.client_conn.timestamp_start or 0)


def stream_hostname(flow, names: DnsNames | None = None) -> Hostname:
    """The best name for a raw TCP or UDP stream's server: its TLS SNI, else its address."""
    if sni := _sni(flow):
        return Hostname(sni, "sni")
    return _address_hostname(flow.server_conn.address, names, flow.client_conn.timestamp_start or 0)


def _hostname_metadata(pf: cp.Flow, hostname: Hostname, sni: str) -> None:
    pf.metadata[mk.HOSTNAME_SOURCE] = hostname.source
    if hostname.source == "dns":
        pf.metadata[mk.HOSTNAME_DNS_FLOW] = hostname.dns_flow
        if hostname.candidates:
            pf.metadata[mk.HOSTNAME_DNS_CANDIDATES] = ",".join(hostname.candidates)
    if sni:
        # Recorded even when the Host header won: a Host that disagrees with the SNI (a
        # fronted domain) is worth seeing.
        pf.metadata[mk.TLS_SNI] = sni


def _is_ws_upgrade(resp) -> bool:
    return bool(resp and resp.status_code == 101 and
                resp.headers.get("upgrade", "").lower() == "websocket")


def _socks_proxy(flow: http.HTTPFlow) -> cp.Proxy | None:
    """Extract SOCKS5 proxy metadata stashed by SocksUpstreamLayer, if present."""
    # Falls back to the client connection because the pool can hand the inner request a
    # different Server than the one the layer stamped (see SocksUpstreamLayer._establish).
    info = (getattr(flow.server_conn, "_socks_proxy", None)
            or getattr(flow.client_conn, "_socks_proxy", None))
    if not info:
        return None
    return cp.Proxy(
        addr=info.get("addr", ""),
        type=info.get("type", "socks"),
        username=info.get("username", ""),
        password=info.get("password", ""),
    )


def build_flow(flow: http.HTTPFlow, names: DnsNames | None = None) -> cp.Flow:
    """Translate a mitmproxy HTTPFlow into the gateway's proto Flow."""
    req, resp = flow.request, flow.response
    path, _, query = (req.path or "/").partition("?")
    hostname = http_hostname(flow, names)

    pf = cp.Flow(
        id=flow.id,
        method=req.method or "",
        scheme=req.scheme or "",
        authority=hostname.name,
        path=path,
        query=query,
        protocol=_norm_proto(req.http_version),
        status=resp.status_code if resp else 0,
        src_addr=_peer(flow.client_conn.peername),
        dst_addr=_peer(flow.server_conn.address),
        ts_unix_micros=int((req.timestamp_start or 0) * 1_000_000),
        tls_decrypted=(req.scheme == "https"),
        user_agent=req.headers.get("user-agent", ""),
        websocket=_is_ws_upgrade(resp),
        connection_id=_conn_id(flow.client_conn),
    )
    for k, v in req.headers.fields:
        pf.request_headers.append(cp.Header(name=_s(k), value=_s(v)))
    if resp:
        for k, v in resp.headers.fields:
            pf.response_headers.append(cp.Header(name=_s(k), value=_s(v)))
        pf.content_type = resp.headers.get("content-type", "")
    if not pf.content_type:
        pf.content_type = req.headers.get("content-type", "")

    rbody, rcut = _content(req)
    pf.request_bytes = len(rbody)
    if rbody:
        pf.request_body.CopyFrom(cp.Body(size=len(rbody), content_type=req.headers.get("content-type", ""),
                                         inline=rbody, content_encoding=_wire_encoding(req)))
    if resp:
        sbody, scut = _content(resp)
        if sbody:
            pf.response_body.CopyFrom(cp.Body(size=len(sbody), content_type=resp.headers.get("content-type", ""),
                                              inline=sbody, content_encoding=_wire_encoding(resp)))

    # Forward any source-supplied metadata. Other addons (e.g. a scrape manager
    # that knows which proxy/provider served the request) stash it on
    # flow.metadata; we pass it through verbatim for the viewer to display.
    for k, v in (flow.metadata or {}).items():
        pf.metadata[_s(k)] = _s(v)
    _hostname_metadata(pf, hostname, _sni(flow))
    if rcut:
        _note_truncated(pf.metadata, "request", f"{req.method} {req.pretty_url}")
    if resp and scut:
        _note_truncated(pf.metadata, "response", f"{req.method} {req.pretty_url}")

    proxy = _socks_proxy(flow)
    if proxy:
        pf.proxy.CopyFrom(proxy)

    # Record why a request failed (connection reset, timeout, TLS/upstream error, …) so
    # the viewer can explain a flow with no response — mitmproxy sets flow.error on the
    # `error` hook.
    if flow.error and flow.error.msg:
        pf.error = _s(flow.error.msg)

    # Request→response elapsed, once the response is complete; left 0 while in flight so
    # the viewer shows a live stopwatch from ts_unix_micros instead.
    if resp and resp.timestamp_end and req.timestamp_start:
        pf.duration_micros = max(int((resp.timestamp_end - req.timestamp_start) * 1_000_000), 0)
    return pf


# conn.outcome: why a connection is recorded without decoded traffic. The gateway hides
# all but tcp_passthrough by default (filter.Hidden) and drops it once a decoder claims
# the stream.
TCP_PASSTHROUGH = "tcp_passthrough"  # a raw TCP stream, its bytes kept as messages
UDP_UNDECODED = "udp_undecoded"      # UDP that is neither DNS nor HTTP/3
TLS_REJECTED = "tls_rejected"        # the client refused mitmproxy's certificate
NO_REQUEST = "no_request"            # closed before it carried anything


def _named_authority(hostname: Hostname, addr) -> str:
    # A stream with no name keeps its port: "ip:port" says more than a bare IP does about
    # what a raw stream might be.
    if hostname.source in ("ip", "connect") and addr:
        return f"{hostname.name}:{addr[1]}"
    return hostname.name


def build_stream_flow(flow, names: DnsNames | None = None) -> cp.Flow:
    """Synthesize a Flow for a raw TCP or UDP stream mitmproxy forwarded without decoding.
    Its bytes are surfaced as directional messages (like WebSocket), so websocket=True
    reuses the message-timeline UI."""
    is_udp = isinstance(flow, udp.UDPFlow)
    addr = flow.server_conn.address
    hostname = stream_hostname(flow, names)
    pf = cp.Flow(
        id=flow.id,
        protocol="UDP" if is_udp else "TCP",
        authority=_named_authority(hostname, addr),
        src_addr=_peer(flow.client_conn.peername),
        dst_addr=_peer(addr),
        ts_unix_micros=int((flow.client_conn.timestamp_start or 0) * 1_000_000),
        tls_decrypted=bool(getattr(flow.server_conn, "tls_established", False)),
        websocket=True,
        connection_id=_conn_id(flow.client_conn),
    )
    _hostname_metadata(pf, hostname, _sni(flow))
    pf.metadata[mk.CONN_OUTCOME] = UDP_UNDECODED if is_udp else TCP_PASSTHROUGH
    _byte_counts(pf, flow.messages)
    return pf



def _byte_counts(pf: cp.Flow, messages) -> None:
    up = sum(len(m.content or b"") for m in messages if m.from_client)
    down = sum(len(m.content or b"") for m in messages if not m.from_client)
    pf.request_bytes = up
    pf.metadata[mk.CONN_BYTES_UP] = str(up)
    pf.metadata[mk.CONN_BYTES_DOWN] = str(down)


def build_dns_flow(flow: dns.DNSFlow) -> cp.Flow:
    """A DNS lookup the device made: the question as the authority and method, the
    answers as a JSON response body, the response code in dns.rcode (and as the error
    when it is not NOERROR)."""
    req, resp = flow.request, flow.response
    q = req.questions[0] if req.questions else None
    pf = cp.Flow(
        id=flow.id,
        protocol="DNS",
        method=dns_types.to_str(q.type) if q else "",
        authority=q.name.rstrip(".") if q else "",
        src_addr=_peer(flow.client_conn.peername),
        dst_addr=_peer(flow.server_conn.address),
        ts_unix_micros=int((req.timestamp or flow.client_conn.timestamp_start or 0) * 1_000_000),
        connection_id=_conn_id(flow.client_conn),
    )
    if resp:
        rcode = dns_rcodes.to_str(resp.response_code)
        pf.metadata[mk.DNS_RCODE] = rcode
        if rcode != "NOERROR":
            pf.error = rcode
        body = json.dumps([rr.to_json() for rr in resp.answers]).encode()
        pf.response_body.CopyFrom(cp.Body(size=len(body), content_type="application/json", inline=body))
        pf.content_type = "application/json"
        if resp.timestamp and req.timestamp:
            pf.duration_micros = max(round((resp.timestamp - req.timestamp) * 1_000_000), 0)
    if flow.error and flow.error.msg:
        pf.error = _s(flow.error.msg)
    return pf


def _client_dst(client: connection.Client):
    """Where a client was going, when the mode says: in WireGuard, local and transparent
    mode the client's sockname is its original destination; in a regular proxy it is only
    mitmproxy's own listener, so there is no destination to give."""
    mode = getattr(getattr(client, "proxy_mode", None), "type_name", "")
    return client.sockname if mode in ("wireguard", "local", "transparent", "tun") else None


def build_conn_flow(client: connection.Client, outcome: str, error: str,
                    names: DnsNames | None = None, target=None) -> cp.Flow:
    """A connection that carried nothing mitmproxy could decode — a client that refused
    its certificate, or one that closed before its first request — recorded so a reader
    knows the capture saw it. target is a regular proxy's CONNECT target, when there was
    one: the only destination that mode knows."""
    dst = _client_dst(client) or target
    if client.sni:
        hostname = Hostname(_s(client.sni), "sni")
    else:
        hostname = _address_hostname(dst, names, client.timestamp_start or 0)
    end = client.timestamp_end or time.time()
    pf = cp.Flow(
        id=f"conn-{client.id}",
        protocol="UDP" if client.transport_protocol == "udp" else "TCP",
        authority=_named_authority(hostname, dst),
        src_addr=_peer(client.peername),
        dst_addr=_peer(dst),
        ts_unix_micros=int((client.timestamp_start or 0) * 1_000_000),
        duration_micros=max(int((end - (client.timestamp_start or end)) * 1_000_000), 0),
        connection_id=_conn_id(client),
        error=error,
    )
    _hostname_metadata(pf, hostname, _s(client.sni or ""))
    pf.metadata[mk.CONN_OUTCOME] = outcome
    return pf


def _ws_opcode(msg) -> str:
    name = getattr(getattr(msg, "type", None), "name", "") or ""
    return "text" if name.upper() == "TEXT" else "binary"


def _message(flow_id: str, from_client: bool, opcode: str, content: bytes, ts: float) -> cp.Message:
    # Same bound as bodies: one giant frame past the gateway's gRPC limit would fail the
    # push and lose the message. The size describes the bytes kept, as for bodies, and a cut
    # message says so in its metadata.
    content = content or b""
    msg = cp.Message(
        id=str(uuid.uuid4()),
        flow_id=flow_id,
        from_client=bool(from_client),
        opcode=opcode,
        ts_unix_micros=int((ts or 0) * 1_000_000),
        payload=cp.Body(size=min(len(content), _MAX_BODY_BYTES), inline=content[:_MAX_BODY_BYTES]),
    )
    if len(content) > _MAX_BODY_BYTES:
        _note_truncated(msg.metadata, "payload", f"message on flow {flow_id}")
    return msg


def _extra_metadata(raw: str) -> dict[str, str]:
    """Parse CAPTURE_METADATA (a JSON object) into session metadata. Unparseable input is
    dropped rather than raised: a launcher's typo must not cost the capture."""
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
        return {str(k): str(v) for k, v in obj.items()}
    except (ValueError, AttributeError) as exc:
        print(f"ignoring CAPTURE_METADATA: {exc}", flush=True)
        return {}


def outcome_counts(outcomes: Counter[str]) -> dict[str, str]:
    """Session metadata saying how many connections the capture saw but could not decode,
    by reason — so "nothing else happened" can be told from "a lot went undecoded" without
    listing them. Every reason is present, 0 included: an absent key would read as "not
    counted"."""
    return {f"{mk.CONN_UNDECODED_PREFIX}{o}": str(outcomes.get(o, 0))
            for o in (TLS_REJECTED, NO_REQUEST, UDP_UNDECODED)}


class GatewayPusher:
    """Pushes completed flows to the gateway; opens the session on startup."""

    def __init__(self) -> None:
        self.addr = os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331")
        self.label = os.environ.get("CAPTURE_LABEL", "mitmproxy")
        # Metadata keys this source stashes on flows that the viewer should show as table
        # columns by default (comma-separated); declared to the gateway at OpenSession.
        self.viewer_columns = os.environ.get("VIEWER_COLUMNS", "")
        # Extra session metadata (a JSON object) from whoever launched us. Another module
        # driving this proxy — the Android browser capture — records what the capture
        # actually was that way, since a bundle read back a week later otherwise says
        # nothing beyond "mitmproxy".
        self.extra_metadata = os.environ.get("CAPTURE_METADATA", "")
        self._channel: grpc.aio.Channel | None = None
        self._stub: ig.IngestServiceStub | None = None
        self.session_id: str | None = None
        # Track TCP/UDP flow start timestamps so the end hook can compute duration.
        self._tcp_started: dict[str, float] = {}
        # What the device's DNS answers named each IP, for a connection with no name.
        self.names = DnsNames()
        # Client connections that produced a flow of any kind; one that closes without
        # becoming one is recorded as no_request.
        self._used: set[str] = set()
        # Undecoded connections by conn.outcome, reported at close.
        self.outcomes: Counter[str] = Counter()
        # A regular proxy's CONNECT target per client: where a tunnel that then carried
        # nothing (or failed TLS) was going.
        self._targets: dict[str, tuple[str, int]] = {}

    async def running(self) -> None:
        if self.session_id is not None:
            return  # `running` can fire more than once
        # Allow large messages: a captured download body can far exceed gRPC's 4 MiB default.
        self._channel = grpc.aio.insecure_channel(self.addr, options=[
            ("grpc.max_send_message_length", 256 * 1024 * 1024),
            ("grpc.max_receive_message_length", 256 * 1024 * 1024),
        ])
        self._stub = ig.IngestServiceStub(self._channel)
        # The proxy options this capture is running with, recorded on the session as every
        # other source records its own. ctx.options rather than the argv we were started
        # with: an option mitmproxy defaulted still shows up here.
        metadata = {mk.MITMPROXY_MODE: ",".join(ctx.options.mode)}
        # Both are None/"" unless they were actually passed — mitmproxy applies its own
        # defaults later — so an unset one is left out rather than recorded as "None".
        if ctx.options.listen_port:
            metadata[mk.MITMPROXY_LISTEN_PORT] = str(ctx.options.listen_port)
        if ctx.options.listen_host:
            metadata[mk.MITMPROXY_LISTEN_HOST] = ctx.options.listen_host
        if self.viewer_columns:
            metadata[mk.VIEWER_COLUMNS] = self.viewer_columns
        metadata.update(_extra_metadata(self.extra_metadata))
        handle = await self._stub.OpenSession(
            ip.OpenSessionRequest(label=self.label, source="mitmproxy",
                                  shape=cp.SOURCE_SHAPE_FLOWS, metadata=metadata)
        )
        self.session_id = handle.session_id
        ctx.log.info(f"gateway: session {self.session_id} @ {self.addr}")
        # A supervisor (serve-mode source) parses this line to learn the session id;
        # harmless noise otherwise.
        print(f"SESSION {self.session_id}", flush=True)

    async def request(self, flow: http.HTTPFlow) -> None:
        # Push the flow as soon as the request is seen, so an in-flight request (no
        # response yet) shows up immediately with a live stopwatch. response()/error()
        # re-push the same flow id with the outcome (the gateway upserts by id).
        self._used.add(flow.client_conn.id)
        await self._send(flows=[build_flow(flow, self.names)])

    async def response(self, flow: http.HTTPFlow) -> None:
        await self._send(flows=[build_flow(flow, self.names)])

    async def error(self, flow: http.HTTPFlow) -> None:
        # Push request-only flows too (connection reset, upstream error, …).
        if isinstance(flow, http.HTTPFlow):
            self._used.add(flow.client_conn.id)
            await self._send(flows=[build_flow(flow, self.names)])

    # --- DNS -------------------------------------------------------------------------
    # In WireGuard mode the device's resolver is mitmproxy itself, so every lookup passes
    # through here. Each is recorded (hidden by default), and its A/AAAA answers name the
    # connections that follow to those IPs.

    async def dns_response(self, flow: dns.DNSFlow) -> None:
        self._used.add(flow.client_conn.id)
        self.names.learn(flow)
        await self._send(flows=[build_dns_flow(flow)])

    async def dns_error(self, flow: dns.DNSFlow) -> None:
        self._used.add(flow.client_conn.id)
        await self._send(flows=[build_dns_flow(flow)])

    # --- connections nothing decoded ---------------------------------------------------

    async def tls_failed_client(self, data) -> None:
        # The client refused the handshake — almost always mitmproxy's certificate: a
        # pinned app, or one that does not trust the user CA store. No request will come.
        client = data.context.client
        self._used.add(client.id)
        why = _s(data.conn.error or "handshake failed")
        await self._push_conn(client, TLS_REJECTED,
                              f"client rejected the TLS handshake (certificate pinned?): {why}")

    def http_connect(self, flow: http.HTTPFlow) -> None:
        # Not a request in itself: a tunnel that carries nothing is still a no_request.
        self._targets[flow.client_conn.id] = (flow.request.host, flow.request.port)

    async def client_disconnected(self, client: connection.Client) -> None:
        target = self._targets.pop(client.id, None)
        if client.id in self._used:
            self._used.discard(client.id)
            return
        await self._push_conn(client, NO_REQUEST, "connection closed before any request", target)

    async def _push_conn(self, client: connection.Client, outcome: str, error: str,
                         target=None) -> None:
        self.outcomes[outcome] += 1
        target = target or self._targets.get(client.id)
        await self._send(flows=[build_conn_flow(client, outcome, error, self.names, target)])

    # --- UDP that is neither DNS nor HTTP/3 ----------------------------------------------

    async def udp_start(self, flow: udp.UDPFlow) -> None:
        await self._start_stream(flow, UDP_UNDECODED)

    async def udp_message(self, flow: udp.UDPFlow) -> None:
        await self._stream_message(flow)

    async def udp_end(self, flow: udp.UDPFlow) -> None:
        await self._close_tcp_flow(flow)

    async def udp_error(self, flow: udp.UDPFlow) -> None:
        await self._close_tcp_flow(flow)

    async def _start_stream(self, flow, outcome: str) -> None:
        self._used.add(flow.client_conn.id)
        if outcome != TCP_PASSTHROUGH:
            # A raw TCP stream is not counted: the gateway may yet decode it (MAX), which
            # only it knows. Its flows say which, by protocol.
            self.outcomes[outcome] += 1
        self._tcp_started[flow.id] = flow.timestamp_start or 0
        await self._send(flows=[build_stream_flow(flow, self.names)])

    async def _stream_message(self, flow) -> None:
        if not flow.messages:
            return
        m = flow.messages[-1]
        await self._send(messages=[_message(flow.id, m.from_client, "binary", m.content, m.timestamp)])

    async def websocket_message(self, flow: http.HTTPFlow) -> None:
        # The parent Upgrade flow was pushed on `response` (101). Push each frame as it
        # arrives; flow.websocket.messages[-1] is the newest.
        if not flow.websocket or not flow.websocket.messages:
            return
        m = flow.websocket.messages[-1]
        await self._send(messages=[_message(flow.id, m.from_client, _ws_opcode(m), m.content, m.timestamp)])

    async def tcp_start(self, flow: tcp.TCPFlow) -> None:
        # Raw (non-HTTP) TCP connection: push the synthetic connection flow up front so its
        # byte-stream messages have a parent. The gateway decodes it if a custom decoder
        # (MAX) claims it; otherwise it stays a tcp_passthrough stream.
        await self._start_stream(flow, TCP_PASSTHROUGH)

    async def tcp_message(self, flow: tcp.TCPFlow) -> None:
        await self._stream_message(flow)

    async def tcp_end(self, flow: tcp.TCPFlow) -> None:
        # The connection closed — re-push the flow with a duration so the viewer stops
        # the live stopwatch and marks it as done.
        await self._close_tcp_flow(flow)

    async def tcp_error(self, flow: tcp.TCPFlow) -> None:
        if flow.error and flow.error.msg:
            ctx.log.info(f"tcp error on {flow.id}: {flow.error.msg}")
        await self._close_tcp_flow(flow)

    async def websocket_end(self, flow: http.HTTPFlow) -> None:
        # WebSocket closed — re-push the parent flow so the viewer reflects the final state.
        if flow.websocket:
            await self._send(flows=[build_flow(flow, self.names)])

    async def _close_tcp_flow(self, flow) -> None:
        start = self._tcp_started.pop(flow.id, None)
        pf = build_stream_flow(flow, self.names)
        if start:
            pf.duration_micros = max(int((time.time() - start) * 1_000_000), 0)
        if flow.error and flow.error.msg:
            pf.error = _s(flow.error.msg)
        await self._send(flows=[pf])

    def tls_clienthello(self, data) -> None:
        # For a SOCKS-intercepted connection the upstream socket is an already-open tunnel
        # (SocksUpstreamLayer created a ServerTLSLayer → ClientTLSLayer stack over it).
        # Force mitmproxy to establish server TLS *first*, over that tunnel, before
        # replying to the client handshake.  Otherwise — with the default connection
        # strategy — the client side is decrypted but the request is forwarded upstream in
        # cleartext, and the HTTPS server answers "Client sent an HTTP request to an HTTPS
        # server".  This runs after the core tlsconfig hook (user scripts load last), so it
        # overrides tlsconfig's connection_strategy-derived default.
        if any(isinstance(layer, SocksUpstreamLayer) for layer in data.context.layers):
            data.establish_server_tls_first = True

    def next_layer(self, nextlayer: proxy_layer.NextLayer) -> None:
        # Detect a SOCKS5 greeting in the first client bytes after a CONNECT tunnel is
        # established (proxy-chain mode: social-parser → mitmproxy → SOCKS5 proxy → target).
        # Without this, mitmproxy treats the SOCKS5 + inner TLS as opaque TCP and never
        # intercepts the inner connection.  By inserting SocksUpstreamLayer, the SOCKS5
        # handshake is relayed transparently, the real target is extracted, and mitmproxy's
        # own TLS layers intercept the inner connection — so the addon sees normal decoded
        # HTTP/WebSocket flows with the real authority (e.g. ws-api.oneme.ru).
        #
        # The built-in NextLayer addon runs before user scripts (core addons register
        # first), so it has already picked TCPLayer for the SOCKS5 greeting (rawtcp=True +
        # non-HTTP first bytes).  We override that fallback — but only TCPLayer, never a
        # TLS/HTTP layer that a legitimate protocol sniff correctly identified.
        from mitmproxy.proxy.layers import tcp as tcp_layer
        if nextlayer.layer and not isinstance(nextlayer.layer, tcp_layer.TCPLayer):
            return  # a non-TCP layer was already chosen — don't clobber it
        if looks_like_socks5(nextlayer.data_client()):
            nextlayer.layer = SocksUpstreamLayer(nextlayer.context)

    async def _send(self, flows=None, messages=None) -> None:
        if self._stub is None or self.session_id is None:
            return
        try:
            call = self._stub.PushFlows(timeout=PUSH_TIMEOUT)
            await call.write(ip.FlowBatch(
                session_id=self.session_id, flows=flows or [], messages=messages or []))
            await call.done_writing()
            await call
        except Exception as exc:  # noqa: BLE001 (never break the proxy on a push error)
            ctx.log.warn(f"gateway push failed: {exc}")

    def done(self) -> None:
        # Shutdown: close the session over a short-lived sync channel (the async loop
        # is tearing down, so don't rely on it here).
        if self.session_id is None:
            return
        try:
            with grpc.insecure_channel(self.addr) as ch:
                ig.IngestServiceStub(ch).CloseSession(
                    ip.CloseSessionRequest(session_id=self.session_id,
                                           metadata=outcome_counts(self.outcomes)), timeout=10
                )
        except Exception:  # noqa: BLE001
            pass


addons = [GatewayPusher()]
