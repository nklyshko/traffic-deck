from capture_mitmproxy.cli import _WGConfigScanner, _print_qr

# A realistic mitmproxy WireGuard startup log: a prefixed delimiter, the client config
# block, the closing delimiter, then unrelated log lines.
_OUTPUT = [
    "[10:00:00.000] " + "-" * 60 + "\n",
    "[Interface]\n",
    "PrivateKey = CLIENTKEYCLIENTKEYCLIENTKEYCLIENTKEYCLIENT=\n",
    "Address = 10.0.0.1/32\n",
    "DNS = 10.0.0.53\n",
    "\n",
    "[Peer]\n",
    "PublicKey = SERVERPUBSERVERPUBSERVERPUBSERVERPUBSERVER=\n",
    "AllowedIPs = 0.0.0.0/0\n",
    "Endpoint = 192.168.0.27:51820\n",
    "-" * 60 + "\n",
    "[10:00:01.000] HTTP(S) proxy listening at *:8888\n",
]


def _scan(lines):
    s = _WGConfigScanner()
    completed = [i for i, ln in enumerate(lines) if s.feed(ln)]
    return s.config, completed


def test_scanner_extracts_clean_config():
    cfg, completed = _scan(_OUTPUT)
    assert completed == [9]  # the Endpoint line completes the block
    assert cfg.startswith("[Interface]")  # log prefix on the delimiter is dropped
    assert cfg.strip().endswith("Endpoint = 192.168.0.27:51820")  # stops before later logs
    for want in ("PrivateKey = CLIENTKEYCLIENTKEYCLIENTKEYCLIENTKEYCLIENT=", "[Peer]",
                 "PublicKey = SERVERPUBSERVERPUBSERVERPUBSERVERPUBSERVER="):
        assert want in cfg


def test_scanner_none_without_config():
    s = _WGConfigScanner()
    for ln in ["starting up\n", "proxy listening\n"]:
        assert s.feed(ln) is False
    assert s.config is None


def test_scanner_only_first_block():
    lines = _OUTPUT + _OUTPUT  # a second block must not overwrite the first
    cfg, completed = _scan(lines)
    assert completed == [9]  # only the first block completes
    assert cfg is not None


def test_print_qr_renders(capsys):
    _print_qr("\n".join(l.strip() for l in _OUTPUT[1:10]))
    out = capsys.readouterr().out
    assert "WireGuard app" in out and "█" in out  # header + rendered QR modules
