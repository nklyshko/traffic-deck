from capture_mitmproxy import cli
from capture_mitmproxy.cli import _WGConfigScanner, _iface_rank, _print_qr


class _FakeStore:
    def get(self, key, default=""):
        return default


def test_iface_rank_physical_lan_first():
    items = [
        ("172.18.0.1", "singbox_tun"),   # VPN tun (owns default route on this box)
        ("192.168.163.1", "vmnet1"),     # VMware host-only (looks LAN but virtual)
        ("192.168.0.26", "wlan0"),       # the real LAN address
        ("172.17.0.1", "docker0"),
        ("10.0.0.5", "eth0"),
    ]
    ips = [ip for ip, _ in sorted(items, key=_iface_rank)]
    # physical LAN interfaces rank before virtual ones
    assert ips.index("192.168.0.26") < ips.index("192.168.163.1")  # wlan0 before vmnet1
    assert ips.index("10.0.0.5") < ips.index("172.17.0.1")         # eth0 before docker0
    assert ips.index("192.168.0.26") < ips.index("172.18.0.1")     # LAN before VPN tun


def test_choose_host_override_wins():
    assert cli._choose_host(_FakeStore(), "1.2.3.4") == "1.2.3.4"


def test_choose_host_single_candidate(monkeypatch):
    monkeypatch.setattr(cli, "_lan_candidates", lambda: [("192.168.0.26", "wlan0")])
    assert cli._choose_host(_FakeStore(), None) == "192.168.0.26"


def test_choose_host_defaults_to_best_guess(monkeypatch):
    # Non-interactive (pytest stdin isn't a tty) → the first (best-guess) candidate.
    monkeypatch.setattr(cli, "_lan_candidates",
                        lambda: [("192.168.0.26", "wlan0"), ("172.17.0.1", "docker0")])
    assert cli._choose_host(_FakeStore(), None) == "192.168.0.26"


def test_choose_host_none_without_interfaces(monkeypatch):
    monkeypatch.setattr(cli, "_lan_candidates", lambda: [])
    assert cli._choose_host(_FakeStore(), None) is None

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
