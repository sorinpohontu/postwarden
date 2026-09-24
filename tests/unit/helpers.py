import tomllib
from pathlib import Path

from postwarden.config import Settings, parse_settings
from postwarden.policy import ConnectionFacts
from postwarden.postfix import parse_mynetworks, with_postfix

REPO = Path(__file__).resolve().parents[2]
EXAMPLE = REPO / "etc" / "config.example.toml"

MYNETWORKS = parse_mynetworks("127.0.0.0/8 [::1]/128 203.0.113.0/24 [2001:db8:1::]/48")

BASE_TOML = """
schema_version = 1
mode = "enforce"

[protection.addresses."all@*"]
authorized_logins = []

[protection.addresses."everyone@*"]
authorized_logins = []

[protection.addresses."all@example.com"]
authorized_logins = ["manager@example.com", "Ceo@example.com"]

[protection.addresses."everyone@example.com"]
authorized_logins = ["manager@example.com", "Ceo@example.com"]
"""


def _merge(base: dict, extra: dict) -> dict:
    merged = dict(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def settings(extra: str = "", base: str = BASE_TOML, mynetworks=MYNETWORKS, recipient_delimiter="+") -> Settings:
    parsed = parse_settings(_merge(tomllib.loads(base), tomllib.loads(extra)), source="<test>")
    return with_postfix(parsed, mynetworks, recipient_delimiter)


def example_settings() -> Settings:
    return parse_settings(tomllib.loads(EXAMPLE.read_text()), source=str(EXAMPLE))


def smtp25(peer="198.51.100.7", daemon_addr="192.0.2.25"):
    return ConnectionFacts(peer_ip=peer, daemon_port=25, ingress_marker="SMTP25", daemon_addr=daemon_addr)


def submission(port=587, login="manager@example.com", peer="198.51.100.7", tls=True, auth_type="PLAIN"):
    marker = "SUBMISSION587" if port == 587 else "SUBMISSION465"
    return ConnectionFacts(peer_ip=peer, daemon_port=port, ingress_marker=marker,
                           auth_type=auth_type if login else None, auth_authen=login,
                           cipher_bits=256 if tls else None)


def pickup():
    return ConnectionFacts(peer_ip="127.0.0.1", daemon_port=0, ingress_marker="LOCAL_PICKUP")
