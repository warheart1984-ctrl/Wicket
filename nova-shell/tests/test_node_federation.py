from __future__ import annotations

import json


# Test-only 512-bit key, bigger than the 256-bit digest. A toy modulus (it was 221) reduces the digest
# so far that about one tampered payload in a few hundred still verified, which made the
# tamper check below fail now and then.
RSA_PRIVATE = {
    "kty": "RSA",
    "kid": "test-rsa",
    "n": "4622982783450864668229863113822692759782588001413320329331042631063499063082524358812306883051880935519553781241474457053324793767757759640337588674037489",
    "e": "65537",
    "d": "4382229617454285619560126586250834872037680958844639091495822091523701356408292757212134461670786706921389046252778281866033472821629568607533446840384833",
}
RSA_PUBLIC = {
    "kty": "RSA",
    "kid": "test-rsa",
    "n": "4622982783450864668229863113822692759782588001413320329331042631063499063082524358812306883051880935519553781241474457053324793767757759640337588674037489",
    "e": "65537",
}


def test_federation_gossip_summary_contains_identity(tmp_path, monkeypatch) -> None:
    from nova.node.federation import gossip_summary

    monkeypatch.setenv("NOVA_NODE_ID", "jonai-node-fed")

    summary = gossip_summary()

    assert summary["node_id"] == "jonai-node-fed"
    assert summary["policy_hash"]
    assert "governance" in summary["capabilities"]


def test_federation_loads_peers_from_manifest(tmp_path, monkeypatch) -> None:
    from nova.node.federation import load_peers

    peers = [{"peer_id": "peer-1", "endpoint": "https://peer.example"}]
    path = tmp_path / "peers.json"
    path.write_text(json.dumps(peers), encoding="utf-8")
    monkeypatch.setenv("NOVA_NODE_PEERS_PATH", str(path))

    assert load_peers() == peers


def test_signed_gossip_verifies_and_records_trust(tmp_path, monkeypatch) -> None:
    from nova.node.federation import receive_gossip_payload, signed_gossip_summary

    private_path = tmp_path / "private.json"
    public_path = tmp_path / "public.json"
    private_path.write_text(json.dumps(RSA_PRIVATE), encoding="utf-8")
    public_path.write_text(json.dumps(RSA_PUBLIC), encoding="utf-8")
    monkeypatch.setenv("NOVA_NODE_OPERATOR_PRIVATE_KEY", str(private_path))
    monkeypatch.setenv("NOVA_NODE_OPERATOR_PUBLIC_KEY", str(public_path))
    monkeypatch.setenv("NOVA_NODE_RUNTIME_DIR", str(tmp_path))

    signed = signed_gossip_summary()
    received = receive_gossip_payload(signed)

    assert signed["signature"]
    assert received["ack"] is True
    assert received["signature_valid"] is True
    assert received["trust_level"] == "trusted"

    signed["summary"]["policy_hash"] = "tampered"
    tampered = receive_gossip_payload(signed)
    assert tampered["signature_valid"] is False
    assert tampered["trust_level"] == "invalid"


def test_node_hello_returns_signed_identity(tmp_path, monkeypatch) -> None:
    from nova.node.federation import node_hello

    private_path = tmp_path / "private.json"
    private_path.write_text(json.dumps(RSA_PRIVATE), encoding="utf-8")
    monkeypatch.setenv("NOVA_NODE_OPERATOR_PRIVATE_KEY", str(private_path))
    monkeypatch.setenv("NOVA_NODE_ID", "jonai-node-hello")

    hello = node_hello()

    assert hello["node_id"] == "jonai-node-hello"
    assert hello["policy_hash"]
    assert hello["capabilities"]
    assert hello["signature"]
    assert hello["trust_level"] == "self"
