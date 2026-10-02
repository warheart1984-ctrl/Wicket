import json
from pathlib import Path

import pytest

from runtime.chat import run_turn
from runtime.kernel import DEFAULT_POLICY, Kernel, KernelError, find_binary
from runtime.providers import ProviderError, complete

try:
    find_binary()
except KernelError:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)


class FakeClient:
    def __init__(self, text="Paris."):
        self.text, self.calls = text, []

    def __call__(self, url, payload, headers):
        self.calls.append((url, payload, headers))
        return {"choices": [{"message": {"content": self.text}, "finish_reason": "stop"}]}


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    for name in ("GROQ_API_KEY", "NVIDIA_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.setenv(name, "test-key")


def test_allowed_turn_calls_provider_and_logs_receipt(tmp_path):
    log, client = tmp_path / "r.jsonl", FakeClient()
    result = run_turn("Capital of France?", "groq", Kernel(receipt_log=log), client=client)
    assert result.verdict == "allow" and result.reply == "Paris."
    assert len(client.calls) == 1
    assert json.loads(log.read_text().splitlines()[0])["receipt_id"] == result.receipt_id


def test_denied_turn_never_calls_provider(tmp_path):
    policy = tmp_path / "deny.json"
    policy.write_text(json.dumps({
        "version": "infinity.policy.v1", "policy_id": "policy-deny-v1",
        "denied_effects": ["read"], "effects_requiring_approval": [],
    }))
    client = FakeClient()
    result = run_turn("hi", "groq", Kernel(policy=policy), client=client)
    assert result.verdict != "allow" and result.reply is None
    assert client.calls == []


def test_message_text_is_not_sent_to_the_kernel(tmp_path):
    log = tmp_path / "r.jsonl"
    run_turn("my secret message", "nvidia", Kernel(receipt_log=log), client=FakeClient())
    assert "my secret" not in log.read_text()


def test_token_floor_and_headers():
    client = FakeClient()
    complete("groq", [{"role": "user", "content": "x"}], max_tokens=32, client=client)
    _, payload, headers = client.calls[0]
    assert payload["max_tokens"] == 256
    assert payload["reasoning_effort"] == "low"
    assert headers["User-Agent"].startswith("infinity-core")


def test_nvidia_turns_thinking_off():
    client = FakeClient()
    complete("nvidia", [{"role": "user", "content": "x"}], client=client)
    assert client.calls[0][1]["chat_template_kwargs"] == {"enable_thinking": False}


def test_missing_key_and_empty_reply_raise(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY")
    with pytest.raises(ProviderError, match="GROQ_API_KEY"):
        complete("groq", [], client=FakeClient())
    with pytest.raises(ProviderError, match="no text"):
        complete("nvidia", [], client=FakeClient(text=""))
