import io
import json
import urllib.request

from nova.providers import http


class _Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _capture(monkeypatch):
    seen = {}

    def fake_urlopen(request, timeout=None):
        seen["headers"] = {k.lower(): v for k, v in request.header_items()}
        return _Response(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return seen


def test_post_json_sends_a_user_agent(monkeypatch):
    seen = _capture(monkeypatch)
    http.post_json("http://example.test", {}, timeout=1)
    assert seen["headers"]["user-agent"] == http.USER_AGENT


def test_caller_can_override_the_user_agent(monkeypatch):
    seen = _capture(monkeypatch)
    http.post_json("http://example.test", {}, timeout=1, headers={"User-Agent": "custom/1"})
    assert seen["headers"]["user-agent"] == "custom/1"
