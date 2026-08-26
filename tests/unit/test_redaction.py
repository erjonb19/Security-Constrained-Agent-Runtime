"""Unit tests for src.utils.redaction."""

from src.utils.redaction import REDACTED, redact_data, redact_text


class TestRedactData:
    """Tests for recursive data redaction."""

    def test_redacts_sensitive_keys(self) -> None:
        data = {
            "username": "alice",
            "password": "p@ss",
            "nested": {"api_key": "abc123", "safe": "ok"},
        }
        out = redact_data(data)
        assert out["username"] == "alice"
        assert out["password"] == REDACTED
        assert out["nested"]["api_key"] == REDACTED
        assert out["nested"]["safe"] == "ok"

    def test_preserves_list_and_tuple_shape(self) -> None:
        data = {
            "items": ["safe", {"token": "secret"}],
            "pair": ("Authorization: Bearer SUPERSECRET", "ok"),
        }
        out = redact_data(data)
        assert isinstance(out["items"], list)
        assert isinstance(out["pair"], tuple)
        assert out["items"][1]["token"] == REDACTED
        # The whole Authorization header VALUE is masked (stronger than masking
        # only the token after "Bearer"), so the secret must not survive.
        assert out["pair"][0] == f"Authorization: {REDACTED}"
        assert "SUPERSECRET" not in out["pair"][0]
        assert out["pair"][1] == "ok"

    def test_redacts_bare_bearer_token(self) -> None:
        """A bearer token OUTSIDE an Authorization header is still redacted."""
        out = redact_data({"note": "use Bearer SUPERSECRETVALUE123 to call it"})
        assert "Bearer [REDACTED]" in out["note"]
        assert "SUPERSECRETVALUE123" not in out["note"]

    def test_redacts_path_indicators(self) -> None:
        data = {"path": r"C:\Users\alice\.ssh\id_rsa"}
        out = redact_data(data)
        assert "[REDACTED_PATH]" in out["path"]

    def test_binary_values_become_placeholder(self) -> None:
        out = redact_data({"blob": b"\x01\x02\x03"})
        assert "BINARY_DATA_REDACTED" in out["blob"]

    def test_non_sensitive_passthrough(self) -> None:
        data = {"count": 3, "enabled": True, "name": "project"}
        out = redact_data(data)
        assert out == data


class TestRedactText:
    """Tests for free-form text redaction."""

    def test_redacts_bearer_and_auth_header(self) -> None:
        text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"
        out = redact_text(text)
        assert "[REDACTED]" in out
        assert "abcdefghijklmnopqrstuvwxyz" not in out

    def test_redacts_private_key_block(self) -> None:
        text = "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
        out = redact_text(text)
        assert out == REDACTED

    def test_redacts_known_token_patterns(self) -> None:
        text = "token=ghp_123456789012345678901234567890123456"
        out = redact_text(text)
        assert REDACTED in out
