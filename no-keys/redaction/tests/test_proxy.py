"""Tests for the no-keys reverse proxy."""

import json
import unittest

from ..proxy import NoKeysProxy


class TestNoKeysProxy(unittest.TestCase):
    """Test the proxy's request body scanning and redaction."""

    def setUp(self):
        self.proxy = NoKeysProxy()

    def test_redact_json_messages_string_content(self):
        """Secrets in messages[].content (string) are redacted."""
        body = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": "My key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
                }
            ]
        }).encode()

        redacted_body, count = self.proxy._redact_json_body(body)
        data = json.loads(redacted_body)

        self.assertGreaterEqual(count, 1)
        self.assertNotIn("sk-abc123", data["messages"][0]["content"])
        self.assertIn("REDACTED", data["messages"][0]["content"])
        # Model field should be untouched
        self.assertEqual(data["model"], "claude-sonnet-4-20250514")

    def test_redact_json_messages_content_blocks(self):
        """Secrets in messages[].content[] text blocks are redacted."""
        body = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyzABC"
                        }
                    ]
                }
            ]
        }).encode()

        redacted_body, count = self.proxy._redact_json_body(body)
        data = json.loads(redacted_body)

        self.assertGreaterEqual(count, 1)
        self.assertNotIn("ghp_", data["messages"][0]["content"][0]["text"])
        self.assertIn("GITHUB_TOKEN_REDACTED", data["messages"][0]["content"][0]["text"])

    def test_redact_system_prompt_string(self):
        """Secrets in system prompt (string) are redacted."""
        body = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "system": "Use this AWS key: AKIAIOSFODNN7EXAMPLE",
            "messages": [{"role": "user", "content": "hello"}]
        }).encode()

        redacted_body, count = self.proxy._redact_json_body(body)
        data = json.loads(redacted_body)

        self.assertGreaterEqual(count, 1)
        self.assertNotIn("AKIAIOSFODNN7", data["system"])
        self.assertIn("AWS_ACCESS_KEY_REDACTED", data["system"])

    def test_redact_system_prompt_blocks(self):
        """Secrets in system prompt (content blocks) are redacted."""
        body = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "system": [
                {"type": "text", "text": "Key: AKIAIOSFODNN7EXAMPLE"}
            ],
            "messages": [{"role": "user", "content": "hello"}]
        }).encode()

        redacted_body, count = self.proxy._redact_json_body(body)
        data = json.loads(redacted_body)

        self.assertGreaterEqual(count, 1)
        self.assertNotIn("AKIAIOSFODNN7", data["system"][0]["text"])

    def test_no_secrets_passes_through(self):
        """Clean requests pass through unchanged."""
        original = {
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "What is 2 + 2?"}]
        }
        body = json.dumps(original).encode()

        redacted_body, count = self.proxy._redact_json_body(body)
        data = json.loads(redacted_body)

        self.assertEqual(count, 0)
        self.assertEqual(data["messages"][0]["content"], "What is 2 + 2?")

    def test_multiple_secrets_in_one_message(self):
        """Multiple secrets in a single message are all redacted."""
        body = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "OpenAI: sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz\n"
                        "GitHub: ghp_1234567890abcdefghijklmnopqrstuvwxyzABC\n"
                        "Google: AIzaSyD-1234567890abcdefghijklmnopqrstu"
                    )
                }
            ]
        }).encode()

        redacted_body, count = self.proxy._redact_json_body(body)
        data = json.loads(redacted_body)

        self.assertGreaterEqual(count, 2)
        content = data["messages"][0]["content"]
        self.assertNotIn("sk-abc123", content)
        self.assertNotIn("ghp_", content)

    def test_non_json_body_scanned(self):
        """Non-JSON bodies are scanned as raw text."""
        body = b"my key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"

        redacted_body, count = self.proxy._redact_json_body(body)

        self.assertGreaterEqual(count, 1)
        self.assertNotIn(b"sk-abc123", redacted_body)

    def test_empty_body(self):
        """Empty body returns empty."""
        body = b""
        redacted_body, count = self.proxy._redact_json_body(body)
        self.assertEqual(count, 0)

    def test_multiple_messages_scanned(self):
        """All messages in the conversation are scanned."""
        body = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {"role": "user", "content": "Key: AKIAIOSFODNN7EXAMPLE"},
                {"role": "assistant", "content": "I see an AWS key."},
                {"role": "user", "content": "And ghp_1234567890abcdefghijklmnopqrstuvwxyzABC"},
            ]
        }).encode()

        redacted_body, count = self.proxy._redact_json_body(body)
        data = json.loads(redacted_body)

        self.assertGreaterEqual(count, 2)
        self.assertNotIn("AKIAIOSFODNN7", data["messages"][0]["content"])
        self.assertNotIn("ghp_", data["messages"][2]["content"])
        # Assistant message (no secrets) should be unchanged
        self.assertEqual(data["messages"][1]["content"], "I see an AWS key.")

    def test_headers_not_in_body(self):
        """API keys in headers are not part of the body and not scanned."""
        # This test verifies the proxy only scans body content, not headers.
        # Headers are forwarded as-is by _handle_request (tested in integration tests).
        body = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "no secrets here"}]
        }).encode()

        _, count = self.proxy._redact_json_body(body)
        self.assertEqual(count, 0)


class TestNoKeysProxyConfig(unittest.TestCase):
    """Test proxy configuration."""

    def test_default_config(self):
        proxy = NoKeysProxy()
        self.assertEqual(proxy.host, "127.0.0.1")
        self.assertEqual(proxy.port, 8119)

    def test_custom_port(self):
        proxy = NoKeysProxy(port=9090)
        self.assertEqual(proxy.port, 9090)

    def test_metrics_initial(self):
        proxy = NoKeysProxy()
        self.assertEqual(proxy.requests_total, 0)
        self.assertEqual(proxy.secrets_redacted, 0)

    def test_log_mode_default_off(self):
        proxy = NoKeysProxy()
        self.assertFalse(proxy.log_mode)


if __name__ == "__main__":
    unittest.main()
