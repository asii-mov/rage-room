"""no-keys MITM proxy server.

An HTTPS proxy that intercepts CONNECT tunnels, terminates TLS using a
generated CA certificate, scans request bodies for secrets, redacts them,
and forwards the cleaned request to the real upstream.

Usage:
    # Start the proxy
    no-keys start

    # Configure Claude Code to use it
    HTTPS_PROXY=http://127.0.0.1:8119 NODE_EXTRA_CA_CERTS=~/.no-keys/ca.pem claude

Architecture:
    Claude Code
        -> CONNECT api.anthropic.com:443 -> no-keys proxy
        -> TLS handshake (proxy presents cert signed by its CA)
        -> proxy reads plaintext HTTP, scans for secrets, redacts
        -> proxy forwards to real api.anthropic.com over HTTPS
        -> response streamed back through the tunnel
"""

import asyncio
import json
import logging
import ssl
import tempfile
import time
from typing import Optional

import aiohttp

from .certs import load_ca, generate_host_cert, CA_CERT_PATH
from .detector import SecretDetector
from .config import RedactionConfig
from .patterns import PatternManager

logger = logging.getLogger("no-keys")


class NoKeysProxy:
    """MITM proxy that redacts secrets from HTTPS API requests."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8119,
        config: Optional[RedactionConfig] = None,
    ):
        self.host = host
        self.port = port
        self.config = config or RedactionConfig(
            enabled=True,
            rollout_percentage=100.0,
            patterns_config={
                "openai": {"enabled": True, "log_only": False},
                "anthropic": {"enabled": True, "log_only": False},
                "aws_access_key": {"enabled": True, "log_only": False},
                "aws_secret": {"enabled": True, "log_only": False},
                "github_pat": {"enabled": True, "log_only": False},
                "stripe": {"enabled": True, "log_only": False},
                "slack_token": {"enabled": True, "log_only": False},
                "google_api": {"enabled": True, "log_only": False},
                "generic_api_key": {"enabled": False, "log_only": True},
                "hex_secret": {"enabled": False, "log_only": True},
                "jwt_token": {"enabled": True, "log_only": False},
                "private_key_header": {"enabled": True, "log_only": False},
            },
        )
        self.detector = SecretDetector(PatternManager())

        # TLS interception
        self.ca_cert, self.ca_key = load_ca()
        self._host_cert_cache: dict[str, ssl.SSLContext] = {}

        # Metrics
        self.requests_total = 0
        self.secrets_redacted = 0
        self.start_time: Optional[float] = None

        # Detailed logging mode
        self.log_mode = False

    def _get_host_ssl_context(self, hostname: str) -> ssl.SSLContext:
        """Get or create an SSL context with a cert for the given hostname."""
        if hostname not in self._host_cert_cache:
            cert_pem, key_pem = generate_host_cert(hostname, self.ca_cert, self.ca_key)

            # Write to temp files for ssl module
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf, \
                 tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf:
                cf.write(cert_pem)
                cf.flush()
                kf.write(key_pem)
                kf.flush()
                ctx.load_cert_chain(cf.name, kf.name)

            self._host_cert_cache[hostname] = ctx

        return self._host_cert_cache[hostname]

    def _scan_and_redact(self, body: str) -> tuple[str, int]:
        """Scan text for secrets and return redacted version + count."""
        redacted, mapping = self.detector.redact(body)
        count = len(mapping)
        if count > 0:
            for placeholder, original in mapping.items():
                pattern_type = placeholder.split("_REDACTED_")[0].lstrip("<")
                logger.warning(
                    "REDACTED %s (len=%d) in outbound request", pattern_type, len(original)
                )
        return redacted, count

    def _redact_json_body(self, body: bytes) -> tuple[bytes, int]:
        """Parse JSON body, redact secrets in message content, re-serialize."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            text = body.decode("utf-8", errors="replace")
            redacted, count = self._scan_and_redact(text)
            return redacted.encode("utf-8"), count

        total_redacted = 0

        if "messages" in data and isinstance(data["messages"], list):
            for msg in data["messages"]:
                if isinstance(msg.get("content"), str):
                    msg["content"], count = self._scan_and_redact(msg["content"])
                    total_redacted += count
                elif isinstance(msg.get("content"), list):
                    for block in msg["content"]:
                        if isinstance(block, dict) and block.get("type") == "text":
                            block["text"], count = self._scan_and_redact(block["text"])
                            total_redacted += count

        if isinstance(data.get("system"), str):
            data["system"], count = self._scan_and_redact(data["system"])
            total_redacted += count
        elif isinstance(data.get("system"), list):
            for block in data["system"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    block["text"], count = self._scan_and_redact(block["text"])
                    total_redacted += count

        return json.dumps(data).encode("utf-8"), total_redacted

    @staticmethod
    def _extract_text_content(data: dict) -> str:
        """Extract human-readable text from an Anthropic API request body."""
        parts = []
        if isinstance(data.get("system"), str):
            parts.append(f"[system] {data['system']}")
        elif isinstance(data.get("system"), list):
            for block in data["system"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(f"[system] {block['text']}")
        for msg in data.get("messages", []):
            role = msg.get("role", "?")
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(f"[{role}] {content}")
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(f"[{role}] {block['text']}")
        return "\n".join(parts)

    @staticmethod
    def _extract_response_text(body: bytes) -> str:
        """Extract assistant text from an Anthropic API response body."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return body.decode("utf-8", errors="replace")[:500]
        if "content" in data and isinstance(data["content"], list):
            parts = []
            for block in data["content"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block["text"])
            return "\n".join(parts) if parts else str(data)[:500]
        return str(data)[:500]

    def _log_step(self, header: str, body: str, notes: list[str] | None = None):
        """Print a formatted log step to stdout."""
        sep = "=" * 72
        print(f"\n{sep}")
        print(f"  {header}")
        print(sep)
        print(body)
        if notes:
            print()
            for note in notes:
                print(f"  {note}")
        print()

    async def _read_http_request(self, reader: asyncio.StreamReader) -> tuple[str, dict, bytes]:
        """Read a full HTTP request. Returns (request_line, headers, body)."""
        # Read request line
        request_line = (await reader.readline()).decode("utf-8", errors="replace").strip()

        # Read headers
        headers = {}
        while True:
            line = (await reader.readline()).decode("utf-8", errors="replace").strip()
            if not line:
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        # Read body if present
        body = b""
        content_length = int(headers.get("Content-Length", headers.get("content-length", 0)))
        if content_length > 0:
            body = await reader.readexactly(content_length)

        return request_line, headers, body

    def _build_http_response(self, status: int, reason: str, headers: dict, body: bytes) -> bytes:
        """Build a raw HTTP response."""
        lines = [f"HTTP/1.1 {status} {reason}"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append(f"Content-Length: {len(body)}")
        lines.append("")
        lines.append("")
        return "\r\n".join(lines).encode("utf-8") + body

    async def _handle_tunnel(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        hostname: str,
        port: int,
    ):
        """Handle a CONNECT tunnel with TLS interception."""
        # Send 200 to establish tunnel
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        # Upgrade client connection to TLS (we present our fake cert)
        host_ctx = self._get_host_ssl_context(hostname)
        transport = client_writer.transport
        raw_socket = transport.get_extra_info("socket")

        # Wrap the raw socket with TLS for the client side
        loop = asyncio.get_event_loop()
        tls_transport = await loop.start_tls(
            transport, transport.get_protocol(), host_ctx, server_side=True,
        )

        # Create new reader/writer over the TLS transport
        tls_reader = asyncio.StreamReader()
        tls_protocol = asyncio.StreamReaderProtocol(tls_reader)
        tls_transport.set_protocol(tls_protocol)
        tls_writer = asyncio.StreamWriter(tls_transport, tls_protocol, tls_reader, loop)

        try:
            # Read the actual HTTP request from the decrypted stream
            request_line, headers, body = await asyncio.wait_for(
                self._read_http_request(tls_reader), timeout=30
            )

            if not request_line:
                return

            self.requests_total += 1
            method, path, _ = request_line.split(" ", 2)

            # Scan and redact
            redacted_count = 0
            original_text = ""

            if body and self.log_mode:
                try:
                    original_data = json.loads(body)
                    original_text = self._extract_text_content(original_data)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    original_text = body.decode("utf-8", errors="replace")[:2000]

            if body:
                body, redacted_count = self._redact_json_body(body)
                self.secrets_redacted += redacted_count

            if self.log_mode and redacted_count > 0:
                try:
                    redacted_data = json.loads(body)
                    redacted_text = self._extract_text_content(redacted_data)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    redacted_text = body.decode("utf-8", errors="replace")[:2000]

                self._log_step(
                    f"Step 1: Original Request ({redacted_count} secret{'s' if redacted_count != 1 else ''} detected)",
                    original_text,
                )
                self._log_step(
                    "Step 2: Redacted Request Sent to Upstream",
                    redacted_text,
                    [
                        "[PROTECTION] Real secrets replaced with <SERVICE_REDACTED_hash> placeholders",
                        "[SECURITY] The model will never see your actual secrets",
                    ],
                )

            # Forward to real upstream
            upstream_url = f"https://{hostname}{path}"
            fwd_headers = {k: v for k, v in headers.items()
                          if k.lower() not in {"host", "transfer-encoding", "connection"}}
            fwd_headers["Host"] = hostname
            if body:
                fwd_headers["Content-Length"] = str(len(body))

            start = time.monotonic()

            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=method,
                    url=upstream_url,
                    headers=fwd_headers,
                    data=body if body else None,
                    allow_redirects=False,
                ) as upstream_resp:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    resp_body = await upstream_resp.read()

                    if redacted_count > 0:
                        logger.info(
                            "%s %s -> %d (%d secrets redacted, %.0fms)",
                            method, path, upstream_resp.status,
                            redacted_count, elapsed_ms,
                        )
                    else:
                        logger.debug(
                            "%s %s -> %d (%.0fms)",
                            method, path, upstream_resp.status, elapsed_ms,
                        )

                    if self.log_mode and redacted_count > 0:
                        resp_text = self._extract_response_text(resp_body)
                        self._log_step(
                            "Step 3: Model Response",
                            resp_text,
                            [
                                f"[STATS] Requests processed: {self.requests_total}",
                                f"[STATS] Secrets redacted: {self.secrets_redacted}",
                            ],
                        )

                    # Build response headers
                    resp_headers = {
                        k: v for k, v in upstream_resp.headers.items()
                        if k.lower() not in {"transfer-encoding", "connection", "content-encoding"}
                    }

                    raw_resp = self._build_http_response(
                        upstream_resp.status,
                        upstream_resp.reason or "OK",
                        resp_headers,
                        resp_body,
                    )
                    tls_writer.write(raw_resp)
                    await tls_writer.drain()

        except asyncio.TimeoutError:
            logger.debug("Tunnel timeout for %s", hostname)
        except Exception as e:
            logger.error("Tunnel error for %s: %s", hostname, e)
        finally:
            tls_writer.close()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Handle an incoming client connection."""
        try:
            first_line = (await asyncio.wait_for(reader.readline(), timeout=10)).decode(
                "utf-8", errors="replace"
            ).strip()

            if not first_line:
                writer.close()
                return

            parts = first_line.split()
            if len(parts) < 3:
                writer.close()
                return

            method = parts[0].upper()

            if method == "CONNECT":
                # CONNECT host:port HTTP/1.1
                host_port = parts[1]
                if ":" in host_port:
                    hostname, port_str = host_port.rsplit(":", 1)
                    port = int(port_str)
                else:
                    hostname = host_port
                    port = 443

                # Consume remaining headers
                while True:
                    line = (await reader.readline()).decode("utf-8", errors="replace").strip()
                    if not line:
                        break

                logger.debug("CONNECT %s:%d", hostname, port)
                await self._handle_tunnel(reader, writer, hostname, port)

            elif method == "GET" and "/health" in parts[1]:
                # Health check endpoint
                uptime = time.time() - self.start_time if self.start_time else 0
                health = json.dumps({
                    "status": "ok",
                    "uptime_seconds": int(uptime),
                    "requests_total": self.requests_total,
                    "secrets_redacted": self.secrets_redacted,
                })
                resp = self._build_http_response(200, "OK", {"Content-Type": "application/json"}, health.encode())
                writer.write(resp)
                await writer.drain()
                writer.close()

            else:
                # Unsupported method for a proxy
                resp = self._build_http_response(
                    405, "Method Not Allowed",
                    {"Content-Type": "text/plain"},
                    b"no-keys proxy only supports CONNECT (HTTPS proxy) and health checks",
                )
                writer.write(resp)
                await writer.drain()
                writer.close()

        except Exception as e:
            logger.debug("Client handler error: %s", e)
            writer.close()

    def run(self):
        """Start the proxy server."""
        self.start_time = time.time()

        print(f"no-keys proxy listening on http://{self.host}:{self.port}")
        print(f"  CA cert: {CA_CERT_PATH}")
        if self.log_mode:
            print(f"  log mode: ON (showing before/after for every redaction)")
        print()
        print("Configure Claude Code:")
        print(f"  HTTPS_PROXY=http://{self.host}:{self.port} \\")
        print(f"  NODE_EXTRA_CA_CERTS={CA_CERT_PATH} \\")
        print(f"  claude")
        print()

        async def _serve():
            server = await asyncio.start_server(
                self._handle_client, self.host, self.port,
            )
            async with server:
                await server.serve_forever()

        asyncio.run(_serve())
