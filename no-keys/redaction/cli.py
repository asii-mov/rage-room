"""no-keys CLI — secret redaction proxy for AI coding tools."""

import logging
import os
import signal
import sys
from pathlib import Path

import click

from .proxy import NoKeysProxy
from .config import RedactionConfig


PIDFILE = Path.home() / ".no-keys" / "proxy.pid"


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
def cli():
    """no-keys — secret redaction proxy for AI coding tools."""
    pass


@cli.command()
@click.option("--port", default=8119, help="Port to listen on (default: 8119)")
@click.option("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.option("--log", "log_mode", is_flag=True, help="Show before/after for every redaction")
def start(port: int, host: str, verbose: bool, log_mode: bool):
    """Start the no-keys HTTPS proxy server.

    \b
    Usage with Claude Code:
        no-keys start &
        HTTPS_PROXY=http://127.0.0.1:8119 \\
        NODE_EXTRA_CA_CERTS=~/.no-keys/ca.pem \\
        claude

    \b
    Usage with --log to see redactions live:
        no-keys start --log
    """
    _setup_logging(verbose or log_mode)

    # Write PID file
    PIDFILE.parent.mkdir(parents=True, exist_ok=True)
    PIDFILE.write_text(str(os.getpid()))

    def _cleanup(signum, frame):
        PIDFILE.unlink(missing_ok=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)

    try:
        proxy = NoKeysProxy(host=host, port=port)
        proxy.log_mode = log_mode
        proxy.run()
    finally:
        PIDFILE.unlink(missing_ok=True)


@cli.command()
def stop():
    """Stop a running no-keys proxy."""
    if not PIDFILE.exists():
        click.echo("No running proxy found.")
        return

    pid = int(PIDFILE.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        click.echo(f"Stopped no-keys proxy (pid {pid})")
    except ProcessLookupError:
        click.echo(f"Process {pid} not found (stale pidfile).")
    finally:
        PIDFILE.unlink(missing_ok=True)


@cli.command()
def status():
    """Check if the no-keys proxy is running."""
    if not PIDFILE.exists():
        click.echo("Proxy is not running.")
        return

    pid = int(PIDFILE.read_text().strip())
    try:
        os.kill(pid, 0)  # signal 0 = check if alive
        click.echo(f"Proxy is running (pid {pid})")
    except ProcessLookupError:
        click.echo(f"Proxy is not running (stale pidfile for pid {pid})")
        PIDFILE.unlink(missing_ok=True)


def main():
    cli()


if __name__ == "__main__":
    main()
