"""Safe web-port negotiation for local development startup."""
from __future__ import annotations

import socket
from collections.abc import Callable


class PortNegotiationError(RuntimeError):
    """Raised when no usable web port can be selected."""


def is_port_available(host: str, port: int) -> bool:
    """Return whether a TCP bind probe succeeds without disturbing listeners."""
    if port == 0:
        return True
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def find_available_port(
    host: str,
    start: int = 32768,
    attempts: int = 100,
    checker: Callable[[str, int], bool] = is_port_available,
) -> int:
    """Find an available ephemeral-range port without opening a listener."""
    for port in range(start, start + attempts):
        if checker(host, port):
            return port
    raise PortNegotiationError("No available fallback web port was found")


def choose_web_port(
    host: str,
    preferred: int,
    *,
    input_fn: Callable[[str], str] | None = None,
    checker: Callable[[str, int], bool] = is_port_available,
    fallback_fn: Callable[[str], int] | None = None,
) -> int | None:
    """Choose a port, prompting before falling back when the preferred one is busy.

    ``None`` means the caller should exit without starting the server.
    """
    if preferred == 0 or checker(host, preferred):
        return preferred

    print(f"Web port {preferred} is already in use.")
    prompt = input_fn or input
    try:
        answer = prompt("Use a random port instead? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer not in {"y", "yes"}:
        print("Web server not started.")
        return None

    selected = (fallback_fn or find_available_port)(host)
    print(f"Using random web port {selected}.")
    return selected
