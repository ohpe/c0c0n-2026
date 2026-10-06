from __future__ import annotations

from mail_tester.port_utils import choose_web_port, find_available_port, is_port_available


def test_choose_preferred_when_available():
    assert choose_web_port("127.0.0.1", 31337, checker=lambda h, p: True) == 31337


def test_choose_random_after_confirmation():
    prompts = []
    result = choose_web_port(
        "127.0.0.1",
        31337,
        input_fn=lambda prompt: prompts.append(prompt) or "y",
        checker=lambda h, p: False,
        fallback_fn=lambda h: 40001,
    )
    assert result == 40001
    assert prompts


def test_declining_fallback_does_not_start():
    result = choose_web_port(
        "127.0.0.1",
        31337,
        input_fn=lambda prompt: "n",
        checker=lambda h, p: False,
    )
    assert result is None


def test_eof_does_not_start():
    def raise_eof(prompt):
        raise EOFError

    result = choose_web_port(
        "127.0.0.1", 31337, input_fn=raise_eof, checker=lambda h, p: False
    )
    assert result is None


def test_port_zero_is_delegated_to_os():
    assert choose_web_port("127.0.0.1", 0) == 0


def test_find_available_port_uses_first_available():
    checked = []

    def checker(host, port):
        checked.append(port)
        return port == 30002

    assert find_available_port("127.0.0.1", start=30000, attempts=5, checker=checker) == 30002
    assert checked == [30000, 30001, 30002]


def test_real_probe_accepts_ephemeral_port():
    assert is_port_available("127.0.0.1", 0)
