from mail_tester.main import _log_web_server_startup


def test_log_web_server_startup_for_fixed_port(caplog):
    with caplog.at_level("INFO"):
        _log_web_server_startup("127.0.0.1", 8000)

    assert "Web server at http://127.0.0.1:8000" in caplog.text


def test_log_web_server_startup_for_random_port(caplog):
    with caplog.at_level("INFO"):
        _log_web_server_startup("0.0.0.0", 0)

    assert "available port on 0.0.0.0" in caplog.text
    assert ":0" not in caplog.text
