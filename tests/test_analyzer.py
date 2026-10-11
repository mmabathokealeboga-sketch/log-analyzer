from analyzer import extract_ip


def test_extract_ip_finds_ip():
    line = "Sep 28 10:15:01 server sshd[1102]: Failed password for admin from 203.0.113.45 port 40122 ssh2"
    assert extract_ip(line) == "203.0.113.45"


def test_extract_ip_returns_none_without_ip():
    line = "Sep 28 07:00:01 server systemd[1]: Started Daily Cleanup."
    assert extract_ip(line) is None