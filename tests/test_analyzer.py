from datetime import datetime

from analyzer import extract_ip, extract_login_details, extract_time

FAILED_LINE = "Sep 28 10:15:01 server sshd[1102]: Failed password for admin from 203.0.113.45 port 40122 ssh2"
ACCEPTED_LINE = "Sep 28 08:12:04 server sshd[1021]: Accepted password for kea from 192.168.1.10 port 51422 ssh2"
JUNK_LINE = "Sep 28 07:00:01 server systemd[1]: Started Daily Cleanup."


def test_extract_ip_finds_ip():
    assert extract_ip(FAILED_LINE) == "203.0.113.45"


def test_extract_ip_returns_none_without_ip():
    assert extract_ip(JUNK_LINE) is None


def test_extract_login_details_failed():
    assert extract_login_details(FAILED_LINE) == ("Failed", "admin")


def test_extract_login_details_accepted():
    assert extract_login_details(ACCEPTED_LINE) == ("Accepted", "kea")


def test_extract_login_details_returns_none_for_junk():
    assert extract_login_details(JUNK_LINE) == (None, None)


def test_extract_time():
    assert extract_time(FAILED_LINE) == datetime(2026, 9, 28, 10, 15, 1)


def test_extract_time_returns_none_for_broken_line():
    assert extract_time("this line is broken") is None