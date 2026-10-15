from datetime import datetime, timedelta

from analyzer import (
    extract_ip,
    extract_login_details,
    extract_time,
    is_brute_force,
    is_odd_hour,
    parse_line,
)

FAILED_LINE = "Sep 28 10:15:01 server sshd[1102]: Failed password for admin from 203.0.113.45 port 40122 ssh2"
ACCEPTED_LINE = "Sep 28 08:12:04 server sshd[1021]: Accepted password for kea from 192.168.1.10 port 51422 ssh2"
JUNK_LINE = "Sep 28 07:00:01 server systemd[1]: Started Daily Cleanup."


def make_times(seconds_list):
    start = datetime(2026, 9, 28, 10, 15, 0)
    return [start + timedelta(seconds=s) for s in seconds_list]


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


def test_parse_line_returns_event():
    assert parse_line(FAILED_LINE) == {
        "time": datetime(2026, 9, 28, 10, 15, 1),
        "status": "Failed",
        "username": "admin",
        "ip": "203.0.113.45",
    }


def test_parse_line_skips_junk():
    assert parse_line(JUNK_LINE) is None


def test_parse_line_skips_empty_line():
    assert parse_line("") is None


def test_is_odd_hour_in_the_night():
    assert is_odd_hour(datetime(2026, 9, 29, 2, 47, 13)) is True


def test_is_odd_hour_just_before_five():
    assert is_odd_hour(datetime(2026, 9, 29, 4, 59, 58)) is True


def test_is_odd_hour_at_five_is_not_odd():
    assert is_odd_hour(datetime(2026, 9, 29, 5, 0, 2)) is False


def test_is_odd_hour_during_the_day():
    assert is_odd_hour(datetime(2026, 9, 29, 9, 15, 40)) is False


def test_brute_force_detects_fast_attack():
    times = make_times([0, 3, 6, 9, 12, 15, 18, 21])
    assert is_brute_force(times) is True


def test_brute_force_ignores_single_failure():
    times = make_times([0])
    assert is_brute_force(times) is False


def test_brute_force_ignores_failures_spread_out():
    times = make_times([0, 70, 140, 210, 280])
    assert is_brute_force(times) is False


def test_brute_force_exactly_at_threshold():
    times = make_times([0, 3, 6, 9, 12])
    assert is_brute_force(times) is True


def test_brute_force_one_below_threshold():
    times = make_times([0, 3, 6, 9])
    assert is_brute_force(times) is False


def test_brute_force_custom_threshold():
    times = make_times([0, 3, 6])
    assert is_brute_force(times, threshold=3) is True


def test_brute_force_last_attempt_exactly_on_window_edge():
    times = make_times([0, 15, 30, 45, 60])
    assert is_brute_force(times) is True


def test_brute_force_last_attempt_just_outside_window():
    times = make_times([0, 15, 30, 45, 61])
    assert is_brute_force(times) is False