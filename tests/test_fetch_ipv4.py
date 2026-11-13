"""Lambda has no IPv6 egress (ubuntu_usn, live 2026-11-11: the IPv6 address's Errno 99 masked the IPv4 cause)."""
import socket

from radar import fetch

V4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("185.125.190.20", 443))
V6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2620:2d:4000:1::26", 443, 0, 0))


def test_a_host_with_ipv4_resolves_to_ipv4_only():
    gai = fetch._ipv4_first_getaddrinfo(lambda *a, **k: [V6, V4])
    assert gai("ubuntu.com", 443) == [V4]


def test_a_host_with_only_ipv6_keeps_it():
    gai = fetch._ipv4_first_getaddrinfo(lambda *a, **k: [V6])
    assert gai("v6only.example", 443) == [V6]
