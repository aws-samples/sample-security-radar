"""Guard: tests never touch the network. Any real socket connect fails loudly."""

import socket

import pytest


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def deny(*a, **k):
        raise RuntimeError("tests must not open network connections")
    monkeypatch.setattr(socket.socket, "connect", deny)
