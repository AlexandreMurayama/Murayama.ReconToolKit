from argparse import Namespace

import pytest

from recon.cli import get_ports_to_scan


def make_args(
    port=None,
    port_range=None,
):
    return Namespace(
        port=port,
        port_range=port_range,
    )


def test_single_port():
    args = make_args(port=8080)

    assert get_ports_to_scan(args) == [8080]


def test_port_range():
    args = make_args(port_range="80-83")

    assert get_ports_to_scan(args) == [
        80,
        81,
        82,
        83,
    ]


def test_invalid_port():
    args = make_args(port=70000)

    with pytest.raises(
        ValueError,
        match="Port must be between 1 and 65535",
    ):
        get_ports_to_scan(args)


def test_reversed_port_range():
    args = make_args(port_range="9000-8000")

    with pytest.raises(
        ValueError,
        match="Start port cannot be greater than end port",
    ):
        get_ports_to_scan(args)