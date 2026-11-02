"""Tests for the SEGGER RTT control-block scan (probe_tools)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keil_mcp_server.tools.probe_tools import (
    _RTT_MAGIC,
    _RTT_SCAN_BASE,
    _RTT_SCAN_SIZE,
    _find_rtt_control_block,
)

CHUNK = 1024


class FakeTarget:
    """Minimal stand-in for a pyOCD target backed by a sparse memory window."""

    def __init__(self, data=b"", base=None, unreadable=()):
        self.base = _RTT_SCAN_BASE if base is None else base
        self.data = bytearray(data)
        self.unreadable = list(unreadable)
        self.reads = []

    def _readable(self, addr, size):
        for lo, hi in self.unreadable:
            if addr < hi and lo < addr + size:
                return False
        return True

    def read_memory_block8(self, addr, size):
        self.reads.append((addr, size))
        if not self._readable(addr, size):
            raise RuntimeError("unmapped memory at 0x%08x" % addr)
        block = bytearray(size)
        lo = max(addr, self.base)
        hi = min(addr + size, self.base + len(self.data))
        if lo < hi:
            block[lo - addr:hi - addr] = self.data[lo - self.base:hi - self.base]
        return block


def _window_with(offset, payload):
    """Return a full scan window with payload written at offset."""
    buf = bytearray(_RTT_SCAN_SIZE)
    buf[offset:offset + len(payload)] = payload
    return bytes(buf)


def test_finds_magic_inside_first_chunk():
    target = FakeTarget(_window_with(0x40, _RTT_MAGIC))
    assert _find_rtt_control_block(target) == _RTT_SCAN_BASE + 0x40


def test_finds_magic_straddling_a_chunk_boundary():
    # The magic spans the 1024-byte chunk edge, so the scanner has to carry
    # the tail of the previous block into the next search.
    offset = CHUNK - 4
    target = FakeTarget(_window_with(offset, _RTT_MAGIC))
    assert _find_rtt_control_block(target) == _RTT_SCAN_BASE + offset


def test_skips_unreadable_chunks():
    # A hole in the memory map must not abort the scan: the control block sits
    # behind an unmapped region and is still expected to be found.
    offset = 0x2000
    data = _window_with(offset, _RTT_MAGIC)
    target = FakeTarget(
        data,
        unreadable=[(_RTT_SCAN_BASE + 0x400, _RTT_SCAN_BASE + 0x800)],
    )
    assert _find_rtt_control_block(target) == _RTT_SCAN_BASE + offset


def test_returns_none_when_magic_absent():
    target = FakeTarget(b"no control block here")
    assert _find_rtt_control_block(target) is None


def test_scan_stays_inside_window_and_stops_at_magic():
    target = FakeTarget(_window_with(0x100, _RTT_MAGIC))
    _find_rtt_control_block(target)
    assert target.reads, "expected at least one read"
    assert all(_RTT_SCAN_BASE <= a < _RTT_SCAN_BASE + _RTT_SCAN_SIZE
               for a, _ in target.reads)
    assert len(target.reads) == 1, "should stop as soon as the magic is hit"


def test_returns_none_when_whole_window_is_unreadable():
    target = FakeTarget(
        b"",
        unreadable=[(_RTT_SCAN_BASE, _RTT_SCAN_BASE + _RTT_SCAN_SIZE)],
    )
    assert _find_rtt_control_block(target) is None


def test_accepts_custom_magic():
    custom = b"MY CONTROL B"
    buf = bytearray(_RTT_SCAN_SIZE)
    buf[0x80:0x80 + len(custom)] = custom
    target = FakeTarget(bytes(buf))
    assert _find_rtt_control_block(target, magic=custom) == _RTT_SCAN_BASE + 0x80
