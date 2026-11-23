"""Probe debug tools via pyOCD: connect/halt/resume/step/breakpoints/registers.

These are read-only or execution-control operations on a debug probe; flash
persistent operations live in flash_tools.py. Every probe access is serialized
through the per-probe lease (blueprint §7.5).
"""
from __future__ import annotations

import asyncio
import time
from typing import List, Optional

from .context import get_context

_probe_cache: dict = {}


def _session(probe_id: str = "default"):
    from pyocd.core.helpers import ConnectHelper
    s = _probe_cache.get(probe_id)
    if s is None:
        # connect_mode='attach'：连接时既不 reset 也不 halt，仅通过 DAP 做内存/寄存器访问。
        # pyOCD 默认 'halt' 会在 open() 时 halt 内核；本工程 FWDGT 未开 debug suspend
        # （DBG_CTL.FWDGT_SUSP），halt 期间看门狗照常计数，超过喂狗窗口即触发 FWDGTRST，
        # 造成"冷启动/复位"假象（曾误判 18s/58s 复位）。attach 让内核全程正常运行、正常喂狗。
        s = ConnectHelper.session_with_chosen_probe(
            unique_id=probe_id if probe_id != "default" else None,
            options={
                "target_override": None,
                "connect_mode": "attach",
            })
        s.open()
        _probe_cache[probe_id] = s
    return s


def _close(probe_id: str = "default") -> None:
    s = _probe_cache.pop(probe_id, None)
    if s is not None:
        try:
            s.close()
        except Exception:
            pass


async def probe_connect(probe_id: str = "default", chip: str = "") -> dict:
    """Connect to a debug probe via pyOCD (auto-detect or by unique id)."""
    ctx = get_context()
    async with ctx.lease.acquire(probe_id):
        try:
            s = _session(probe_id)
            tgt = s.target
            return {"success": True, "probe_id": probe_id,
                    "target": getattr(tgt, "part_number", "") or chip,
                    "state": "connected"}
        except Exception as e:
            return {"success": False, "error": str(e)}


async def probe_disconnect(probe_id: str = "default") -> dict:
    """Disconnect the probe (releases it for UV4 -f flash path)."""
    ctx = get_context()
    async with ctx.lease.acquire(probe_id):
        try:
            _close(probe_id)
            return {"success": True, "probe_id": probe_id}
        except Exception as e:
            return {"success": False, "error": str(e)}


async def _ctrl(probe_id: str, op: str, **kw) -> dict:
    ctx = get_context()
    async with ctx.lease.acquire(probe_id):
        try:
            s = _session(probe_id)
            t = s.target
            fn = getattr(t, op)
            fn(**kw)
            return {"success": True, "probe_id": probe_id, "op": op}
        except Exception as e:
            return {"success": False, "error": str(e), "op": op}


async def probe_halt(probe_id: str = "default") -> dict:
    """Halt the target."""
    return await _ctrl(probe_id, "halt")


async def probe_resume(probe_id: str = "default") -> dict:
    """Resume the target."""
    return await _ctrl(probe_id, "resume")


async def probe_step(probe_id: str = "default") -> dict:
    """Single-step the target."""
    return await _ctrl(probe_id, "step")


async def set_breakpoint(address: int = 0, symbol: str = "", probe_id: str = "default") -> dict:
    """Set a hardware breakpoint by symbol name or address."""
    ctx = get_context()
    async with ctx.lease.acquire(probe_id):
        try:
            s = _session(probe_id)
            t = s.target
            if symbol and not address:
                # resolve symbol via ELF if loaded
                from pyocd.debug.elf.debug_elf import DebugElf
                elf = getattr(s, "_elf", None)
                if elf is not None:
                    syms = elf.symbols
                    if symbol in syms:
                        address = syms[symbol].address
            if not address:
                return {"success": False, "error": f"cannot resolve symbol {symbol!r} (no ELF loaded)"}
            bp = t.set_breakpoint(address)
            return {"success": True, "address": address, "bp_handle": bp}
        except Exception as e:
            return {"success": False, "error": str(e)}


async def continue_target(probe_id: str = "default") -> dict:
    """Continue the target until the next breakpoint."""
    return await _ctrl(probe_id, "resume")


async def probe_read_registers(probe_id: str = "default") -> dict:
    """Read core registers (r0-r15, xpsr, sp, lr, pc)."""
    ctx = get_context()
    async with ctx.lease.acquire(probe_id):
        try:
            s = _session(probe_id)
            t = s.target
            regs = t.read_core_registers_raw(range(16))
            xpsr = t.read_core_register("xpsr") if hasattr(t, "read_core_register") else None
            names = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                     "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"]
            out = {n: ("0x%08x" % (v & 0xFFFFFFFF)) for n, v in zip(names, regs)}
            if xpsr is not None:
                out["xpsr"] = "0x%08x" % (xpsr & 0xFFFFFFFF)
            return {"success": True, "registers": out}
        except Exception as e:
            return {"success": False, "error": str(e)}


async def probe_read_memory(address: int, length: int = 64, probe_id: str = "default") -> dict:
    """Read memory at address (bytes)."""
    ctx = get_context()
    async with ctx.lease.acquire(probe_id):
        try:
            s = _session(probe_id)
            t = s.target
            data = t.read_memory_block8(address, length)
            hexs = " ".join("%02x" % b for b in data)
            return {"success": True, "address": "0x%08x" % address,
                    "length": length, "data_hex": hexs}
        except Exception as e:
            return {"success": False, "error": str(e)}


_RTT_MAGIC = b"SEGGER RTT"
# The generic CoreSightTarget has no usable device memory map (pyOCD falls back
# to a fake 512 MB "SRAM" region), so scan a bounded window instead.
_RTT_SCAN_BASE = 0x20000000
_RTT_SCAN_SIZE = 0x10000


def _find_rtt_control_block(target, magic: bytes = _RTT_MAGIC) -> Optional[int]:
    """Scan RAM for the "SEGGER RTT" magic; tolerant of unmapped chunks."""
    addr = _RTT_SCAN_BASE
    end = _RTT_SCAN_BASE + _RTT_SCAN_SIZE
    overlap = len(magic) - 1
    prev = b""
    while addr < end:
        size = min(1024, end - addr)
        try:
            data = bytes(target.read_memory_block8(addr, size))
        except Exception:
            prev = b""
            addr += size
            continue
        idx = (prev + data).find(magic)
        if idx >= 0:
            return addr - len(prev) + idx
        prev = (prev + data)[-overlap:] if overlap else b""
        addr += size
    return None


async def read_rtt_log(probe_id: str = "default", timeout_seconds: int = 3,
                       channel: int = 0, rtt_address: int = 0) -> dict:
    """Read recent SEGGER RTT log output from the target (if RTT is running)."""
    ctx = get_context()
    async with ctx.lease.acquire(probe_id):
        try:
            # pyOCD exposes the channel based API in pyocd.debug.rtt; the old
            # pyocd.rtt.RTT facade module does not exist in any release.
            from pyocd.debug.rtt import RTTControlBlock

            s = _session(probe_id)
            t = s.target
            cb_addr = rtt_address or _find_rtt_control_block(t)
            if not cb_addr:
                return {"success": False,
                        "error": "SEGGER RTT control block not found in "
                                 "0x%08x-0x%08x; pass rtt_address if the RTT "
                                 "buffer lives elsewhere"
                                 % (_RTT_SCAN_BASE, _RTT_SCAN_BASE + _RTT_SCAN_SIZE)}

            cb = RTTControlBlock.from_target(t, address=cb_addr, size=0)
            cb.start()
            names = [c.name for c in cb.up_channels]
            if channel < 0 or channel >= len(cb.up_channels):
                return {"success": False,
                        "error": "up channel %d not found (have %d)" % (channel, len(names)),
                        "channels": names}

            ch = cb.up_channels[channel]
            chunks: List[bytes] = []
            deadline = time.monotonic() + max(0, timeout_seconds)
            while True:
                data = ch.read()
                if data:
                    chunks.append(data)
                if time.monotonic() >= deadline:
                    break
                await asyncio.sleep(0.05)

            raw = b"".join(chunks)
            return {"success": True,
                    "rtt_log": raw.decode("utf-8", errors="replace")[-4000:],
                    "bytes": len(raw),
                    "channel": channel,
                    "channels": names,
                    "control_block": "0x%08x" % cb_addr}
        except Exception as e:
            return {"success": False, "error": str(e)}
