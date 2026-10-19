"""Operation-coupled, independently UTC-bounded database timestamp samples.

Each sample bounds ONE database instant. It is a measurement policy, not a
claim that any clock is continuous or step-free between samples. No API input
can supply a trusted value: only the local kernel, local clocks and the exact
database connection of the calling transaction are read. Nothing is written
to the kernel (adjtimex modes=0 is query-only) and no background service runs.
"""
from __future__ import annotations

import ctypes
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone

MEASUREMENT_POLICY = 'operation-sampled-utc-bound-v1'
MOVEMENT_TOLERANCE_NS = 2_000_000
_STA_UNSYNC, _STA_CLOCKERR, _TIME_OK = 0x0040, 0x1000, 0
_SAFE = re.compile(r'[A-Za-z0-9._:/-]{1,64}', re.ASCII)


class ClockRejected(ValueError):
    """Fixed bounded code; the sample is unusable for fresh admission."""


def _reject(code):
    raise ClockRejected(code) from None


class _Timex(ctypes.Structure):
    # Linux/glibc LP64 layout (bits/timex.h); other ABIs are rejected below.
    _fields_ = [('modes', ctypes.c_uint)] + [
        (n, ctypes.c_long) for n in ('offset', 'freq', 'maxerror', 'esterror')
    ] + [('status', ctypes.c_int)] + [
        (n, ctypes.c_long) for n in
        ('constant', 'precision', 'tolerance', 'time_sec', 'time_usec', 'tick', 'ppsfreq', 'jitter')
    ] + [('shift', ctypes.c_int)] + [
        (n, ctypes.c_long) for n in ('stabil', 'jitcnt', 'calcnt', 'errcnt', 'stbcnt')
    ] + [('tai', ctypes.c_int), ('reserved', ctypes.c_int * 11)]


@dataclass(frozen=True)
class Kernel:
    state: int
    status: int
    maxerror_us: int


class LocalProbe:
    """Real local evidence. Tests may substitute a probe only to prove rejection."""

    def kernel(self):
        if ctypes.sizeof(ctypes.c_long) != 8 or ctypes.sizeof(_Timex) != 208:
            _reject('clock_syscall_unavailable')
        try:
            function = ctypes.CDLL(None, use_errno=True).adjtimex
        except (OSError, AttributeError):
            _reject('clock_syscall_unavailable')
        function.argtypes, function.restype = [ctypes.POINTER(_Timex)], ctypes.c_int
        value = _Timex()  # zero-initialized: modes=0 is query-only
        state = function(ctypes.byref(value))
        if state < 0:
            _reject('clock_syscall_unavailable')
        return Kernel(state=state, status=value.status, maxerror_us=value.maxerror)

    def clocks(self):
        # CLOCK_BOOTTIME advances across suspend; CLOCK_MONOTONIC does not.
        return (time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.monotonic_ns(), time.time_ns())


@dataclass(frozen=True)
class SourcePolicy:
    source_policy_id: str
    max_sample_error_ms: int
    max_rtt_ms: int

    @classmethod
    def from_settings(cls):
        """None when no approved source policy is configured (fail closed)."""
        from django.conf import settings

        values = (getattr(settings, "ZOOM_DEAUTH_CLOCK_SOURCE_POLICY_ID", ""),
                  getattr(settings, "ZOOM_DEAUTH_CLOCK_MAX_SAMPLE_ERROR_MS", ""),
                  getattr(settings, "ZOOM_DEAUTH_CLOCK_MAX_RTT_MS", ""))
        if (type(values[0]) is not str or not _SAFE.fullmatch(values[0])
                or any(type(v) is not str or not re.fullmatch(r"[0-9]{1,4}", v) for v in values[1:])):
            return None
        policy = cls(values[0], int(values[1]), int(values[2]))
        return policy if valid_policy(policy) else None


def valid_policy(policy):
    return (type(policy) is SourcePolicy and type(policy.source_policy_id) is str
            and _SAFE.fullmatch(policy.source_policy_id) is not None
            and type(policy.max_sample_error_ms) is int and 1 <= policy.max_sample_error_ms <= 1000
            and type(policy.max_rtt_ms) is int and 1 <= policy.max_rtt_ms <= 1000)


@dataclass(frozen=True)
class Sample:
    db_at: datetime  # the exact sampled database timestamp (UTC)
    error_ms: int    # conservative ceil bound on |db_at - true UTC|
    rtt_us: int
    source_policy_id: str
    measurement_policy: str = MEASUREMENT_POLICY


def _healthy(kernel):
    return (type(kernel) is Kernel and kernel.state == _TIME_OK
            and not kernel.status & (_STA_UNSYNC | _STA_CLOCKERR)
            and type(kernel.maxerror_us) is int and kernel.maxerror_us >= 0)


def sample(query, policy, probe=None):
    """Bracket ``query()`` (``SELECT clock_timestamp()`` on the caller's exact
    connection/transaction) with local kernel and clock evidence at both ends.

    Byte-for-byte the same algorithm as the SkyTerra client module; keep the
    two in lockstep (only the policy source differs)."""
    if not valid_policy(policy):
        _reject('clock_source_unapproved')
    probe = probe or LocalProbe()
    k0 = probe.kernel()
    b0, m0, w0 = probe.clocks()
    value = query()
    b1, m1, w1 = probe.clocks()
    k1 = probe.kernel()
    if not (_healthy(k0) and _healthy(k1)):
        _reject('clock_unsynchronized')
    mono = m1 - m0
    if mono < 0 or abs((w1 - w0) - mono) > MOVEMENT_TOLERANCE_NS or abs((b1 - b0) - mono) > MOVEMENT_TOLERANCE_NS:
        _reject('clock_local_movement')
    if mono > policy.max_rtt_ms * 1_000_000:
        _reject('clock_latency_excessive')
    if type(value) is not datetime or value.tzinfo is None:
        _reject('clock_db_invalid')
    db_at = value.astimezone(timezone.utc)
    # Exact integer microseconds; no float rounding inside the bound.
    delta = db_at - datetime(1970, 1, 1, tzinfo=timezone.utc)
    stamp_us = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    maxerr = max(k0.maxerror_us, k1.maxerror_us)
    lower_us, upper_us = w0 // 1000 - maxerr, -(-w1 // 1000) + maxerr
    if not lower_us <= stamp_us <= upper_us:
        _reject('clock_bracket_violation')
    error_ms = -(-max(stamp_us - lower_us, upper_us - stamp_us) // 1000) + 1
    if error_ms > policy.max_sample_error_ms:
        _reject('clock_bound_excessive')
    return Sample(db_at=db_at, error_ms=error_ms, rtt_us=mono // 1000,
                  source_policy_id=policy.source_policy_id)
