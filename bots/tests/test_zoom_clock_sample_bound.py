"""SYNTHETIC clocks only: proves the per-sample bound, never live readiness.

Lockstep twin of the SkyTerra Client tests/test_zoom_clock_sample_bound.py.
"""
import itertools
from datetime import datetime, timedelta, timezone
from unittest import TestCase

from bots import zoom_clock_sample as cs

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
BASE_US = 1_792_000_000_000_000  # 2026-10 in microseconds
POLICY = cs.SourcePolicy('bound_test_src', 1000, 1000)


class Fixed(cs.LocalProbe):
    """Two exact readings rtt apart; synthetic kernel bound."""
    def __init__(self, maxerror_us, w0_us, rtt_us):
        self.k, self.w0_us, self.rtt_us, self.calls = cs.Kernel(0, 0x2001, maxerror_us), w0_us, rtt_us, 0

    def kernel(self):
        return self.k

    def clocks(self):
        t = (self.w0_us + (self.rtt_us if self.calls else 0)) * 1000
        self.calls += 1
        return t, t, t


def run(maxerror_us, app_offset_us, db_offset_us, rtt_us, frac):
    true_start = BASE_US
    true_query = true_start + int(rtt_us * frac)
    stamp = EPOCH + timedelta(microseconds=true_query + db_offset_us)
    probe = Fixed(maxerror_us, true_start + app_offset_us, rtt_us)
    return cs.sample(lambda: stamp, POLICY, probe), abs(db_offset_us)


class SampleBoundTests(TestCase):
    def test_bound_holds_for_db_offsets_inside_and_outside_the_bracket(self):
        checked = outside = 0
        for e, a_frac, d, rtt, frac in itertools.product(
                (1_979, 120_793, 300_000), (-1, -0.5, 0, 0.5, 1),
                (-50_000, -5_000, -2_000, -1, 0, 1, 2_000, 5_000, 50_000), (200, 1_000, 25_000), (0, 0.5, 1)):
            a = int(e * a_frac)
            measured, true_error_us = run(e, a, d, rtt, frac)
            assert true_error_us <= measured.error_ms * 1000
            lower, upper = BASE_US + a - e, BASE_US + a + rtt + e
            stamp = BASE_US + int(rtt * frac) + d
            outside += not lower <= stamp <= upper
            checked += 1
        assert checked == 1215 and outside > 0  # the formerly rejected region is exercised


    def test_small_database_offset_is_charged_not_rejected(self):
        # Render Client staging 2026-10-19: maxerror 1979 us, database about -2 ms.
        measured, _ = run(1_979, 0, -2_000 - 1_979 - 1, 1_000, 0)
        assert measured.error_ms <= 8


    def test_large_database_offset_fails_the_bound(self):
        with self.assertRaisesRegex(cs.ClockRejected, 'clock_bound_excessive'):
            run(1_979, 0, -5_000_000, 1_000, 0.5)


    def test_containment_never_guaranteed_a_dishonest_kernel_bound(self):
        # Trust root is the kernel's maxerror. If the host is really 10 ms off while
        # claiming 2 ms and the database is off the same way, V sits inside the old
        # bracket (old check passed) and the bound is wrong either way: containment
        # was a heuristic, not a guarantee, so dropping it loses no proven property.
        e, a, d, rtt = 2_000, 10_000, 10_000, 500
        stamp = BASE_US + d
        assert BASE_US + a - e <= stamp <= BASE_US + a + rtt + e
        measured, true_error_us = run(e, a, d, rtt, 0)
        assert true_error_us > measured.error_ms * 1000
