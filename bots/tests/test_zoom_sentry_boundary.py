"""Real SDK, fresh process, memory-only transport; no credentials or network."""

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROBE = r'''
import io, json, logging, os
from unittest.mock import patch
import sentry_sdk
from sentry_sdk.transport import Transport
from attendee.sentry import init_sentry
from attendee.logging import ZoomTrustBoundaryRedactionFilter

envelopes = []
initializations = []
class MemoryOnly(Transport):
    def capture_envelope(self, envelope):
        envelopes.append(envelope.serialize().decode('utf-8', errors='replace'))
original_init = sentry_sdk.init
def memory_init(**kwargs):
    initializations.append(True)
    kwargs.update(transport=MemoryOnly, traces_sample_rate=0, profiles_sample_rate=0)
    return original_init(**kwargs)

startup_output = io.StringIO()
startup_logger = logging.getLogger('attendee.sentry')
startup_logger.handlers = [logging.StreamHandler(startup_output)]
startup_logger.propagate = False
with patch.object(sentry_sdk, 'init', side_effect=memory_init):
    init_sentry()
    init_sentry()  # Repeated settings/application startup must also stay closed.
    sentry_sdk.add_breadcrumb(message='RAW_ZOOM_BREADCRUMB_CANARY')
    with sentry_sdk.new_scope() as scope:
        scope.set_context('synthetic_request', {'query': 'RAW_ZOOM_QUERY_CANARY'})
        try:
            raise RuntimeError('RAW_ZOOM_CONTENT_CANARY')
        except RuntimeError:
            event_id = sentry_sdk.capture_exception()
    sentry_sdk.capture_message('RAW_ZOOM_MESSAGE_CANARY')
    sentry_sdk.flush()

output = io.StringIO()
handler = logging.StreamHandler(output)
handler.addFilter(ZoomTrustBoundaryRedactionFilter())
ordinary = logging.getLogger('ordinary_diagnostic_control')
ordinary.handlers = [handler]
ordinary.propagate = False
ordinary.warning('ordinary diagnostic remains available')
print(json.dumps({'initializations': len(initializations),
                  'envelopes': len(envelopes),
                  'raw_marker_present': 'RAW_ZOOM_' in ''.join(envelopes),
                  'event_id': event_id,
                  'disabled_diagnostic_present':
                      'sentry_telemetry_disabled code=zoom_sensitive_service' in startup_output.getvalue(),
                  'ordinary_diagnostic_preserved':
                      'ordinary diagnostic remains available' in output.getvalue()}))
'''


class ZoomSentryBoundaryTests(unittest.TestCase):
    def test_sdk_cannot_emit_even_with_dsn_and_sensitive_settings_enabled(self):
        for pii in ('false', 'true'):
            with self.subTest(send_pii=pii):
                result = self._probe({
                    'SENTRY_DSN': 'http://synthetic@example.invalid/1',
                    'SENTRY_SEND_PII': pii,
                    'SENTRY_TRACES_SAMPLE_RATE': '1',
                    'SENTRY_PROFILES_SAMPLE_RATE': '1',
                })
                self.assertEqual(result['initializations'], 0)
                self.assertEqual(result['envelopes'], 0)
                self.assertFalse(result['raw_marker_present'])
                self.assertIsNone(result['event_id'])
                self.assertTrue(result['disabled_diagnostic_present'])
                self.assertTrue(result['ordinary_diagnostic_preserved'])

    def test_no_dsn_remains_no_telemetry(self):
        result = self._probe({'SENTRY_DSN': ''})
        self.assertEqual(result['initializations'], 0)
        self.assertEqual(result['envelopes'], 0)
        self.assertTrue(result['ordinary_diagnostic_preserved'])

    @staticmethod
    def _probe(settings):
        completed = subprocess.run(
            [sys.executable, '-c', PROBE], cwd=ROOT,
            env={**os.environ, **settings, 'PYTHONDONTWRITEBYTECODE': '1'},
            capture_output=True, text=True, timeout=30, check=True,
        )
        return json.loads(completed.stdout.strip().splitlines()[-1])
