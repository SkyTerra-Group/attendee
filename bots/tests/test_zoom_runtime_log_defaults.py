"""Bounded runtime failure output and native SDK initialization defaults."""

from contextlib import ExitStack
import logging
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, override_settings

from bots.tests.zoom_log_capture import CaptureConfiguredZoomLogBytes


class ZoomRuntimeLogDefaultsTests(SimpleTestCase):
    @override_settings(USE_REMOTE_STORAGE_FOR_AUDIO_CHUNKS=False)
    def test_main_loop_failure_has_bounded_configured_console_output(self):
        from bots.bot_controller.bot_controller import BotController

        controller = Mock(run_called=False)
        controller.end_bot_if_zoom_onbehalf_token_unavailable.return_value = False
        controller.pipeline_configuration = SimpleNamespace(rtmp_stream_audio=False, rtmp_stream_video=False)
        controller.should_create_gstreamer_pipeline.return_value = False
        controller.should_create_screen_and_audio_recorder.return_value = False
        controller.should_create_websocket_client_manager.return_value = False
        controller.bot_in_db.should_launch_webpage_streamer.return_value = False
        controller.bot_in_db.id = 918273645
        controller.pubsub_channel = 'synthetic-private-bot-channel'
        main_loop = Mock()
        main_loop.run.side_effect = RuntimeError('RAW_MEETING_CONTENT_FAILURE_CANARY')
        prefix = 'bots.bot_controller.bot_controller.'
        constructors = (
            'PerParticipantNonStreamingAudioInputManager',
            'PerParticipantStreamingAudioInputManager', 'GroupedClosedCaptionManager',
            'ClosedCaptionManager', 'AudioOutputManager', 'RealtimeAudioOutputManager',
            'VideoOutputManager', 'BotResourceSnapshotTaker', 'threading.Thread',
            'GLib.timeout_add', 'GLib.unix_signal_add',
        )
        with ExitStack() as stack:
            for name in constructors:
                stack.enter_context(patch(prefix + name))
            stack.enter_context(patch(prefix + 'GLib.MainLoop', return_value=main_loop))
            capture = stack.enter_context(CaptureConfiguredZoomLogBytes())
            BotController.run(controller)
            logging.getLogger('ordinary_runtime_control').warning('ordinary runtime diagnostic')

        controller.cleanup.assert_called_once_with()
        controller.pubsub.unsubscribe.assert_called_once_with(controller.pubsub_channel)
        self.assertTrue(controller.run_called)
        capture.assert_absent(self, 'RAW_MEETING_CONTENT_FAILURE_CANARY', '918273645')
        self.assertIn(b'runtime_main_loop_failed code=runtime_error', capture.bytes)
        self.assertIn(b'ordinary runtime diagnostic', capture.bytes)

    def test_native_init_disables_logs_and_dumps_preserving_success_and_failure(self):
        from bots.zoom_bot_adapter.zoom_bot_adapter import ZoomBotAdapter

        for succeeded in (True, False):
            with self.subTest(succeeded=succeeded):
                adapter = SimpleNamespace(create_services=Mock())
                parameters = SimpleNamespace()
                sdk = SimpleNamespace(
                    InitParam=Mock(return_value=parameters), SDKERR_SUCCESS=0,
                    InitSDK=Mock(return_value=0 if succeeded else 1),
                    SDK_LANGUAGE_ID=SimpleNamespace(LANGUAGE_English=1),
                )
                with patch('bots.zoom_bot_adapter.zoom_bot_adapter.zoom', sdk):
                    if succeeded:
                        ZoomBotAdapter.init(adapter)
                        adapter.create_services.assert_called_once_with()
                    else:
                        with self.assertRaisesRegex(Exception, '^InitSDK failed$'):
                            ZoomBotAdapter.init(adapter)
                        adapter.create_services.assert_not_called()
                sdk.InitSDK.assert_called_once_with(parameters)
                self.assertIs(parameters.enableLogByDefault, False)
                self.assertIs(parameters.enableGenerateDump, False)
                self.assertEqual(parameters.strWebDomain, 'https://zoom.us')
