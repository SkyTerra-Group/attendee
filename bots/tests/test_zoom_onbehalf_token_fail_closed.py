"""
SkyTerra: a Zoom bot created with zoom_settings.onbehalf_token must never join without that token.

Upstream turns every failure to get the onbehalf (OBF) token into "no token" and the bot then joins
anonymously. These tests pin the fork's behavior: the bot is ended with a terminal event that says
why, before any pipeline, Redis subscription or adapter exists, so no join is ever attempted. Bots
that did not ask for an onbehalf token go down exactly the same path as before.
"""

from datetime import timedelta
from unittest.mock import Mock, patch

from django.test import TestCase, tag
from django.utils import timezone

from accounts.models import Organization
from bots.bot_controller import BotController
from bots.models import (
    Bot,
    BotEventManager,
    BotEventSubTypes,
    BotEventTypes,
    BotStates,
    Project,
    Recording,
    RecordingTypes,
    TranscriptionProviders,
    TranscriptionTypes,
    WebhookDeliveryAttempt,
    WebhookSubscription,
    WebhookTriggerTypes,
    ZoomOAuthApp,
    ZoomOAuthConnection,
    ZoomOAuthConnectionStates,
)
from bots.zoom_oauth_connections_utils import get_zoom_tokens_via_zoom_oauth_app

MEETING_URL = "https://zoom.us/j/123456789?pwd=password123"


class StopRunHere(Exception):
    """Raised from a patched step to stop BotController.run() once it is past the onbehalf check."""


@tag("zoom_tests")
class TestZoomOnbehalfTokenFailClosed(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Test Org")
        self.project = Project.objects.create(name="Test Project", organization=self.organization)

        self.zoom_oauth_app = ZoomOAuthApp.objects.create(project=self.project, client_id="test_client_id")
        self.zoom_oauth_app.set_credentials({"client_secret": "test_secret"})

        # The capabilities SkyTerra creates its connections with: onbehalf only.
        self.zoom_oauth_connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_oauth_app,
            user_id="obf_user_id",
            account_id="test_account_id",
            is_local_recording_token_supported=False,
            is_onbehalf_token_supported=True,
            state=ZoomOAuthConnectionStates.CONNECTED,
        )
        self.zoom_oauth_connection.set_credentials({"refresh_token": "test_refresh_token"})

        WebhookSubscription.objects.create(project=self.project, url="https://example.com/webhook", triggers=[WebhookTriggerTypes.BOT_STATE_CHANGE])

        self.requested_zoom_api_urls = []

    # ---- helpers -------------------------------------------------------------------------------

    def _bot_settings(self, onbehalf_user_id=None, extra=None):
        settings = {"zoom_settings": {"sdk": "native"}}
        if onbehalf_user_id:
            settings["zoom_settings"]["onbehalf_token"] = {"zoom_oauth_connection_user_id": onbehalf_user_id}
        settings.update(extra or {})
        return settings

    def _create_bot(self, settings, meeting_url=MEETING_URL):
        bot = Bot.objects.create(project=self.project, name="Test Bot", meeting_url=meeting_url, settings=settings)
        Recording.objects.create(
            bot=bot,
            recording_type=RecordingTypes.AUDIO_ONLY,
            transcription_type=TranscriptionTypes.NON_REALTIME,
            transcription_provider=TranscriptionProviders.DEEPGRAM,
            is_default_recording=True,
        )
        return bot

    def _create_joining_bot(self, settings, meeting_url=MEETING_URL):
        # What the API does for an ad hoc bot (no join_at): READY -> JOINING, then the worker runs it.
        bot = self._create_bot(settings, meeting_url=meeting_url)
        BotEventManager.create_event(bot, BotEventTypes.JOIN_REQUESTED)
        return bot

    def _create_staged_bot(self, settings):
        bot = self._create_bot(settings)
        join_at = timezone.now() + timedelta(minutes=5)
        bot.state = BotStates.SCHEDULED
        bot.join_at = join_at
        bot.save()
        BotEventManager.create_event(bot=bot, event_type=BotEventTypes.STAGED, event_metadata={"join_at": join_at.isoformat()})
        return bot

    def _mock_zoom(self, mock_post, mock_session, onbehalf_token=None, fail=False):
        token_response = Mock()
        token_response.json.return_value = {"access_token": "mock_access_token"}
        token_response.raise_for_status.return_value = None
        mock_post.return_value = token_response

        def send(request, **kwargs):
            self.requested_zoom_api_urls.append(request.url)
            if fail:
                raise ConnectionError("Zoom API unreachable")
            response = Mock()
            response.raise_for_status.return_value = None
            response.json.return_value = {"token": onbehalf_token}
            return response

        mock_session.return_value.__enter__ = Mock(return_value=mock_session.return_value)
        mock_session.return_value.__exit__ = Mock(return_value=False)
        mock_session.return_value.send = send

    def _last_event(self, bot):
        return bot.bot_events.order_by("-created_at", "-id").first()

    # ---- acceptance 1: onbehalf requested, token fetch fails -> fatal state, no join attempt ----

    @patch("bots.bot_controller.bot_controller.GLib.MainLoop")
    @patch("bots.bot_controller.bot_controller.GstreamerPipeline")
    @patch("bots.zoom_bot_adapter.ZoomBotAdapter")
    @patch.object(BotController, "connect_to_redis")
    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_onbehalf_bot_ends_in_fatal_state_and_never_joins_when_token_fetch_fails(self, mock_post, mock_session, mock_connect_to_redis, MockZoomBotAdapter, MockGstreamerPipeline, MockMainLoop):
        bot = self._create_joining_bot(self._bot_settings(onbehalf_user_id="obf_user_id"))
        self._mock_zoom(mock_post, mock_session, fail=True)

        controller = BotController(bot.id)
        controller.run()

        # Terminal state, with a reason a caller can act on.
        bot.refresh_from_db()
        self.assertEqual(bot.state, BotStates.FATAL_ERROR)
        event = self._last_event(bot)
        self.assertEqual(event.event_type, BotEventTypes.COULD_NOT_JOIN)
        self.assertEqual(event.event_sub_type, BotEventSubTypes.COULD_NOT_JOIN_MEETING_ZOOM_AUTHORIZATION_FAILED)
        self.assertEqual(event.metadata["reason"], "onbehalf_token_unavailable")
        self.assertEqual(event.metadata["onbehalf_token_failure_reason"], "zoom_api_error")
        self.assertIn("did not join", event.metadata["message"])

        # The webhook the app receives carries the same reason.
        delivery = WebhookDeliveryAttempt.objects.filter(bot=bot).order_by("-id").first()
        self.assertEqual(delivery.payload["event_type"], "could_not_join_meeting")
        self.assertEqual(delivery.payload["event_sub_type"], "zoom_authorization_failed")
        self.assertEqual(delivery.payload["new_state"], "fatal_error")
        self.assertEqual(delivery.payload["event_metadata"]["reason"], "onbehalf_token_unavailable")

        # No join attempt: no adapter was built, so the Zoom SDK was never initialised or asked to join,
        # and nothing that runs a meeting (Redis subscription, media pipeline, main loop) was started.
        MockZoomBotAdapter.assert_not_called()
        mock_connect_to_redis.assert_not_called()
        MockGstreamerPipeline.assert_not_called()
        MockMainLoop.assert_not_called()
        self.assertFalse(hasattr(controller, "adapter"))

        # The only Zoom API call was the onbehalf token request itself.
        self.assertEqual(len(self.requested_zoom_api_urls), 1)
        self.assertIn("token?type=onbehalf", self.requested_zoom_api_urls[0])

    @patch("bots.zoom_bot_adapter.ZoomBotAdapter")
    @patch.object(BotController, "connect_to_redis")
    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_onbehalf_bot_for_a_user_who_never_connected_ends_without_any_zoom_call(self, mock_post, mock_session, mock_connect_to_redis, MockZoomBotAdapter):
        bot = self._create_joining_bot(self._bot_settings(onbehalf_user_id="someone_who_never_connected"))

        BotController(bot.id).run()

        bot.refresh_from_db()
        self.assertEqual(bot.state, BotStates.FATAL_ERROR)
        self.assertEqual(self._last_event(bot).metadata["onbehalf_token_failure_reason"], "zoom_oauth_connection_not_found")
        mock_post.assert_not_called()
        mock_session.assert_not_called()
        MockZoomBotAdapter.assert_not_called()
        mock_connect_to_redis.assert_not_called()

    @patch("bots.zoom_bot_adapter.ZoomBotAdapter")
    @patch.object(BotController, "connect_to_redis")
    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_staged_onbehalf_bot_ends_with_a_fatal_error_event(self, mock_post, mock_session, mock_connect_to_redis, MockZoomBotAdapter):
        """A scheduled bot is still STAGED when its tokens are fetched; COULD_NOT_JOIN is not valid there."""
        bot = self._create_staged_bot(self._bot_settings(onbehalf_user_id="obf_user_id"))
        self._mock_zoom(mock_post, mock_session, fail=True)

        BotController(bot.id).run()

        bot.refresh_from_db()
        self.assertEqual(bot.state, BotStates.FATAL_ERROR)
        event = self._last_event(bot)
        self.assertEqual(event.event_type, BotEventTypes.FATAL_ERROR)
        self.assertEqual(event.event_sub_type, BotEventSubTypes.FATAL_ERROR_ATTENDEE_INTERNAL_ERROR)
        self.assertEqual(event.metadata["reason"], "onbehalf_token_unavailable")
        MockZoomBotAdapter.assert_not_called()
        mock_connect_to_redis.assert_not_called()

    @patch("bots.zoom_bot_adapter.ZoomBotAdapter")
    @patch.object(BotController, "connect_to_redis")
    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_onbehalf_bot_in_a_state_with_no_valid_failure_event_still_never_joins(self, mock_post, mock_session, mock_connect_to_redis, MockZoomBotAdapter):
        bot = self._create_joining_bot(self._bot_settings(onbehalf_user_id="obf_user_id"))
        # e.g. the bot was ended by someone else while the worker was picking it up.
        BotEventManager.create_event(bot, BotEventTypes.COULD_NOT_JOIN, event_sub_type=BotEventSubTypes.COULD_NOT_JOIN_MEETING_REQUEST_TO_JOIN_DENIED)
        events_before = bot.bot_events.count()
        self._mock_zoom(mock_post, mock_session, fail=True)

        BotController(bot.id).run()

        bot.refresh_from_db()
        self.assertEqual(bot.state, BotStates.FATAL_ERROR)
        self.assertEqual(bot.bot_events.count(), events_before)
        MockZoomBotAdapter.assert_not_called()
        mock_connect_to_redis.assert_not_called()

    # ---- onbehalf requested and the token is there: the bot carries on, with one fetch ----------

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_onbehalf_bot_with_a_token_continues_and_fetches_it_only_once(self, mock_post, mock_session):
        bot = self._create_joining_bot(self._bot_settings(onbehalf_user_id="obf_user_id"))
        self._mock_zoom(mock_post, mock_session, onbehalf_token="onbehalf_token_456")

        controller = BotController(bot.id)
        with patch.object(BotController, "connect_to_redis", side_effect=StopRunHere):
            with self.assertRaises(StopRunHere):
                controller.run()

        # It went past the check into the normal path, with the token in hand.
        self.assertEqual(controller.prefetched_zoom_tokens["onbehalf_token"], "onbehalf_token_456")
        self.assertEqual(controller.get_zoom_tokens()["onbehalf_token"], "onbehalf_token_456")
        self.assertEqual(len(self.requested_zoom_api_urls), 1)
        bot.refresh_from_db()
        self.assertEqual(bot.state, BotStates.JOINING)

    # ---- acceptance 2: bots without onbehalf behave exactly as before ----------------------------

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_zoom_bot_without_onbehalf_goes_down_the_unchanged_path(self, mock_post, mock_session):
        bot = self._create_joining_bot(self._bot_settings(onbehalf_user_id=None))

        controller = BotController(bot.id)
        self.assertFalse(controller.zoom_onbehalf_token_was_requested())
        with patch.object(BotController, "connect_to_redis", side_effect=StopRunHere) as mock_connect_to_redis:
            with self.assertRaises(StopRunHere):
                controller.run()

        # Nothing was fetched early and nothing was recorded: run() reached its first upstream step as before.
        mock_connect_to_redis.assert_called_once()
        self.assertIsNone(controller.prefetched_zoom_tokens)
        mock_post.assert_not_called()
        mock_session.assert_not_called()
        bot.refresh_from_db()
        self.assertEqual(bot.state, BotStates.JOINING)
        self.assertEqual(self._last_event(bot).event_type, BotEventTypes.JOIN_REQUESTED)

        # And the tokens it gets later are exactly what the upstream lookup returns.
        self.assertEqual(controller.get_zoom_tokens(), get_zoom_tokens_via_zoom_oauth_app(bot))
        self.assertEqual(controller.get_zoom_tokens(), {"zak_token": None, "join_token": None, "app_privilege_token": None, "onbehalf_token": None})

    def test_non_zoom_bots_never_take_the_onbehalf_path(self):
        teams_bot = self._create_joining_bot(
            self._bot_settings(onbehalf_user_id="obf_user_id"),
            meeting_url="https://teams.microsoft.com/l/meetup-join/19%3ameeting_abc%40thread.v2/0?context=%7b%22Tid%22%3a%22t%22%2c%22Oid%22%3a%22o%22%7d",
        )
        self.assertFalse(BotController(teams_bot.id).zoom_onbehalf_token_was_requested())

    def test_tokens_from_a_customer_callback_are_left_alone(self):
        bot = self._create_joining_bot(self._bot_settings(onbehalf_user_id="obf_user_id", extra={"callback_settings": {"zoom_tokens_url": "https://example.com/zoom-tokens"}}))
        self.assertFalse(BotController(bot.id).zoom_onbehalf_token_was_requested())
