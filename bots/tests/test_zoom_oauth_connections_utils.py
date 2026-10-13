from unittest.mock import Mock, patch

from django.test import TestCase

from accounts.models import Organization
from bots.models import (
    Bot,
    Project,
    ZoomMeetingToZoomOAuthConnectionMapping,
    ZoomOAuthApp,
    ZoomOAuthConnection,
    ZoomOAuthConnectionStates,
)
from bots.zoom_oauth_connections_utils import (
    ONBEHALF_TOKEN_FAILURE_CONNECTION_DOES_NOT_SUPPORT_ONBEHALF_TOKENS,
    ONBEHALF_TOKEN_FAILURE_CONNECTION_NOT_FOUND,
    ONBEHALF_TOKEN_FAILURE_NO_MEETING_ID,
    ONBEHALF_TOKEN_FAILURE_NO_ZOOM_OAUTH_APP,
    ONBEHALF_TOKEN_FAILURE_ZOOM_API_AUTHENTICATION_ERROR,
    ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR,
    ONBEHALF_TOKEN_FAILURE_ZOOM_API_RETURNED_NO_TOKEN,
    ZoomAPIAuthenticationError,
    ZoomOnbehalfTokenUnavailableError,
    _handle_zoom_api_authentication_error,
    compute_zoom_webhook_validation_response,
    get_onbehalf_token_via_zoom_oauth_app,
    get_zoom_tokens_via_zoom_oauth_app,
)


class TestComputeZoomWebhookValidationResponse(TestCase):
    """Test the compute_zoom_webhook_validation_response function."""

    def test_returns_correct_format(self):
        """Test that the response has correct format."""
        plain_token = "test_plain_token"
        secret_token = "test_secret_token"

        result = compute_zoom_webhook_validation_response(plain_token, secret_token)

        self.assertIn("plainToken", result)
        self.assertIn("encryptedToken", result)
        self.assertEqual(result["plainToken"], plain_token)

    def test_encrypted_token_is_correct_hmac(self):
        """Test that the encrypted token is correctly computed."""
        import hashlib
        import hmac

        plain_token = "qgg8vlvZRS6UYooatFL8Aw"
        secret_token = "my_webhook_secret"

        result = compute_zoom_webhook_validation_response(plain_token, secret_token)

        # Compute expected value
        expected_hash = hmac.new(secret_token.encode("utf-8"), plain_token.encode("utf-8"), hashlib.sha256).hexdigest()

        self.assertEqual(result["encryptedToken"], expected_hash)

    def test_different_tokens_produce_different_results(self):
        """Test that different plain tokens produce different encrypted tokens."""
        secret_token = "test_secret"

        result1 = compute_zoom_webhook_validation_response("token1", secret_token)
        result2 = compute_zoom_webhook_validation_response("token2", secret_token)

        self.assertNotEqual(result1["encryptedToken"], result2["encryptedToken"])

    def test_different_secrets_produce_different_results(self):
        """Test that different secrets produce different encrypted tokens."""
        plain_token = "test_token"

        result1 = compute_zoom_webhook_validation_response(plain_token, "secret1")
        result2 = compute_zoom_webhook_validation_response(plain_token, "secret2")

        self.assertNotEqual(result1["encryptedToken"], result2["encryptedToken"])


class TestHandleZoomApiAuthenticationError(TestCase):
    """Test the _handle_zoom_api_authentication_error function."""

    def setUp(self):
        self.organization = Organization.objects.create(name="Test Org")
        self.project = Project.objects.create(name="Test Project", organization=self.organization)
        self.zoom_oauth_app = ZoomOAuthApp.objects.create(project=self.project, client_id="test_client_id")
        self.zoom_oauth_app.set_credentials({"client_secret": "test_secret"})
        self.zoom_oauth_connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_oauth_app,
            user_id="test_user_id",
            account_id="test_account_id",
            state=ZoomOAuthConnectionStates.CONNECTED,
        )

    @patch("bots.zoom_oauth_connections_utils.trigger_webhook")
    def test_sets_state_to_disconnected(self, mock_trigger_webhook):
        """Test that authentication error sets connection state to DISCONNECTED."""
        error = ZoomAPIAuthenticationError("Invalid credentials")

        _handle_zoom_api_authentication_error(self.zoom_oauth_connection, error)

        self.zoom_oauth_connection.refresh_from_db()
        self.assertEqual(self.zoom_oauth_connection.state, ZoomOAuthConnectionStates.DISCONNECTED)

    @patch("bots.zoom_oauth_connections_utils.trigger_webhook")
    def test_sets_connection_failure_data(self, mock_trigger_webhook):
        """Test that authentication error sets connection failure data."""
        error = ZoomAPIAuthenticationError("Invalid credentials")

        _handle_zoom_api_authentication_error(self.zoom_oauth_connection, error)

        self.zoom_oauth_connection.refresh_from_db()
        self.assertIsNotNone(self.zoom_oauth_connection.connection_failure_data)
        self.assertIn("error", self.zoom_oauth_connection.connection_failure_data)
        self.assertIn("Invalid credentials", self.zoom_oauth_connection.connection_failure_data["error"])
        self.assertIn("timestamp", self.zoom_oauth_connection.connection_failure_data)

    @patch("bots.zoom_oauth_connections_utils.trigger_webhook")
    def test_triggers_webhook(self, mock_trigger_webhook):
        """Test that authentication error triggers a webhook."""
        error = ZoomAPIAuthenticationError("Invalid credentials")

        _handle_zoom_api_authentication_error(self.zoom_oauth_connection, error)

        mock_trigger_webhook.assert_called_once()

    @patch("bots.zoom_oauth_connections_utils.trigger_webhook")
    def test_skips_if_already_disconnected(self, mock_trigger_webhook):
        """Test that no action is taken if connection is already disconnected."""
        self.zoom_oauth_connection.state = ZoomOAuthConnectionStates.DISCONNECTED
        self.zoom_oauth_connection.save()

        error = ZoomAPIAuthenticationError("Invalid credentials")

        _handle_zoom_api_authentication_error(self.zoom_oauth_connection, error)

        # Should not trigger webhook since already disconnected
        mock_trigger_webhook.assert_not_called()

        # State should remain disconnected
        self.zoom_oauth_connection.refresh_from_db()
        self.assertEqual(self.zoom_oauth_connection.state, ZoomOAuthConnectionStates.DISCONNECTED)


class TestGetZoomTokensViaZoomOAuthApp(TestCase):
    """Test the get_zoom_tokens_via_zoom_oauth_app function."""

    def setUp(self):
        self.organization = Organization.objects.create(name="Test Org")
        self.project = Project.objects.create(name="Test Project", organization=self.organization)

        # Create ZoomOAuthApp with credentials
        self.zoom_oauth_app = ZoomOAuthApp.objects.create(project=self.project, client_id="test_client_id")
        self.zoom_oauth_app.set_credentials({"client_secret": "test_secret"})

        # Create ZoomOAuthConnection with credentials
        self.zoom_oauth_connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_oauth_app,
            user_id="test_user_id",
            account_id="test_account_id",
            is_local_recording_token_supported=True,
            is_onbehalf_token_supported=True,
        )
        self.zoom_oauth_connection.set_credentials({"refresh_token": "test_refresh_token"})

        # Create meeting mapping for local recording token lookup
        self.meeting_id = "1234567890"
        ZoomMeetingToZoomOAuthConnectionMapping.objects.create(
            zoom_oauth_app=self.zoom_oauth_app,
            zoom_oauth_connection=self.zoom_oauth_connection,
            meeting_id=self.meeting_id,
        )

    def _create_bot(self, use_web_adapter=False, onbehalf_user_id=None):
        """Helper to create a bot with specific settings."""
        settings = {"zoom_settings": {"sdk": "web" if use_web_adapter else "native"}}
        if onbehalf_user_id:
            settings["zoom_settings"]["onbehalf_token"] = {"zoom_oauth_connection_user_id": onbehalf_user_id}
        return Bot.objects.create(
            project=self.project,
            meeting_url=f"https://zoom.us/j/{self.meeting_id}",
            settings=settings,
        )

    def _mock_zoom_api_responses(self, mock_post, mock_session, local_recording_token=None, onbehalf_token=None):
        """Helper to set up mock responses for Zoom API calls."""
        # Mock token refresh response
        mock_token_response = Mock()
        mock_token_response.json.return_value = {"access_token": "mock_access_token"}
        mock_token_response.raise_for_status.return_value = None
        mock_post.return_value = mock_token_response

        # Mock API responses for local recording and onbehalf tokens
        def mock_send(request, **kwargs):
            response = Mock()
            response.raise_for_status.return_value = None
            if "local_recording" in request.url:
                response.json.return_value = {"token": local_recording_token}
            elif "token?type=onbehalf" in request.url:
                response.json.return_value = {"token": onbehalf_token}
            return response

        mock_session.return_value.__enter__ = Mock(return_value=mock_session.return_value)
        mock_session.return_value.__exit__ = Mock(return_value=False)
        mock_session.return_value.send = mock_send

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_returns_local_recording_token_when_no_onbehalf_configured(self, mock_post, mock_session):
        """Test that local recording token is fetched when no onbehalf token is configured."""
        bot = self._create_bot(use_web_adapter=False, onbehalf_user_id=None)
        self._mock_zoom_api_responses(mock_post, mock_session, local_recording_token="local_rec_token_123")

        result = get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(result["app_privilege_token"], "local_rec_token_123")
        self.assertIsNone(result["onbehalf_token"])

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_returns_both_tokens_when_using_web_adapter(self, mock_post, mock_session):
        """Test that both tokens are fetched when using web adapter."""
        bot = self._create_bot(use_web_adapter=True, onbehalf_user_id="test_user_id")
        self._mock_zoom_api_responses(mock_post, mock_session, local_recording_token="local_rec_token_123", onbehalf_token="onbehalf_token_456")

        result = get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(result["app_privilege_token"], "local_rec_token_123")
        self.assertEqual(result["onbehalf_token"], "onbehalf_token_456")

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_returns_both_tokens_when_using_native_adapter(self, mock_post, mock_session):
        """Test that both tokens are fetched when using native adapter."""
        bot = self._create_bot(use_web_adapter=False, onbehalf_user_id="test_user_id")
        self._mock_zoom_api_responses(mock_post, mock_session, local_recording_token="local_rec_token_123", onbehalf_token="onbehalf_token_456")

        result = get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(result["app_privilege_token"], "local_rec_token_123")
        self.assertEqual(result["onbehalf_token"], "onbehalf_token_456")


class TestGetZoomTokensFailsClosedForOnbehalfBots(TestCase):
    """SkyTerra: a bot created with zoom_settings.onbehalf_token never gets a token set without an onbehalf token."""

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
        self.meeting_id = "1234567890"

    def _create_bot(self, onbehalf_user_id=None, meeting_url=None):
        settings = {"zoom_settings": {"sdk": "native"}}
        if onbehalf_user_id:
            settings["zoom_settings"]["onbehalf_token"] = {"zoom_oauth_connection_user_id": onbehalf_user_id}
        return Bot.objects.create(
            project=self.project,
            meeting_url=meeting_url or f"https://zoom.us/j/{self.meeting_id}",
            settings=settings,
        )

    def _mock_token_refresh(self, mock_post):
        mock_token_response = Mock()
        mock_token_response.json.return_value = {"access_token": "mock_access_token"}
        mock_token_response.raise_for_status.return_value = None
        mock_post.return_value = mock_token_response

    def _mock_zoom_api(self, mock_session, send):
        mock_session.return_value.__enter__ = Mock(return_value=mock_session.return_value)
        mock_session.return_value.__exit__ = Mock(return_value=False)
        mock_session.return_value.send = send

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_raises_when_onbehalf_token_fetch_fails(self, mock_post, mock_session):
        bot = self._create_bot(onbehalf_user_id="obf_user_id")
        self._mock_token_refresh(mock_post)
        requested_urls = []

        def send(request, **kwargs):
            requested_urls.append(request.url)
            raise ConnectionError("Zoom API unreachable")

        self._mock_zoom_api(mock_session, send)

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR)
        # Only the onbehalf token was asked for; nothing else was fetched after it failed.
        self.assertEqual(len(requested_urls), 1)
        self.assertIn("token?type=onbehalf", requested_urls[0])

    @patch("bots.zoom_oauth_connections_utils.trigger_webhook")
    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_raises_on_authentication_error_and_marks_connection_disconnected(self, mock_post, mock_session, mock_trigger_webhook):
        bot = self._create_bot(onbehalf_user_id="obf_user_id")

        import requests as real_requests

        error_response = Mock()
        error_response.json.return_value = {"error": "invalid_grant"}
        refresh_response = Mock()
        refresh_response.raise_for_status.side_effect = real_requests.HTTPError(response=error_response)
        mock_post.return_value = refresh_response

        def send(request, **kwargs):
            raise AssertionError("No Zoom API call may be made after the token refresh failed")

        self._mock_zoom_api(mock_session, send)

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_AUTHENTICATION_ERROR)
        self.zoom_oauth_connection.refresh_from_db()
        self.assertEqual(self.zoom_oauth_connection.state, ZoomOAuthConnectionStates.DISCONNECTED)

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_raises_when_zoom_returns_no_token(self, mock_post, mock_session):
        bot = self._create_bot(onbehalf_user_id="obf_user_id")
        self._mock_token_refresh(mock_post)

        def send(request, **kwargs):
            response = Mock()
            response.raise_for_status.return_value = None
            response.json.return_value = {}
            return response

        self._mock_zoom_api(mock_session, send)

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_RETURNED_NO_TOKEN)

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_raises_without_any_zoom_call_when_connection_is_missing(self, mock_post, mock_session):
        bot = self._create_bot(onbehalf_user_id="someone_who_never_connected")

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_CONNECTION_NOT_FOUND)
        mock_post.assert_not_called()
        mock_session.assert_not_called()

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_raises_when_connection_does_not_support_onbehalf_tokens(self, mock_post, mock_session):
        self.zoom_oauth_connection.is_onbehalf_token_supported = False
        self.zoom_oauth_connection.is_local_recording_token_supported = True
        self.zoom_oauth_connection.save()
        bot = self._create_bot(onbehalf_user_id="obf_user_id")

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_CONNECTION_DOES_NOT_SUPPORT_ONBEHALF_TOKENS)
        mock_post.assert_not_called()
        mock_session.assert_not_called()

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_raises_without_any_zoom_call_when_meeting_url_has_no_meeting_id(self, mock_post, mock_session):
        # The bot API rejects a Zoom URL without a numeric meeting id, so this guards a bot stored another way,
        # for example with a personal link (zoom.us/my/<name>) saved directly.
        bot = self._create_bot(onbehalf_user_id="obf_user_id", meeting_url="https://zoom.us/my/obfuserroom")

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_NO_MEETING_ID)
        mock_post.assert_not_called()
        mock_session.assert_not_called()

    def test_raises_when_project_has_no_zoom_oauth_app(self):
        other_project = Project.objects.create(name="Project without a Zoom OAuth app", organization=self.organization)
        bot = Bot.objects.create(
            project=other_project,
            meeting_url=f"https://zoom.us/j/{self.meeting_id}",
            settings={"zoom_settings": {"sdk": "native", "onbehalf_token": {"zoom_oauth_connection_user_id": "obf_user_id"}}},
        )

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_NO_ZOOM_OAUTH_APP)

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_onbehalf_bot_gets_its_token_when_the_fetch_succeeds(self, mock_post, mock_session):
        bot = self._create_bot(onbehalf_user_id="obf_user_id")
        self._mock_token_refresh(mock_post)
        requested_urls = []

        def send(request, **kwargs):
            requested_urls.append(request.url)
            response = Mock()
            response.raise_for_status.return_value = None
            response.json.return_value = {"token": "onbehalf_token_456"}
            return response

        self._mock_zoom_api(mock_session, send)

        result = get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(result["onbehalf_token"], "onbehalf_token_456")
        # An onbehalf-only connection never asks Zoom for a local recording token (no mapping, capability off).
        self.assertIsNone(result["app_privilege_token"])
        self.assertEqual(len(requested_urls), 1)
        self.assertIn("token?type=onbehalf", requested_urls[0])
        self.assertNotIn("local_recording", requested_urls[0])

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_bot_without_onbehalf_is_unchanged_and_never_raises(self, mock_post, mock_session):
        """A bot that did not ask for an onbehalf token keeps the upstream behavior, including when Zoom fails."""
        mapping_connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_oauth_app,
            user_id="host_user_id",
            account_id="test_account_id",
            is_local_recording_token_supported=True,
            is_onbehalf_token_supported=False,
        )
        mapping_connection.set_credentials({"refresh_token": "host_refresh_token"})
        ZoomMeetingToZoomOAuthConnectionMapping.objects.create(
            zoom_oauth_app=self.zoom_oauth_app,
            zoom_oauth_connection=mapping_connection,
            meeting_id=self.meeting_id,
        )
        bot = self._create_bot(onbehalf_user_id=None)
        self._mock_token_refresh(mock_post)

        def send(request, **kwargs):
            raise ConnectionError("Zoom API unreachable")

        self._mock_zoom_api(mock_session, send)

        result = get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertEqual(result, {"zak_token": None, "join_token": None, "app_privilege_token": None, "onbehalf_token": None})

    @patch("bots.zoom_oauth_connections_utils.requests.Session")
    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_get_onbehalf_token_via_zoom_oauth_app_still_returns_none_on_failure(self, mock_post, mock_session):
        """The single-token helper keeps its upstream contract: a token or None, never an exception."""
        bot = self._create_bot(onbehalf_user_id="someone_who_never_connected")

        self.assertIsNone(get_onbehalf_token_via_zoom_oauth_app(bot))
        mock_post.assert_not_called()
