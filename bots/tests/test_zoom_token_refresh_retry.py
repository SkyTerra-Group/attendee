"""SkyTerra: the Zoom token path survives one network blip, and its health is visible.

The refresh POST is resent only when the request never reached Zoom (DNS
lookup or connection setup failed), because Zoom rotates the refresh token on
every accepted refresh. The on-behalf token GET is idempotent and is resent on
any transport error. Both refresh timestamps are written through the
generation fence, and a failed save of a rotated token is retried once.
"""

import socket
import threading
from unittest.mock import Mock, patch

import requests
from django.db.utils import OperationalError
from django.test import Client, SimpleTestCase, TestCase

from accounts.models import Organization
from bots.models import (
    ApiKey,
    Bot,
    Project,
    ZoomMeetingToZoomOAuthConnectionMapping,
    ZoomOAuthApp,
    ZoomOAuthConnection,
    ZoomOAuthConnectionStates,
)
from bots.serializers import ZoomOAuthConnectionSerializer
from bots.tests.zoom_log_capture import CaptureZoomLogBytes
from bots.zoom_oauth_connections_utils import (
    ONBEHALF_TOKEN_FAILURE_ZOOM_API_AUTHENTICATION_ERROR,
    ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR,
    ZOOM_OAUTH_TOKEN_URL,
    ZoomAPIError,
    ZoomOAuthConnectionRemovalFenced,
    ZoomOnbehalfTokenUnavailableError,
    _get_access_token,
    _request_never_reached_zoom,
    get_zoom_tokens_via_zoom_oauth_app,
    update_zoom_oauth_connection_if_writable,
)

UTILS = "bots.zoom_oauth_connections_utils"


# ---------------------------------------------------------------------------
# Real exceptions, produced by the pinned requests/urllib3 without any network.
# ---------------------------------------------------------------------------


def _session_without_proxies() -> requests.Session:
    # requests.post uses a default Session; this one only ignores proxy
    # environment variables so the exception shape is the direct-connection one.
    # requests.sessions.Session, not requests.Session: tests patch the latter.
    session = requests.sessions.Session()
    session.trust_env = False
    return session


def _capture_requests_error(send) -> requests.RequestException:
    try:
        send()
    except requests.RequestException as error:
        return error
    raise AssertionError("expected the request to fail")


def real_name_resolution_error() -> requests.RequestException:
    """The incident's failure: the resolver could not answer for zoom.us."""

    with patch("socket.getaddrinfo", side_effect=socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")):
        return _capture_requests_error(lambda: _session_without_proxies().post(ZOOM_OAUTH_TOKEN_URL, data={"grant_type": "probe"}, timeout=2))


def real_connection_refused_error() -> requests.RequestException:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return _capture_requests_error(lambda: _session_without_proxies().post(f"http://127.0.0.1:{port}/oauth/token", data={"grant_type": "probe"}, timeout=2))


def real_connect_timeout_error() -> requests.RequestException:
    with patch("urllib3.util.connection.create_connection", side_effect=socket.timeout("timed out")):
        return _capture_requests_error(lambda: _session_without_proxies().post(ZOOM_OAUTH_TOKEN_URL, data={"grant_type": "probe"}, timeout=2))


class _LocalServer:
    """Accepts one connection, reads the request, then stalls or hangs up without answering."""

    def __init__(self, behaviour: str):
        self.behaviour = behaviour
        self.received = threading.Event()
        self.release = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        connection, _ = self.listener.accept()
        with connection:
            connection.recv(65536)
            self.received.set()
            if self.behaviour == "stall":
                self.release.wait(5)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.release.set()
        self.thread.join(5)
        self.listener.close()


def real_read_timeout_error() -> tuple[requests.RequestException, bool]:
    with _LocalServer("stall") as server:
        error = _capture_requests_error(lambda: _session_without_proxies().post(f"http://127.0.0.1:{server.port}/oauth/token", data={"grant_type": "probe"}, timeout=0.5))
        return error, server.received.is_set()


def real_protocol_error() -> tuple[requests.RequestException, bool]:
    with _LocalServer("hang_up") as server:
        error = _capture_requests_error(lambda: _session_without_proxies().post(f"http://127.0.0.1:{server.port}/oauth/token", data={"grant_type": "probe"}, timeout=2))
        return error, server.received.is_set()


def http_error_response(status_code: int, body: bytes) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response._content = body
    response.url = ZOOM_OAUTH_TOKEN_URL
    return response


class RequestNeverReachedZoomClassifierTest(SimpleTestCase):
    """The retry decision, checked against exceptions the installed libraries really raise."""

    def test_name_resolution_failure_never_reached_zoom(self):
        error = real_name_resolution_error()
        self.assertIsInstance(error, requests.exceptions.ConnectionError)
        self.assertEqual(type(error.args[0].reason).__name__, "NameResolutionError")
        self.assertTrue(_request_never_reached_zoom(error))

    def test_refused_connection_never_reached_zoom(self):
        error = real_connection_refused_error()
        self.assertEqual(type(error.args[0].reason).__name__, "NewConnectionError")
        self.assertTrue(_request_never_reached_zoom(error))

    def test_connect_timeout_never_reached_zoom(self):
        error = real_connect_timeout_error()
        self.assertIsInstance(error, requests.exceptions.ConnectTimeout)
        self.assertEqual(type(error.args[0].reason).__name__, "ConnectTimeoutError")
        self.assertTrue(_request_never_reached_zoom(error))

    def test_read_timeout_may_have_reached_zoom(self):
        error, server_received_request = real_read_timeout_error()
        self.assertTrue(server_received_request)
        self.assertIsInstance(error, requests.exceptions.ReadTimeout)
        self.assertFalse(_request_never_reached_zoom(error))

    def test_connection_aborted_after_send_may_have_reached_zoom(self):
        error, server_received_request = real_protocol_error()
        self.assertTrue(server_received_request)
        self.assertIsInstance(error, requests.exceptions.ConnectionError)
        self.assertEqual(type(error.args[0]).__name__, "ProtocolError")
        self.assertFalse(_request_never_reached_zoom(error))

    def test_http_responses_ssl_and_proxy_errors_are_not_unsent(self):
        response = http_error_response(503, b"{}")
        try:
            response.raise_for_status()
        except requests.HTTPError as http_error:
            self.assertFalse(_request_never_reached_zoom(http_error))
        self.assertFalse(_request_never_reached_zoom(requests.exceptions.SSLError("tls")))
        self.assertFalse(_request_never_reached_zoom(requests.exceptions.ProxyError("proxy")))
        self.assertFalse(_request_never_reached_zoom(requests.exceptions.ConnectionError("bare")))
        self.assertFalse(_request_never_reached_zoom(ValueError("not a request error")))


# ---------------------------------------------------------------------------
# The dispatch-time token path with mocked Zoom.
# ---------------------------------------------------------------------------


class ZoomTokenPathTestBase(TestCase):
    ORIGINAL_REFRESH_TOKEN = "original-refresh-token-canary"
    ROTATED_REFRESH_TOKEN = "rotated-refresh-token-canary"
    ACCESS_TOKEN = "fresh-access-token-canary"
    ONBEHALF_TOKEN = "onbehalf-join-token-canary"
    CLIENT_SECRET = "client-secret-canary"
    MEETING_ID = "1234567890"

    def setUp(self):
        self.organization = Organization.objects.create(name="Test Org")
        self.project = Project.objects.create(name="Test Project", organization=self.organization)
        self.zoom_oauth_app = ZoomOAuthApp.objects.create(project=self.project, client_id="test_client_id")
        self.zoom_oauth_app.set_credentials({"client_secret": self.CLIENT_SECRET})
        self.connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_oauth_app,
            user_id="obf_user_id",
            account_id="test_account_id",
            is_local_recording_token_supported=False,
            is_onbehalf_token_supported=True,
            state=ZoomOAuthConnectionStates.CONNECTED,
        )
        self.connection.set_credentials({"refresh_token": self.ORIGINAL_REFRESH_TOKEN})
        self.bot = Bot.objects.create(
            project=self.project,
            meeting_url=f"https://zoom.us/j/{self.MEETING_ID}",
            settings={"zoom_settings": {"sdk": "native", "onbehalf_token": {"zoom_oauth_connection_user_id": "obf_user_id"}}},
        )
        sleep_patcher = patch(f"{UTILS}.time.sleep")
        self.mock_sleep = sleep_patcher.start()
        self.addCleanup(sleep_patcher.stop)

    def token_response(self, refresh_token=None):
        response = Mock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "access_token": self.ACCESS_TOKEN,
            "refresh_token": refresh_token or self.ROTATED_REFRESH_TOKEN,
        }
        return response

    def mock_obf_api(self, mock_session, send):
        mock_session.return_value.__enter__ = Mock(return_value=mock_session.return_value)
        mock_session.return_value.__exit__ = Mock(return_value=False)
        mock_session.return_value.send = send

    def obf_success_send(self, sent_urls):
        def send(request, **kwargs):
            sent_urls.append(request.url)
            response = Mock()
            response.raise_for_status.return_value = None
            response.json.return_value = {"token": self.ONBEHALF_TOKEN}
            return response

        return send

    def stored_refresh_token(self):
        return ZoomOAuthConnection.objects.get(pk=self.connection.pk).get_credentials()["refresh_token"]

    def refresh_tokens_sent(self, mock_post):
        return [call.kwargs["data"]["refresh_token"] for call in mock_post.call_args_list]

    def assert_no_token_material(self, capture):
        capture.assert_absent(
            self,
            self.ORIGINAL_REFRESH_TOKEN,
            self.ROTATED_REFRESH_TOKEN,
            self.ACCESS_TOKEN,
            self.ONBEHALF_TOKEN,
            self.CLIENT_SECRET,
            self.connection.object_id,
            self.connection.user_id,
            self.connection.account_id,
            self.MEETING_ID,
        )

    def assert_connection_untouched_by_failure(self):
        current = ZoomOAuthConnection.objects.get(pk=self.connection.pk)
        self.assertEqual(current.state, ZoomOAuthConnectionStates.CONNECTED)
        self.assertIsNone(current.connection_failure_data)
        self.assertEqual(current.get_credentials()["refresh_token"], self.ORIGINAL_REFRESH_TOKEN)
        self.assertIsNone(current.last_successful_token_refresh_at)


class RefreshPostRetryTest(ZoomTokenPathTestBase):
    """A1 / A6: the refresh POST is resent only when it never reached Zoom."""

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_dns_failure_then_success_returns_obf_token_and_saves_one_rotation(self, mock_post, mock_session):
        mock_post.side_effect = [real_name_resolution_error(), self.token_response()]
        sent_urls = []
        self.mock_obf_api(mock_session, self.obf_success_send(sent_urls))

        real_set_credentials = ZoomOAuthConnection.set_credentials
        with (
            patch.object(ZoomOAuthConnection, "set_credentials", autospec=True, side_effect=real_set_credentials) as set_credentials_spy,
            CaptureZoomLogBytes() as capture,
        ):
            tokens = get_zoom_tokens_via_zoom_oauth_app(self.bot)

        self.assertEqual(tokens["onbehalf_token"], self.ONBEHALF_TOKEN)
        self.assertEqual(mock_post.call_count, 2)
        # Both attempts carried the same, still-current refresh token.
        self.assertEqual(self.refresh_tokens_sent(mock_post), [self.ORIGINAL_REFRESH_TOKEN, self.ORIGINAL_REFRESH_TOKEN])
        self.mock_sleep.assert_called_once_with(1.0)
        # Exactly one rotation was saved, and it is the stored token now.
        self.assertEqual(set_credentials_spy.call_count, 1)
        self.assertEqual(self.stored_refresh_token(), self.ROTATED_REFRESH_TOKEN)
        self.assertEqual(capture.bytes.count(b"zoom_oauth_refresh_rotated"), 1)
        self.assertIn(b"zoom_oauth_refresh_retrying code=connection_not_established attempt=1 exception_class=ConnectionError", capture.bytes)
        self.assertEqual(len(sent_urls), 1)
        current = ZoomOAuthConnection.objects.get(pk=self.connection.pk)
        self.assertEqual(current.state, ZoomOAuthConnectionStates.CONNECTED)
        self.assertIsNotNone(current.last_successful_token_refresh_at)
        self.assert_no_token_material(capture)

    @patch(f"{UTILS}.requests.post")
    def test_refused_connection_and_connect_timeout_are_retried(self, mock_post):
        mock_post.side_effect = [real_connection_refused_error(), real_connect_timeout_error(), self.token_response()]

        self.assertEqual(_get_access_token(self.connection), self.ACCESS_TOKEN)

        self.assertEqual(mock_post.call_count, 3)
        self.assertEqual([call.args for call in self.mock_sleep.call_args_list], [(1.0,), (2.0,)])
        self.assertEqual(self.stored_refresh_token(), self.ROTATED_REFRESH_TOKEN)

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_dns_failure_on_every_attempt_stops_after_three_attempts(self, mock_post, mock_session):
        mock_post.side_effect = [real_name_resolution_error() for _ in range(5)]
        self.mock_obf_api(mock_session, Mock(side_effect=AssertionError("no Zoom API call after a failed refresh")))

        with CaptureZoomLogBytes() as capture:
            with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
                get_zoom_tokens_via_zoom_oauth_app(self.bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR)
        self.assertEqual(mock_post.call_count, 3)
        self.assertEqual(self.mock_sleep.call_count, 2)
        self.assertIn(b"zoom_oauth_refresh_failed code=provider_request_failed", capture.bytes)
        self.assert_connection_untouched_by_failure()
        self.assert_no_token_material(capture)

    def _assert_sent_request_is_not_retried(self, mock_post, mock_session, error):
        mock_post.side_effect = [error, self.token_response()]
        self.mock_obf_api(mock_session, Mock(side_effect=AssertionError("no Zoom API call after a failed refresh")))

        with CaptureZoomLogBytes() as capture:
            with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
                get_zoom_tokens_via_zoom_oauth_app(self.bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR)
        self.assertEqual(mock_post.call_count, 1)
        self.mock_sleep.assert_not_called()
        self.assertIn(b"zoom_oauth_refresh_failed code=provider_request_failed", capture.bytes)
        self.assertNotIn(b"zoom_oauth_refresh_retrying", capture.bytes)
        self.assert_connection_untouched_by_failure()
        self.assert_no_token_material(capture)

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_read_timeout_is_not_retried(self, mock_post, mock_session):
        error, _ = real_read_timeout_error()
        self._assert_sent_request_is_not_retried(mock_post, mock_session, error)

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_protocol_error_is_not_retried(self, mock_post, mock_session):
        error, _ = real_protocol_error()
        self._assert_sent_request_is_not_retried(mock_post, mock_session, error)

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_http_error_response_is_not_retried(self, mock_post, mock_session):
        mock_post.return_value = http_error_response(503, b'{"reason": "provider-body-canary"}')
        self.mock_obf_api(mock_session, Mock(side_effect=AssertionError("no Zoom API call after a failed refresh")))

        with CaptureZoomLogBytes() as capture:
            with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
                get_zoom_tokens_via_zoom_oauth_app(self.bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR)
        self.assertEqual(mock_post.call_count, 1)
        self.mock_sleep.assert_not_called()
        self.assert_connection_untouched_by_failure()
        capture.assert_absent(self, "provider-body-canary")

    @patch(f"{UTILS}.trigger_webhook")
    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_invalid_grant_response_is_not_retried(self, mock_post, mock_session, mock_trigger_webhook):
        mock_post.return_value = http_error_response(400, b'{"error": "invalid_grant"}')
        self.mock_obf_api(mock_session, Mock(side_effect=AssertionError("no Zoom API call after a failed refresh")))

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(self.bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_AUTHENTICATION_ERROR)
        self.assertEqual(mock_post.call_count, 1)
        self.mock_sleep.assert_not_called()

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_retry_is_not_sent_once_the_connection_enters_removal(self, mock_post, mock_session):
        mock_post.side_effect = [real_name_resolution_error(), self.token_response()]
        self.mock_obf_api(mock_session, Mock(side_effect=AssertionError("no Zoom API call for a connection being removed")))

        def removal_starts_during_backoff(_seconds):
            ZoomOAuthConnection.objects.filter(pk=self.connection.pk).update(state=ZoomOAuthConnectionStates.REMOVING)

        self.mock_sleep.side_effect = removal_starts_during_backoff

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(self.bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR)
        self.assertEqual(mock_post.call_count, 1)
        current = ZoomOAuthConnection.objects.get(pk=self.connection.pk)
        self.assertEqual(current.state, ZoomOAuthConnectionStates.REMOVING)
        self.assertEqual(current.get_credentials()["refresh_token"], self.ORIGINAL_REFRESH_TOKEN)


class OnbehalfTokenGetRetryTest(ZoomTokenPathTestBase):
    """A1: the idempotent on-behalf token GET is resent on transport errors only."""

    def _send_sequence(self, sent_urls, outcomes):
        outcomes = list(outcomes)

        def send(request, **kwargs):
            sent_urls.append(request.url)
            outcome = outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        return send

    def _obf_response(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"token": self.ONBEHALF_TOKEN}
        return response

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_transport_errors_are_retried_until_the_token_arrives(self, mock_post, mock_session):
        mock_post.return_value = self.token_response()
        read_timeout, _ = real_read_timeout_error()
        sent_urls = []
        self.mock_obf_api(mock_session, self._send_sequence(sent_urls, [real_name_resolution_error(), read_timeout, self._obf_response()]))

        with CaptureZoomLogBytes() as capture:
            tokens = get_zoom_tokens_via_zoom_oauth_app(self.bot)

        self.assertEqual(tokens["onbehalf_token"], self.ONBEHALF_TOKEN)
        self.assertEqual(len(sent_urls), 3)
        self.assertTrue(all("token?type=onbehalf" in url for url in sent_urls))
        self.assertEqual(mock_post.call_count, 1)
        self.assertEqual([call.args for call in self.mock_sleep.call_args_list], [(1.0,), (2.0,)])
        self.assertIn(b"zoom_api_request_retrying code=transport_error attempt=2 exception_class=ReadTimeout", capture.bytes)
        self.assert_no_token_material(capture)

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_transport_errors_stop_after_three_attempts(self, mock_post, mock_session):
        mock_post.return_value = self.token_response()
        sent_urls = []
        self.mock_obf_api(mock_session, self._send_sequence(sent_urls, [real_name_resolution_error() for _ in range(5)]))

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(self.bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR)
        self.assertEqual(len(sent_urls), 3)
        self.assertEqual(ZoomOAuthConnection.objects.get(pk=self.connection.pk).state, ZoomOAuthConnectionStates.CONNECTED)

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_http_error_response_is_not_retried(self, mock_post, mock_session):
        mock_post.return_value = self.token_response()
        sent_urls = []
        self.mock_obf_api(mock_session, self._send_sequence(sent_urls, [http_error_response(500, b"{}"), self._obf_response()]))

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(self.bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR)
        self.assertEqual(len(sent_urls), 1)
        self.mock_sleep.assert_not_called()

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_retry_is_not_sent_once_the_connection_enters_removal(self, mock_post, mock_session):
        mock_post.return_value = self.token_response()
        sent_urls = []
        self.mock_obf_api(mock_session, self._send_sequence(sent_urls, [real_name_resolution_error(), self._obf_response()]))

        def removal_starts_during_backoff(_seconds):
            ZoomOAuthConnection.objects.filter(pk=self.connection.pk).update(state=ZoomOAuthConnectionStates.REMOVING)

        self.mock_sleep.side_effect = removal_starts_during_backoff

        with self.assertRaises(ZoomOnbehalfTokenUnavailableError) as raised:
            get_zoom_tokens_via_zoom_oauth_app(self.bot)

        self.assertEqual(raised.exception.failure_reason, ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR)
        self.assertEqual(len(sent_urls), 1)

    @patch(f"{UTILS}.requests.Session")
    @patch(f"{UTILS}.requests.post")
    def test_local_recording_token_get_keeps_single_attempt(self, mock_post, mock_session):
        """Only the on-behalf GET opts in; the upstream local-recording path is unchanged."""

        host_connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_oauth_app,
            user_id="host_user_id",
            account_id="test_account_id",
            is_local_recording_token_supported=True,
            is_onbehalf_token_supported=False,
        )
        host_connection.set_credentials({"refresh_token": "host-refresh-token-canary"})
        ZoomMeetingToZoomOAuthConnectionMapping.objects.create(
            zoom_oauth_app=self.zoom_oauth_app,
            zoom_oauth_connection=host_connection,
            meeting_id=self.MEETING_ID,
        )
        bot = Bot.objects.create(
            project=self.project,
            meeting_url=f"https://zoom.us/j/{self.MEETING_ID}",
            settings={"zoom_settings": {"sdk": "native"}},
        )
        mock_post.return_value = self.token_response()
        sent_urls = []
        self.mock_obf_api(mock_session, self._send_sequence(sent_urls, [real_name_resolution_error(), self._obf_response()]))

        tokens = get_zoom_tokens_via_zoom_oauth_app(bot)

        self.assertIsNone(tokens["app_privilege_token"])
        self.assertEqual(len(sent_urls), 1)
        self.assertIn("local_recording", sent_urls[0])
        self.mock_sleep.assert_not_called()


class RefreshTimestampsTest(ZoomTokenPathTestBase):
    """A2: a successful refresh records both timestamps through the generation fence."""

    @patch(f"{UTILS}.requests.post")
    def test_successful_refresh_sets_both_timestamps(self, mock_post):
        mock_post.return_value = self.token_response()

        with patch(f"{UTILS}.update_zoom_oauth_connection_if_writable", wraps=update_zoom_oauth_connection_if_writable) as fenced_update:
            self.assertEqual(_get_access_token(self.connection), self.ACCESS_TOKEN)

        fenced_update.assert_called_once()
        self.assertEqual(set(fenced_update.call_args.kwargs), {"last_attempted_token_refresh_at", "last_successful_token_refresh_at"})
        current = ZoomOAuthConnection.objects.get(pk=self.connection.pk)
        self.assertIsNotNone(current.last_successful_token_refresh_at)
        self.assertEqual(current.last_attempted_token_refresh_at, current.last_successful_token_refresh_at)
        self.assertEqual(current.state, ZoomOAuthConnectionStates.CONNECTED)

    @patch(f"{UTILS}.requests.post")
    def test_successful_refresh_without_rotation_still_sets_both_timestamps(self, mock_post):
        mock_post.return_value = self.token_response(refresh_token=self.ORIGINAL_REFRESH_TOKEN)

        self.assertEqual(_get_access_token(self.connection), self.ACCESS_TOKEN)

        current = ZoomOAuthConnection.objects.get(pk=self.connection.pk)
        self.assertIsNotNone(current.last_successful_token_refresh_at)
        self.assertEqual(current.get_credentials()["refresh_token"], self.ORIGINAL_REFRESH_TOKEN)

    @patch(f"{UTILS}.requests.post")
    def test_failed_refresh_records_only_the_attempt(self, mock_post):
        mock_post.side_effect = [real_name_resolution_error() for _ in range(3)]

        with self.assertRaises(ZoomAPIError):
            _get_access_token(self.connection)

        current = ZoomOAuthConnection.objects.get(pk=self.connection.pk)
        self.assertIsNotNone(current.last_attempted_token_refresh_at)
        self.assertIsNone(current.last_successful_token_refresh_at)
        self.assertEqual(current.state, ZoomOAuthConnectionStates.CONNECTED)

    @patch(f"{UTILS}.requests.post")
    def test_timestamps_never_reinsert_a_connection_purged_mid_refresh(self, mock_post):
        mock_post.return_value = self.token_response()
        pk = self.connection.pk

        def purge_after_rotation(connection, new_refresh_token):
            ZoomOAuthConnection.objects.filter(pk=pk).delete()

        with patch(f"{UTILS}._persist_rotated_refresh_token", side_effect=purge_after_rotation):
            with self.assertRaises(ZoomOAuthConnectionRemovalFenced):
                _get_access_token(self.connection)

        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=pk).exists())

    @patch(f"{UTILS}.requests.post")
    def test_timestamps_are_not_written_once_removal_began(self, mock_post):
        mock_post.return_value = self.token_response()
        pk = self.connection.pk

        def removal_starts_after_rotation(connection, new_refresh_token):
            ZoomOAuthConnection.objects.filter(pk=pk).update(state=ZoomOAuthConnectionStates.REMOVING)

        with patch(f"{UTILS}._persist_rotated_refresh_token", side_effect=removal_starts_after_rotation):
            with self.assertRaises(ZoomOAuthConnectionRemovalFenced):
                _get_access_token(self.connection)

        current = ZoomOAuthConnection.objects.get(pk=pk)
        self.assertEqual(current.state, ZoomOAuthConnectionStates.REMOVING)
        self.assertIsNone(current.last_successful_token_refresh_at)

    @patch(f"{UTILS}.requests.post")
    def test_status_write_failure_does_not_fail_an_accepted_refresh(self, mock_post):
        mock_post.return_value = self.token_response()

        with (
            patch(f"{UTILS}.update_zoom_oauth_connection_if_writable", side_effect=OperationalError("status-db-canary")),
            CaptureZoomLogBytes() as capture,
        ):
            self.assertEqual(_get_access_token(self.connection), self.ACCESS_TOKEN)

        self.assertEqual(self.stored_refresh_token(), self.ROTATED_REFRESH_TOKEN)
        self.assertIn(b"zoom_oauth_refresh_status_write_failed code=status_write_failed", capture.bytes)
        capture.assert_absent(self, "status-db-canary")
        self.assert_no_token_material(capture)


class RotationSaveRetryTest(ZoomTokenPathTestBase):
    """A3: a failed save of the rotated refresh token is retried once, then reported without token material."""

    def _flaky_set_credentials(self, failures):
        real_set_credentials = ZoomOAuthConnection.set_credentials
        calls = {"count": 0}

        def set_credentials(instance, credentials):
            calls["count"] += 1
            if calls["count"] <= failures:
                raise OperationalError(f"database-canary {self.ROTATED_REFRESH_TOKEN}")
            return real_set_credentials(instance, credentials)

        return set_credentials, calls

    @patch(f"{UTILS}.requests.post")
    def test_save_failing_once_is_retried(self, mock_post):
        mock_post.return_value = self.token_response()
        set_credentials, calls = self._flaky_set_credentials(failures=1)

        with (
            patch.object(ZoomOAuthConnection, "set_credentials", autospec=True, side_effect=set_credentials),
            CaptureZoomLogBytes() as capture,
        ):
            self.assertEqual(_get_access_token(self.connection), self.ACCESS_TOKEN)

        self.assertEqual(calls["count"], 2)
        self.assertEqual(self.stored_refresh_token(), self.ROTATED_REFRESH_TOKEN)
        self.mock_sleep.assert_called_once_with(0.5)
        self.assertIn(b"zoom_oauth_refresh_rotation_save_retrying code=rotation_persist_retry", capture.bytes)
        self.assertNotIn(b"rotation_persist_failed", capture.bytes)
        self.assertEqual(mock_post.call_count, 1)
        self.assert_no_token_material(capture)
        capture.assert_absent(self, "database-canary")

    @patch(f"{UTILS}.requests.post")
    def test_save_failing_twice_logs_rotation_persist_failed_without_token_material(self, mock_post):
        mock_post.return_value = self.token_response()
        set_credentials, calls = self._flaky_set_credentials(failures=2)

        with (
            patch.object(ZoomOAuthConnection, "set_credentials", autospec=True, side_effect=set_credentials),
            CaptureZoomLogBytes() as capture,
        ):
            with self.assertRaises(ZoomAPIError) as raised:
                _get_access_token(self.connection)

        self.assertEqual(str(raised.exception), "zoom_refresh_rotation_persist_failed")
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual(calls["count"], 2)
        # The refresh POST itself is never resent because a save failed.
        self.assertEqual(mock_post.call_count, 1)
        self.assertIn(b"zoom_oauth_refresh_failed code=rotation_persist_failed", capture.bytes)
        self.assertNotIn(b"zoom_oauth_refresh_rotated", capture.bytes)
        self.assert_no_token_material(capture)
        capture.assert_absent(self, "database-canary")
        self.assertEqual(self.stored_refresh_token(), self.ORIGINAL_REFRESH_TOKEN)

    @patch(f"{UTILS}.requests.post")
    def test_removal_fence_is_never_retried(self, mock_post):
        pk = self.connection.pk

        # Removal begins while the refresh POST is in flight: the rotation is
        # refused once by the fence and never retried or written.
        def removal_starts_during_post(*args, **kwargs):
            ZoomOAuthConnection.objects.filter(pk=pk).update(state=ZoomOAuthConnectionStates.REMOVING)
            return self.token_response()

        mock_post.side_effect = removal_starts_during_post

        with (
            patch.object(ZoomOAuthConnection, "set_credentials", autospec=True) as set_credentials,
            CaptureZoomLogBytes() as capture,
        ):
            with self.assertRaises(ZoomOAuthConnectionRemovalFenced):
                _get_access_token(self.connection)

        set_credentials.assert_not_called()
        self.mock_sleep.assert_not_called()
        self.assertNotIn(b"rotation_persist", capture.bytes)
        self.assertEqual(self.stored_refresh_token(), self.ORIGINAL_REFRESH_TOKEN)


class RefreshTimestampsApiTest(TestCase):
    """A5: the API shows both refresh timestamps."""

    def setUp(self):
        organization = Organization.objects.create(name="Test Org")
        self.project = Project.objects.create(name="Test Project", organization=organization)
        _, self.api_key = ApiKey.create(project=self.project, name="API Key")
        zoom_oauth_app = ZoomOAuthApp.objects.create(project=self.project, client_id="test_client_id")
        zoom_oauth_app.set_credentials({"client_secret": "client-secret-canary"})
        self.connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=zoom_oauth_app,
            user_id="user_id",
            account_id="account_id",
            is_onbehalf_token_supported=True,
        )
        self.connection.set_credentials({"refresh_token": "refresh-token-canary"})

    def test_serializer_and_list_endpoint_expose_both_timestamps(self):
        response = Client().get("/api/v1/zoom_oauth_connections", HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, 200)
        listed = response.json()["results"][0]
        self.assertIsNone(listed["last_attempted_token_refresh_at"])
        self.assertIsNone(listed["last_successful_token_refresh_at"])

        attempted = "2026-10-21T16:48:33.526000Z"
        succeeded = "2026-10-21T17:03:15.250000Z"
        ZoomOAuthConnection.objects.filter(pk=self.connection.pk).update(
            last_attempted_token_refresh_at=attempted,
            last_successful_token_refresh_at=succeeded,
        )

        response = Client().get("/api/v1/zoom_oauth_connections", HTTP_AUTHORIZATION=f"Token {self.api_key}")
        listed = response.json()["results"][0]
        self.assertEqual(listed["last_attempted_token_refresh_at"], attempted)
        self.assertEqual(listed["last_successful_token_refresh_at"], succeeded)
        self.assertNotIn(b"refresh-token-canary", response.content)

        serialized = ZoomOAuthConnectionSerializer(ZoomOAuthConnection.objects.get(pk=self.connection.pk)).data
        self.assertEqual(serialized["last_attempted_token_refresh_at"], attempted)
        self.assertEqual(serialized["last_successful_token_refresh_at"], succeeded)
