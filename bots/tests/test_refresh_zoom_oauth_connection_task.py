from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from accounts.models import Organization
from bots.models import (
    Project,
    ZoomOAuthApp,
    ZoomOAuthConnection,
    ZoomOAuthConnectionStates,
)
from bots.tasks.refresh_zoom_oauth_connection_task import (
    refresh_zoom_oauth_connection,
)
from bots.tests.zoom_log_capture import CaptureZoomLogBytes
from bots.zoom_oauth_connections_utils import ZoomAPIAuthenticationError, ZoomAPIError


class TestRefreshZoomOAuthConnection(TestCase):
    """Test the refresh_zoom_oauth_connection Celery task."""

    def setUp(self):
        self.organization = Organization.objects.create(name="Test Org")
        self.project = Project.objects.create(name="Test Project", organization=self.organization)
        self.zoom_oauth_app = ZoomOAuthApp.objects.create(project=self.project, client_id="test_client_id")
        self.zoom_oauth_app.set_credentials({"client_secret": "test_secret"})
        self.zoom_oauth_connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_oauth_app,
            user_id="test_user_id",
            account_id="test_account_id",
        )
        self.zoom_oauth_connection.set_credentials({"refresh_token": "test_refresh_token"})

    @patch("bots.tasks.refresh_zoom_oauth_connection_task._get_access_token")
    def test_refresh_zoom_oauth_connection_success(self, mock_get_access_token):
        """Test successful refresh of zoom oauth connection token."""
        mock_get_access_token.return_value = "mock_access_token"

        refresh_zoom_oauth_connection(self.zoom_oauth_connection.id)

        mock_get_access_token.assert_called_once_with(self.zoom_oauth_connection)

        self.zoom_oauth_connection.refresh_from_db()
        self.assertEqual(self.zoom_oauth_connection.state, ZoomOAuthConnectionStates.CONNECTED)
        self.assertIsNotNone(self.zoom_oauth_connection.last_attempted_token_refresh_at)
        self.assertIsNotNone(self.zoom_oauth_connection.last_successful_token_refresh_at)
        self.assertIsNone(self.zoom_oauth_connection.connection_failure_data)

    @patch("bots.zoom_oauth_connections_utils.trigger_webhook")
    @patch("bots.tasks.refresh_zoom_oauth_connection_task._get_access_token")
    def test_refresh_zoom_oauth_connection_authentication_error(self, mock_get_access_token, mock_trigger_webhook):
        """Test refresh handles authentication errors properly."""
        auth_error = ZoomAPIAuthenticationError("Invalid credentials")
        mock_get_access_token.side_effect = auth_error

        refresh_zoom_oauth_connection(self.zoom_oauth_connection.id)

        self.zoom_oauth_connection.refresh_from_db()
        self.assertEqual(self.zoom_oauth_connection.state, ZoomOAuthConnectionStates.DISCONNECTED)
        self.assertIsNotNone(self.zoom_oauth_connection.connection_failure_data)
        self.assertEqual(
            self.zoom_oauth_connection.connection_failure_data["error"],
            "zoom_authentication_rejected",
        )
        self.assertIn("timestamp", self.zoom_oauth_connection.connection_failure_data)

    @patch("bots.tasks.refresh_zoom_oauth_connection_task._get_access_token")
    def test_refresh_zoom_oauth_connection_general_exception(self, mock_get_access_token):
        """Test refresh handles general exceptions properly."""
        mock_get_access_token.side_effect = Exception("Network error")

        with self.assertRaises(ZoomAPIError) as cm:
            refresh_zoom_oauth_connection(self.zoom_oauth_connection.id)

        self.assertEqual(str(cm.exception), "zoom_oauth_refresh_failed")

        self.zoom_oauth_connection.refresh_from_db()
        self.assertIsNotNone(self.zoom_oauth_connection.last_attempted_token_refresh_at)

    @patch("bots.tasks.refresh_zoom_oauth_connection_task.ZoomOAuthConnection.objects.get")
    def test_initial_database_failure_raises_fixed_error_without_unbound_local(
        self,
        mock_get,
    ):
        provider_marker = "database-provider-body-canary"
        mock_get.side_effect = RuntimeError(provider_marker)

        with CaptureZoomLogBytes() as capture:
            with self.assertRaises(ZoomAPIError) as raised:
                refresh_zoom_oauth_connection(self.zoom_oauth_connection.id)

        self.assertEqual(str(raised.exception), "zoom_oauth_refresh_failed")
        capture.assert_absent(self, provider_marker)

    @patch("bots.tasks.refresh_zoom_oauth_connection_task._get_access_token")
    def test_refresh_zoom_oauth_connection_clears_failure_data(self, mock_get_access_token):
        """Test that successful refresh clears previous connection failure data."""
        mock_get_access_token.return_value = "mock_access_token"

        # Set initial failure state
        self.zoom_oauth_connection.state = ZoomOAuthConnectionStates.DISCONNECTED
        self.zoom_oauth_connection.connection_failure_data = {
            "error": "Previous error",
            "timestamp": timezone.now().isoformat(),
        }
        self.zoom_oauth_connection.save()

        refresh_zoom_oauth_connection(self.zoom_oauth_connection.id)

        self.zoom_oauth_connection.refresh_from_db()

        self.assertEqual(self.zoom_oauth_connection.state, ZoomOAuthConnectionStates.CONNECTED)
        self.assertIsNone(self.zoom_oauth_connection.connection_failure_data)
