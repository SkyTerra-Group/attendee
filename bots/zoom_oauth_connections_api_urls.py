from django.urls import path

from . import zoom_oauth_connections_api_views, zoom_retention_api_views

urlpatterns = [
    path("zoom_oauth_connections", zoom_oauth_connections_api_views.ZoomOAuthConnectionListCreateView.as_view(), name="zoom-oauth-connection-list-create"),
    path("zoom_oauth_connections/<str:object_id>", zoom_oauth_connections_api_views.ZoomOAuthConnectionDetailPatchDeleteView.as_view(), name="zoom-oauth-connection-detail-patch-delete"),
    path("zoom_retention/revoke", zoom_retention_api_views.ZoomConnectionRevokeView.as_view(), name="zoom-retention-revoke"),
    path("zoom_retention/purge", zoom_retention_api_views.ZoomBotPurgeView.as_view(), name="zoom-retention-purge"),
    path("zoom_retention/operations/<uuid:operation_id>", zoom_retention_api_views.ZoomRemovalOperationDetailView.as_view(), name="zoom-retention-operation-detail"),
]
