"""Local erasure is exact, atomic, durable, and never remote revoke evidence."""
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import patch

from django.db import IntegrityError, close_old_connections, connection, transaction
from django.db.models.query import QuerySet
from django.test import TransactionTestCase, override_settings

from bots import zoom_retention as service
from bots.models import (WebhookDeliveryAttempt, WebhookSubscription, WebhookTriggerTypes,
                         ZoomOAuthConnection, ZoomRemovalOperation)
from bots.tests import test_zoom_deauthorization as fixture


@override_settings(**{**fixture.ZoomSignedDeauthorizationTests._overridden_settings,
                      'ENABLE_ZOOM_LOCAL_CREDENTIAL_PURGE': True})
class LocalCredentialPurgeTests(TransactionTestCase):
    def setUp(self):
        fixture.ZoomSignedDeauthorizationTests.setUp(self)
        self.other_connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=type(self.zoom_app).objects.create(project=self.other_project, client_id='other-client'), user_id='other-user', account_id='other-account')
        self.other_connection.set_credentials({'refresh_token':'other-refresh'})
    tearDown = fixture.ZoomSignedDeauthorizationTests.tearDown
    activate_audit_registry = fixture.ZoomSignedDeauthorizationTests.activate_audit_registry
    add_clock_sample = fixture.ZoomSignedDeauthorizationTests.add_clock_sample
    reconnect = fixture.ZoomSignedDeauthorizationTests._deferred_reconnect

    def payload(self, **changes):
        value = dict(project_id=self.project.object_id, operation_id=str(uuid.uuid4()),
                     connection_id=self.connection.object_id, source='skyterra_initiated',
                     zoom_oauth_app_binding=str(self.app_binding), grant_binding_id=str(self.grant.binding_id),
                     authorization_generation=str(self.grant.authorization_generation))
        value.update(changes)
        return value

    def post(self, payload, key=None):
        return self.client.post('/api/v1/zoom_retention/local-credential-purge', data=json.dumps(payload),
                                content_type='application/json', HTTP_AUTHORIZATION='Token '+(key or self.api_key))

    def call(self, payload):
        data = dict(payload)
        data.pop('project_id')
        data['operation_id'] = uuid.UUID(data['operation_id'])
        data['connection_object_id'] = data.pop('connection_id')
        return service.process_local_credential_purge(project=self.project, **data)

    def attempt(self, connection=None):
        subscription = WebhookSubscription.objects.create(project=self.project, url='https://example.test/hook')
        return WebhookDeliveryAttempt.objects.create(webhook_subscription=subscription,
            webhook_trigger_type=WebhookTriggerTypes.ZOOM_OAUTH_CONNECTION_STATE_CHANGE,
            idempotency_key=uuid.uuid4(), zoom_oauth_connection=connection or self.connection,
            payload={'sensitive': 'synthetic-test'})

    def assert_proof(self, body):
        self.assertEqual(body['operation_type'], 'purge_connection_credentials')
        self.assertEqual(body['state'], 'purged')
        self.assertEqual(body['phase'], 'complete')
        self.assertEqual(body['terminal_basis'], 'local_credential_erasure')
        self.assertEqual(body['evidence'], {'provider_revoke': False, 'signed_deauthorization': False,
                                           'local_credential_erasure': True})
        self.assertEqual(body['grant_binding_id'], str(self.grant.binding_id))
        self.assertEqual(body['connection_generation'], str(self.grant.authorization_generation))
        self.assertNotIn('verified_deauthorization_event_digest', body)

    def test_local_erasure_deletes_exact_rows_and_independent_get_proves_only_local(self):
        attempt = self.attempt()
        other = self.attempt(self.other_connection)
        payload = self.payload()
        self.connection.set_credentials({'refresh_token': 'invalid-A', service.PENDING_REVOKE_ACCESS_TOKEN_KEY: 'invalid-access-A'})
        with patch('bots.zoom_retention.requests.post') as remote:
            result = self.post(payload)
            self.assertEqual(result.status_code, 200, result.content)
            remote.assert_not_called()
        self.assert_proof(result.json())
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
        self.assertFalse(WebhookDeliveryAttempt.objects.filter(pk=attempt.pk).exists())
        self.assertTrue(WebhookDeliveryAttempt.objects.filter(pk=other.pk).exists())
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.other_connection.pk).exists())
        self.grant.refresh_from_db()
        self.assertIsNone(self.grant.canonical_removal_operation_id)
        get = self.client.get('/api/v1/zoom_retention/operations/'+payload['operation_id'], HTTP_AUTHORIZATION='Token '+self.api_key)
        self.assertEqual(get.json(), result.json())

    def test_gate_off_refuses_api_and_internal_service(self):
        with override_settings(ENABLE_ZOOM_LOCAL_CREDENTIAL_PURGE=False), patch('bots.zoom_retention.requests.post') as remote:
            self.assertEqual(self.post(self.payload()).status_code, 404)
            with self.assertRaises(service.UntrustedDeauthorizationSource):
                self.call(self.payload())
            remote.assert_not_called()
        self.assertEqual(ZoomRemovalOperation.objects.count(), 0)

    def test_disabled_receipt_trigger_refuses_before_erasure(self):
        with connection.cursor() as cursor:
            cursor.execute('ALTER TABLE bots_zoomremovaloperation DISABLE TRIGGER zoom_local_erasure_receipt_immutable')
        try:
            self.assertEqual(self.post(self.payload()).status_code,409)
            self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
            self.assertEqual(ZoomRemovalOperation.objects.count(),0)
        finally:
            with connection.cursor() as cursor:
                cursor.execute('ALTER TABLE bots_zoomremovaloperation ENABLE TRIGGER zoom_local_erasure_receipt_immutable')

    def test_retention_gate_off_refuses(self):
        with override_settings(ENABLE_ZOOM_RETENTION_REMOVAL_API=False):
            self.assertEqual(self.post(self.payload()).status_code, 404)

    def test_unauthenticated_refuses_without_effect(self):
        result = self.client.post('/api/v1/zoom_retention/local-credential-purge', data=json.dumps(self.payload()), content_type='application/json')
        self.assertIn(result.status_code, (401,403))
        self.assertEqual(ZoomRemovalOperation.objects.count(), 0)

    def test_missing_malformed_and_wrong_tuple_refuse_without_effect(self):
        for field in ('zoom_oauth_app_binding','grant_binding_id','authorization_generation'):
            for value, status in ((None,400),('broken',400),(str(uuid.uuid4()),409)):
                with self.subTest(field=field,value=value), patch('bots.zoom_retention.requests.post') as remote:
                    self.assertEqual(self.post(self.payload(**{field:value})).status_code, status)
                    remote.assert_not_called()
                    self.assertEqual(ZoomRemovalOperation.objects.count(), 0)
                    self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())

    def test_cross_project_and_wrong_source_refuse(self):
        self.assertEqual(self.post(self.payload(project_id=self.other_project.object_id), key=self.other_api_key).status_code,404)
        self.assertEqual(self.post(self.payload(source='zoom_deauthorization')).status_code,400)
        self.assertEqual(ZoomRemovalOperation.objects.count(),0)

    def test_replacement_before_admission_refuses_stale_tuple(self):
        payload = self.payload()
        replacement,error = self.reconnect()
        self.assertIsNone(error)
        with patch('bots.zoom_retention.requests.post') as remote:
            self.assertEqual(self.post(payload).status_code,409)
            remote.assert_not_called()
        replacement.refresh_from_db()
        self.assertEqual(replacement.get_credentials(),{'refresh_token':'recovery-refresh-test'})
        self.assertEqual(ZoomRemovalOperation.objects.count(),0)

    def test_absent_connection_without_our_proof_stays_unproved(self):
        payload = self.payload()
        self.connection.delete()
        self.assertEqual(self.post(payload).status_code,409)
        self.assertEqual(ZoomRemovalOperation.objects.count(),0)

    def test_same_tuple_retry_and_canonical_conflict(self):
        payload = self.payload()
        first = self.post(payload)
        self.assertEqual(first.status_code,200,first.content)
        self.assertEqual(self.post(payload).json(), first.json())
        other = self.post({**payload,'operation_id':str(uuid.uuid4())})
        self.assertEqual(other.status_code,409)
        self.assertEqual(other.json(),{'error':'operation_conflict','canonical_operation_id':payload['operation_id']})
        self.assertEqual(ZoomRemovalOperation.objects.count(),1)

    def test_completed_A_retry_cannot_adopt_or_delete_new_B(self):
        payload = self.payload()
        first = self.post(payload)
        self.assertEqual(first.status_code,200)
        replacement,error = self.reconnect()
        self.assertIsNone(error)
        newer = {**payload,'connection_id':replacement.object_id,
                 'grant_binding_id':str(replacement.authorization_grant.binding_id),
                 'authorization_generation':str(replacement.authorization_generation)}
        self.assertEqual(self.post(newer).status_code,409)
        self.assertEqual(self.post(payload).status_code,200)
        replacement.refresh_from_db()
        self.assertEqual(replacement.get_credentials(),{'refresh_token':'recovery-refresh-test'})

    def test_revoke_operation_identity_and_receipt_are_not_reused_or_changed(self):
        payload = self.payload()
        with patch('bots.zoom_retention._revoke_at_zoom', return_value=service.ProviderOutcome(False,'revoke_transport_unknown')):
            revoke = service.process_connection_revoke(project=self.project,
                operation_id=uuid.UUID(payload['operation_id']),connection_object_id=payload['connection_id'],
                source=payload['source'],zoom_oauth_app_binding=payload['zoom_oauth_app_binding'],
                grant_binding_id=payload['grant_binding_id'],authorization_generation=payload['authorization_generation'])
        before = service.operation_result(revoke)
        self.assertEqual(self.post(payload).status_code,409)
        local = self.post({**payload,'operation_id':str(uuid.uuid4())})
        self.assertEqual(local.status_code,200,local.content)
        self.assert_proof(local.json())
        revoke.refresh_from_db()
        self.assertEqual(service.operation_result(revoke),before)
        self.grant.refresh_from_db()
        self.assertEqual(self.grant.canonical_removal_operation_id,revoke.pk)

    def test_delivery_delete_failure_rolls_back_every_effect(self):
        attempt = self.attempt()
        original = QuerySet.delete
        def fail(qs):
            if qs.model is WebhookDeliveryAttempt:
                raise service.DatabaseVerificationError()
            return original(qs)
        with patch.object(QuerySet,'delete',new=fail):
            self.assertEqual(self.post(self.payload()).status_code,409)
        self.assertTrue(WebhookDeliveryAttempt.objects.filter(pk=attempt.pk).exists())
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
        self.assertEqual(ZoomRemovalOperation.objects.count(),0)

    def test_silently_retained_attempt_is_detected_and_rolled_back(self):
        attempt = self.attempt()
        original = QuerySet.delete
        def skip(qs):
            if qs.model is WebhookDeliveryAttempt:
                return (0,{})
            return original(qs)
        with patch.object(QuerySet,'delete',new=skip):
            self.assertEqual(self.post(self.payload()).status_code,409)
        self.assertTrue(WebhookDeliveryAttempt.objects.filter(pk=attempt.pk,zoom_oauth_connection=self.connection).exists())
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
        self.assertEqual(ZoomRemovalOperation.objects.count(),0)

    def test_receipt_write_failure_rolls_back_deleted_credentials_and_attempts(self):
        attempt = self.attempt()
        original = ZoomRemovalOperation.save
        def fail(obj,*args,**kwargs):
            if obj.operation_type == 'purge_connection_credentials' and obj.state == 'purged':
                raise service.DatabaseVerificationError()
            return original(obj,*args,**kwargs)
        with patch.object(ZoomRemovalOperation,'save',new=fail):
            self.assertEqual(self.post(self.payload()).status_code,409)
        self.assertTrue(WebhookDeliveryAttempt.objects.filter(pk=attempt.pk).exists())
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
        self.assertEqual(ZoomRemovalOperation.objects.count(),0)

    def test_proof_cannot_be_relabelled_remote_or_changed_after_commit(self):
        result = self.post(self.payload())
        operation = service.get_project_operation(self.project,uuid.UUID(result.json()['operation_id']))
        for changes in ({'terminal_basis':'local_credential_erasure'},{'terminal_basis':'provider_revoke','provider_revoke_settled_at':operation.completed_at},
                        {'completed_at':operation.completed_at.replace(year=2020)}):
            with self.subTest(changes=list(changes)), self.assertRaises(IntegrityError),transaction.atomic():
                ZoomRemovalOperation.objects.filter(pk=operation.pk).update(**changes)

    def test_independent_get_is_project_scoped(self):
        result = self.post(self.payload())
        other = self.client.get('/api/v1/zoom_retention/operations/'+result.json()['operation_id'],HTTP_AUTHORIZATION='Token '+self.other_api_key)
        self.assertEqual(other.status_code,404)

    def test_reconnect_token_exchange_can_overlap_but_persistence_waits_for_local_purge(self):
        entered,release,exchanged = Event(),Event(),Event()
        original = ZoomOAuthConnection.delete
        def paused_delete(obj,*args,**kwargs):
            if obj.pk == self.connection.pk:
                entered.set()
                if not release.wait(10):
                    raise AssertionError('purge barrier timeout')
            return original(obj,*args,**kwargs)
        def purge():
            close_old_connections()
            try: return self.call(self.payload())
            finally: close_old_connections()
        from bots import zoom_oauth_connections_api_utils as callback
        def reconnect():
            close_old_connections()
            token = {'access_token':'new-access','refresh_token':'recovery-refresh-test',
                     'scope':'user:read:user user:read:zak meeting:read:list_meetings meeting:read:local_recording_token'}
            def user_info(*args):
                exchanged.set()
                return {'id':self.connection.user_id,'account_id':self.connection.account_id,'status':'active'}
            payload = {'zoom_oauth_app_binding':str(self.app_binding),'authorization_code':'new-code','redirect_uri':'https://client-agent.test/reconnect'}
            try:
                with patch.object(callback,'_exchange_access_code_for_tokens',return_value=token), patch.object(callback,'_get_user_info',side_effect=user_info):
                    return callback.create_zoom_oauth_connection(payload,self.project)
            finally: close_old_connections()
        with patch.object(ZoomOAuthConnection,'delete',new=paused_delete), ThreadPoolExecutor(max_workers=2) as pool:
            deleting = pool.submit(purge)
            try:
                self.assertTrue(entered.wait(10))
                replacing = pool.submit(reconnect)
                self.assertTrue(exchanged.wait(10))
                self.assertFalse(replacing.done())
            finally: release.set()
            operation = deleting.result(15)
            replacement,error = replacing.result(15)
        self.assertIsNone(error)
        self.assertEqual(operation.state,'purged')
        replacement.refresh_from_db()
        self.assertEqual(replacement.get_credentials(),{'refresh_token':'recovery-refresh-test'})
        self.assertNotEqual(replacement.authorization_generation,self.grant.authorization_generation)
        self.assertNotEqual(replacement.pk,self.connection.pk)
