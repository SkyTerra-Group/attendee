"""Expired leases cannot be revived or authorize local destructive writes."""

import uuid
from datetime import timedelta
from unittest.mock import patch

from django.db.models.query import QuerySet
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from bots import zoom_retention as retention
from bots.models import Bot, BotStates, ZoomOAuthConnection, ZoomRemovalOperation, ZoomRemovalOperationPhases, ZoomRemovalOperationSources, ZoomRemovalOperationStates, ZoomRemovalOperationTypes
from bots.tests import test_zoom_retention as fixtures


@override_settings(ENABLE_ZOOM_RETENTION_REMOVAL_API=True, LOG_BOT_STATE_CHANGES=False)
class ZoomRemovalLeaseExpiryTests(TransactionTestCase):
    setUp = fixtures.ZoomRetentionTests.setUp
    tearDown = fixtures.ZoomRetentionTests.tearDown
    make_bot = fixtures.ZoomRetentionTests.make_bot
    make_connection = fixtures.ZoomRetentionTests.make_connection

    def operation(self, bot):
        return retention._get_or_create_operation(project=self.project, operation_id=uuid.uuid4(), operation_type=ZoomRemovalOperationTypes.PURGE_BOT, target_object_id=bot.object_id)

    def test_expired_or_missing_expiry_cannot_renew_complete_or_release(self):
        now = timezone.now()
        for expiry in (None, now, now - timedelta(seconds=1)):
            for action in ("update", "complete", "release"):
                with self.subTest(expiry=expiry, action=action):
                    operation, token = retention._claim_operation(self.operation(self.make_bot()))
                    ZoomRemovalOperation.objects.filter(pk=operation.pk).update(lease_expires_at=expiry)
                    before = ZoomRemovalOperation.objects.filter(pk=operation.pk).values().get()
                    with patch("bots.zoom_retention.timezone.now", return_value=now):
                        if action == "release":
                            retention._release_claim(operation.pk, token, state=ZoomRemovalOperationStates.PURGE_UNKNOWN, failure_code="synthetic")
                        else:
                            with self.assertRaises(retention.LeaseLost):
                                if action == "update":
                                    retention._update_claimed(operation.pk, token, phase=ZoomRemovalOperationPhases.STORAGE_VERIFIED)
                                else:
                                    retention._complete_claim(operation.pk, token, ZoomRemovalOperationStates.PURGED)
                    self.assertEqual(ZoomRemovalOperation.objects.filter(pk=operation.pk).values().get(), before)

    def test_claim_uses_clock_after_operation_lock(self):
        operation = self.operation(self.make_bot())
        clock = [timezone.now()]
        late = clock[0] + timedelta(seconds=retention.LEASE_SECONDS + 1)
        original_get = QuerySet.get

        def get_after_wait(queryset, *args, **kwargs):
            result = original_get(queryset, *args, **kwargs)
            if queryset.model is ZoomRemovalOperation and queryset.query.select_for_update:
                clock[0] = late
            return result

        with patch("bots.zoom_retention.timezone.now", side_effect=lambda: clock[0]), patch.object(QuerySet, "get", new=get_after_wait):
            claimed, _token = retention._claim_operation(operation)
        self.assertEqual(claimed.lease_expires_at, late + timedelta(seconds=retention.LEASE_SECONDS))

    def test_expiry_during_operation_save_rolls_back_renewal_release_and_completion(self):
        for action in ("update", "release", "complete"):
            with self.subTest(action=action):
                operation, token = retention._claim_operation(self.operation(self.make_bot()))
                before = ZoomRemovalOperation.objects.filter(pk=operation.pk).values().get()
                clock = [timezone.now()]
                original_save = ZoomRemovalOperation.save

                def save_after_wait(instance, *args, **kwargs):
                    result = original_save(instance, *args, **kwargs)
                    clock[0] = operation.lease_expires_at
                    return result

                with patch("bots.zoom_retention.timezone.now", side_effect=lambda: clock[0]), patch.object(ZoomRemovalOperation, "save", new=save_after_wait):
                    if action == "release":
                        retention._release_claim(operation.pk, token, state=ZoomRemovalOperationStates.PURGE_UNKNOWN)
                    else:
                        with self.assertRaises(retention.LeaseLost):
                            if action == "update":
                                retention._update_claimed(operation.pk, token, phase=ZoomRemovalOperationPhases.STORAGE_VERIFIED)
                            else:
                                retention._complete_claim(operation.pk, token, ZoomRemovalOperationStates.PURGED)
                self.assertEqual(ZoomRemovalOperation.objects.filter(pk=operation.pk).values().get(), before)

    def test_expiry_during_storage_without_reclaimer_stays_pending_then_recovers(self):
        bot = self.make_bot()
        operation_id = uuid.uuid4()
        clock = [timezone.now()]

        def storage(_manifest):
            clock[0] += timedelta(seconds=retention.LEASE_SECONDS + 1)

        with patch("bots.zoom_retention.timezone.now", side_effect=lambda: clock[0]), patch.object(retention, "_delete_and_verify_storage", side_effect=storage):
            result = retention.process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertIsNone(result.completed_at)
        self.assertEqual(result.phase, ZoomRemovalOperationPhases.PENDING)
        self.assertLessEqual(result.lease_expires_at, clock[0])
        self.assertTrue(Bot.objects.filter(pk=bot.pk).exists())
        with patch("bots.zoom_retention.timezone.now", side_effect=lambda: clock[0]), patch.object(retention, "_delete_and_verify_storage", return_value=None):
            recovered = retention.process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(recovered.state, ZoomRemovalOperationStates.PURGED)
        self.assertEqual(recovered.attempt_count, 2)

    def test_expiry_during_revoke_preserves_connection_and_unfinished_operation(self):
        connection = self.make_connection()
        clock = [timezone.now()]

        def revoke(_connection):
            clock[0] += timedelta(seconds=retention.LEASE_SECONDS + 1)
            return retention.ProviderOutcome(True)

        with patch("bots.zoom_retention.timezone.now", side_effect=lambda: clock[0]), patch.object(retention, "_revoke_at_zoom", side_effect=revoke):
            result = retention.process_connection_revoke(project=self.project, operation_id=uuid.uuid4(), connection_object_id=connection.object_id, source=ZoomRemovalOperationSources.SKYTERRA_INITIATED)
        self.assertIsNone(result.completed_at)
        self.assertIsNotNone(result.target_object_id)
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())

    def test_expiry_during_connection_delete_rolls_back_target_and_receipt(self):
        connection = self.make_connection()
        clock = [timezone.now()]
        original_delete = ZoomOAuthConnection.delete

        def delete_then_expire(instance, *args, **kwargs):
            result = original_delete(instance, *args, **kwargs)
            clock[0] += timedelta(seconds=retention.LEASE_SECONDS + 1)
            return result

        with patch("bots.zoom_retention.timezone.now", side_effect=lambda: clock[0]), patch.object(retention, "_revoke_at_zoom", return_value=retention.ProviderOutcome(True)), patch.object(ZoomOAuthConnection, "delete", new=delete_then_expire):
            result = retention.process_connection_revoke(project=self.project, operation_id=uuid.uuid4(), connection_object_id=connection.object_id, source=ZoomRemovalOperationSources.SKYTERRA_INITIATED)
        self.assertIsNone(result.completed_at)
        self.assertIsNotNone(result.target_object_id)
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())

    def test_expiry_after_bot_lock_prevents_fence_writes(self):
        bot = self.make_bot()
        operation, token = retention._claim_operation(self.operation(bot))
        clock = [timezone.now()]
        original_get = QuerySet.get

        def get_after_wait(queryset, *args, **kwargs):
            result = original_get(queryset, *args, **kwargs)
            if queryset.model is Bot and queryset.query.select_for_update:
                clock[0] = operation.lease_expires_at
            return result

        with patch("bots.zoom_retention.timezone.now", side_effect=lambda: clock[0]), patch.object(QuerySet, "get", new=get_after_wait):
            with self.assertRaises(retention.LeaseLost):
                retention._fence_bot_for_removal(bot, operation.pk, token)
        bot.refresh_from_db()
        operation.refresh_from_db()
        self.assertIsNone(bot.removal_requested_at)
        self.assertIsNone(operation.target_generation)

    def test_expiry_during_data_deletion_rolls_back_database_changes(self):
        bot = self.make_bot()
        clock = [timezone.now()]
        original_delete = Bot.delete_data

        def delete_then_expire(instance):
            original_delete(instance)
            clock[0] += timedelta(seconds=retention.LEASE_SECONDS + 1)

        with patch("bots.zoom_retention.timezone.now", side_effect=lambda: clock[0]), patch.object(retention, "_delete_and_verify_storage", return_value=None), patch.object(Bot, "delete_data", new=delete_then_expire):
            result = retention.process_bot_purge(project=self.project, operation_id=uuid.uuid4(), bot_object_id=bot.object_id)
        self.assertIsNone(result.completed_at)
        self.assertEqual(result.phase, ZoomRemovalOperationPhases.STORAGE_VERIFIED)
        bot.refresh_from_db()
        self.assertEqual(bot.state, BotStates.ENDED)

    def test_expiry_during_final_bot_delete_rolls_back_row_and_proof(self):
        bot = self.make_bot()
        clock = [timezone.now()]
        original_delete = Bot.delete

        def delete_then_expire(instance, *args, **kwargs):
            result = original_delete(instance, *args, **kwargs)
            clock[0] += timedelta(seconds=retention.LEASE_SECONDS + 1)
            return result

        with patch("bots.zoom_retention.timezone.now", side_effect=lambda: clock[0]), patch.object(retention, "_delete_and_verify_storage", return_value=None), patch.object(Bot, "delete", new=delete_then_expire):
            result = retention.process_bot_purge(project=self.project, operation_id=uuid.uuid4(), bot_object_id=bot.object_id)
        self.assertIsNone(result.completed_at)
        self.assertEqual(result.phase, ZoomRemovalOperationPhases.DATA_DELETED)
        self.assertTrue(Bot.objects.filter(pk=bot.pk).exists())
