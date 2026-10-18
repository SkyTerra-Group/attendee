"""Generation-bound launch fencing and runtime-absence proof for bot removal."""

from __future__ import annotations

import os
import uuid

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from bots.models import Bot, BotStates


def configured_runtime_backend() -> str:
    return os.getenv("LAUNCH_BOT_METHOD", "celery") or "celery"


def claim_bot_runtime_launch(bot_id: int, backend: str | None = None) -> Bot | None:
    """Fence a launch against removal and assign a fresh runtime generation."""

    with transaction.atomic():
        bot = Bot.objects.select_for_update().get(pk=bot_id)
        if bot.removal_requested_at is not None or bot.runtime_launch_in_progress:
            return None
        bot.runtime_generation = uuid.uuid4()
        bot.runtime_backend = backend or configured_runtime_backend()
        bot.runtime_identifier = None
        bot.runtime_launch_started_at = timezone.now()
        bot.runtime_launch_completed_at = None
        bot.runtime_launch_in_progress = True
        bot.runtime_absence_confirmed_at = None
        bot.runtime_absence_generation = None
        bot.save(
            update_fields=[
                "runtime_generation",
                "runtime_backend",
                "runtime_identifier",
                "runtime_launch_started_at",
                "runtime_launch_completed_at",
                "runtime_launch_in_progress",
                "runtime_absence_confirmed_at",
                "runtime_absence_generation",
                "updated_at",
            ]
        )
        return bot


def runtime_launch_is_allowed(bot_id: int, generation: uuid.UUID) -> bool:
    return Bot.objects.filter(
        pk=bot_id,
        runtime_generation=generation,
        runtime_launch_in_progress=True,
        removal_requested_at__isnull=True,
    ).exists()


def complete_bot_runtime_launch(bot_id: int, generation: uuid.UUID, *, runtime_identifier: str | None = None) -> None:
    """Record that the generation's launcher finished without crossing a fence."""

    with transaction.atomic():
        bot = Bot.objects.select_for_update().filter(pk=bot_id, runtime_generation=generation).first()
        if bot is None:
            return
        if runtime_identifier:
            bot.runtime_identifier = runtime_identifier
        bot.runtime_launch_in_progress = False
        bot.runtime_launch_completed_at = timezone.now()
        bot.save(update_fields=["runtime_identifier", "runtime_launch_in_progress", "runtime_launch_completed_at", "updated_at"])


def _kubernetes_runtime_is_absent(bot: Bot) -> bool:
    try:
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        api = client.CoreV1Api()
        pod_namespaces = [(bot.k8s_pod_name(), settings.BOT_POD_NAMESPACE)]
        if bot.should_launch_webpage_streamer():
            pod_namespaces.append((f"{bot.k8s_pod_name()}-webpage-streamer", settings.WEBPAGE_STREAMER_POD_NAMESPACE))
        for pod_name, namespace in pod_namespaces:
            try:
                pod = api.read_namespaced_pod(name=pod_name, namespace=namespace)
            except client.ApiException as error:
                if error.status == 404:
                    continue
                return False
            # Presence always blocks deletion.  When known, also bind the
            # observation to the exact generation's provider identity.
            pod_uid = str(getattr(getattr(pod, "metadata", None), "uid", "") or "")
            if pod_name != bot.k8s_pod_name() or not bot.runtime_identifier or pod_uid != bot.runtime_identifier:
                return False
            try:
                api.delete_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body=client.V1DeleteOptions(
                        grace_period_seconds=60,
                        preconditions=client.V1Preconditions(uid=pod_uid),
                    ),
                )
                api.read_namespaced_pod(name=pod_name, namespace=namespace)
                return False
            except client.ApiException as error:
                if error.status == 404:
                    continue
                return False
        return True
    except Exception:
        return False


def _docker_runtime_is_absent(bot: Bot) -> bool:
    try:
        import docker

        try:
            container = docker.from_env().containers.get(bot.ephemeral_container_name())
        except docker.errors.NotFound:
            return True
        container_id = str(getattr(container, "id", "") or "")
        if not bot.runtime_identifier or container_id != bot.runtime_identifier:
            return False
        container.stop(timeout=60)
        container.reload()
        return container.status not in {"created", "restarting", "running"}
    except Exception:
        return False


def bot_runtime_is_absent(bot: Bot) -> bool:
    """Return true only from an independently checkable, fenced absence fact."""

    if bot.removal_requested_at is None or bot.runtime_launch_in_progress:
        return False
    if bot.state in {BotStates.SCHEDULED, BotStates.STAGED} and bot.runtime_launch_started_at is None and bot.first_heartbeat_timestamp is None:
        return True

    backend = bot.runtime_backend or configured_runtime_backend()
    if backend == "kubernetes":
        return _kubernetes_runtime_is_absent(bot)
    if backend == "docker-compose-multi-host":
        return _docker_runtime_is_absent(bot)
    if backend == "celery":
        # The runner's own completion is the only identity-bound Celery
        # absence proof.  Cleanup state alone never substitutes for it.
        return bot.runtime_launch_started_at is not None and bot.runtime_launch_completed_at is not None
    return False


def confirm_bot_runtime_absence(bot_id: int) -> Bot | None:
    """Persist an absence proof only if its generation remains fenced."""

    bot = Bot.objects.get(pk=bot_id)
    generation = bot.runtime_generation
    if not bot_runtime_is_absent(bot):
        return None
    with transaction.atomic():
        locked = Bot.objects.select_for_update().filter(pk=bot_id, runtime_generation=generation).first()
        if locked is None or locked.removal_requested_at is None or locked.runtime_launch_in_progress:
            return None
        locked.runtime_absence_generation = generation
        locked.runtime_absence_confirmed_at = timezone.now()
        locked.save(update_fields=["runtime_absence_generation", "runtime_absence_confirmed_at", "updated_at"])
        return locked
