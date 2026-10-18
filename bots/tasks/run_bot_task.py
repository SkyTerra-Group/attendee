import logging
import os
import signal
import uuid

from celery import shared_task
from celery.signals import worker_shutting_down

from bots.bot_controller import BotController
from bots.bot_runtime_fence import claim_bot_runtime_launch, complete_bot_runtime_launch, runtime_launch_is_allowed

logger = logging.getLogger(__name__)


# SkyTerra: the upstream value (3600s) is measured from when the WORKER PICKS THE
# TASK UP, not from when the bot is admitted to the meeting. A bot dispatched
# 10 minutes early therefore has ~50 minutes of meeting left, and when the limit
# fires Celery raises SoftTimeLimitExceeded INSIDE the task: the bot is torn out
# of a LIVE call and post-processing never runs, so the recording it already made
# is LOST (2026-09-02 bot_bdHe6itHEXbIqKiS: recording_state/transcription_state
# both "complete" provider-side, transcript_id NULL app-side).
#
# Env-tunable here (upstream hardcodes it). Ordering that must hold on the
# worker's dockerCommand and the broker:
#     soft (this, 10800) < hard --time-limit (12000) < visibility_timeout (14400)
# If this is raised, raise those too, and set BOT_PROVIDER_SOFT_CAP_SECONDS on
# the engagement app to match so its handoff sweep stops guessing.
BOT_SOFT_TIME_LIMIT_SECONDS = int(os.getenv("BOT_SOFT_TIME_LIMIT_SECONDS", "10800"))


@shared_task(bind=True, soft_time_limit=BOT_SOFT_TIME_LIMIT_SECONDS)
def run_bot(self, bot_id, runtime_generation=None):
    logger.info(f"Running bot {bot_id}")
    if runtime_generation is None:
        bot = claim_bot_runtime_launch(bot_id, "celery")
        if bot is None:
            return
        generation = bot.runtime_generation
    else:
        try:
            generation = uuid.UUID(str(runtime_generation))
        except (TypeError, ValueError):
            return
        if not runtime_launch_is_allowed(bot_id, generation):
            return
    try:
        bot_controller = BotController(bot_id)
        bot_controller.run()
    finally:
        complete_bot_runtime_launch(bot_id, generation)


def kill_child_processes():
    # Get the process group ID (PGID) of the current process
    pgid = os.getpgid(os.getpid())

    try:
        # Send SIGTERM to all processes in the process group
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass  # Process group may no longer exist


@worker_shutting_down.connect
def shutting_down_handler(sig, how, exitcode, **kwargs):
    # Just adding this code so we can see how to shut down all the tasks
    # when the main process is terminated.
    # It's likely overkill.
    logger.info("Celery worker shutting down, sending SIGTERM to all child processes")
    kill_child_processes()
