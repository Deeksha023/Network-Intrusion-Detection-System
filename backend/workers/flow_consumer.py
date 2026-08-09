"""
workers/flow_consumer.py — Redis Stream consumer: the real-time processing loop.

This is the central worker process.  It continuously reads from the Redis
Stream `ids:flows` (written by ingestion/producer.py or the API's /ingest
endpoints), runs each flow through the full ML pipeline, persists the result
to PostgreSQL, and broadcasts new alerts over WebSocket.

Consumer group pattern:
    Group:    ids-workers
    Consumer: worker-<hostname>-<pid>
    Stream:   ids:flows

Using a consumer group (rather than plain XREAD) ensures that:
  - Each message is processed exactly once even if multiple workers run.
  - Unacknowledged messages are recoverable after a crash (XPENDING / XCLAIM).

Run with:
    python -m workers.flow_consumer
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import asyncio
import json
import logging
import signal
import socket
import time
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from feature_extraction.extractor import extract_features
from ml.pipeline import DetectionPipeline
from workers.alert_broadcaster import broadcast_alert
from api.dependencies import get_redis_url

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
STREAM_NAME = "ids:flows"
GROUP_NAME = "ids-workers"
CONSUMER_NAME = f"worker-{socket.gethostname()}-{os.getpid()}"
BLOCK_MS = 5_000          # Block on XREADGROUP for up to 5 s before looping
BATCH_SIZE = 10           # Max messages to read per XREADGROUP call

# ---------------------------------------------------------------------------
# Globals (initialised in main)
# ---------------------------------------------------------------------------
_running: bool = True
_pipeline: DetectionPipeline | None = None


def _handle_sigterm(signum: int, frame: Any) -> None:
    """Graceful shutdown on SIGTERM / SIGINT."""
    global _running
    logger.info("Received signal %d — shutting down worker gracefully...", signum)
    _running = False


# ---------------------------------------------------------------------------
# Stream group bootstrap
# ---------------------------------------------------------------------------
async def _ensure_consumer_group(redis: aioredis.Redis) -> None:
    """Create the consumer group if it doesn't exist yet."""
    try:
        await redis.xgroup_create(STREAM_NAME, GROUP_NAME, id="0", mkstream=True)
        logger.info("Consumer group '%s' created on stream '%s'", GROUP_NAME, STREAM_NAME)
    except ResponseError as e:
        if "BUSYGROUP" in str(e):
            logger.debug("Consumer group '%s' already exists — OK", GROUP_NAME)
        else:
            raise


# ---------------------------------------------------------------------------
# Message processing
# ---------------------------------------------------------------------------
async def _process_message(
    redis: aioredis.Redis,
    message_id: str,
    fields: dict[str, str],
) -> None:
    """
    Process a single flow message from the Redis Stream.

    Steps:
      1. Deserialise fields → flow dict
      2. Extract feature vector (78-element numpy array)
      3. Run ML pipeline → alert dict
      4. Persist FlowRecord + Alert to PostgreSQL
      5. Broadcast alert over WebSocket
      6. Acknowledge the message (XACK)
    """
    try:
        # --- Step 1: Deserialise ------------------------------------------------
        flow_dict: dict[str, Any] = {}
        for k, v in fields.items():
            try:
                flow_dict[k] = float(v) if k not in ("src_ip", "dst_ip", "protocol") else v
            except ValueError:
                flow_dict[k] = v

        # --- Step 2: Feature extraction -----------------------------------------
        features = extract_features(flow_dict)

        # --- Step 3: ML pipeline ------------------------------------------------
        assert _pipeline is not None
        alert = _pipeline.run(features)

        # --- Step 4: Persist to DB ----------------------------------------------
        from db.session import AsyncSessionLocal
        from db.models import FlowRecord, Alert

        async with AsyncSessionLocal() as session:
            flow_record = FlowRecord(
                src_ip=str(flow_dict.get("src_ip", "0.0.0.0")),
                dst_ip=str(flow_dict.get("dst_ip", "0.0.0.0")),
                src_port=int(flow_dict.get("src_port", 0)),
                dst_port=int(flow_dict.get("dst_port", 0)),
                protocol=str(flow_dict.get("protocol", "TCP")),
                features={
                    k: v for k, v in flow_dict.items()
                    if k not in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")
                },
            )
            session.add(flow_record)
            await session.flush()

            alert_row = Alert(
                id=alert["id"],
                timestamp=alert["timestamp"],
                flow_id=flow_record.id,
                stage=alert["stage"],
                attack_type=alert.get("attack_type"),
                confidence=alert["confidence"],
                severity=alert["severity"],
                reconstruction_error=alert.get("reconstruction_error"),
                shap_values=alert.get("shap_values"),
                raw_features=alert.get("raw_features", {}),
            )
            session.add(alert_row)
            await session.commit()
            logger.info("Persisted FlowRecord %s and Alert %s (Stage %d, %s)", flow_record.id, alert_row.id, alert_row.stage, alert_row.attack_type or "Anomaly")

        # --- Step 5: WebSocket broadcast ----------------------------------------
        await broadcast_alert(alert)

        # --- Step 6: Acknowledge ------------------------------------------------
        await redis.xack(STREAM_NAME, GROUP_NAME, message_id)
        logger.debug("Processed and ACK'd message %s", message_id)

    except Exception:
        logger.exception("Error processing message %s — will not ACK (pending for retry)", message_id)


# ---------------------------------------------------------------------------
# Main consumer loop
# ---------------------------------------------------------------------------
async def _consumer_loop(redis: aioredis.Redis) -> None:
    """Continuously read from the Redis Stream and process each message."""
    global _running
    logger.info(
        "Worker '%s' starting consumer loop on stream '%s' group '%s'",
        CONSUMER_NAME, STREAM_NAME, GROUP_NAME,
    )
    while _running:
        try:
            # Publish periodic worker heartbeat (15s TTL)
            await redis.set("ids:worker:heartbeat", str(time.time()), ex=15)

            # XREADGROUP returns: [[stream_name, [(msg_id, {field: value}), ...]]]
            response = await redis.xreadgroup(
                groupname=GROUP_NAME,
                consumername=CONSUMER_NAME,
                streams={STREAM_NAME: ">"},   # ">" = only undelivered messages
                count=BATCH_SIZE,
                block=BLOCK_MS,
            )
            if not response:
                continue  # Timeout — loop again

            for _stream_name, messages in response:
                for message_id, fields in messages:
                    await _process_message(redis, message_id, fields)

        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Unexpected error in consumer loop — retrying in 2 s")
            await asyncio.sleep(2)

    logger.info("Consumer loop exited cleanly.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
async def main() -> None:
    global _pipeline

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, _handle_sigterm)
    from dotenv import load_dotenv
    load_dotenv()

    redis_url = get_redis_url()
    logger.info("Connecting to Redis at %s", redis_url)
    redis = aioredis.Redis.from_url(redis_url, encoding="utf-8", decode_responses=True, protocol=2)

    # Initialise the ML pipeline (loads model stubs; will be real once trained)
    _pipeline = DetectionPipeline()

    # Ensure the consumer group exists
    await _ensure_consumer_group(redis)

    # Run the main processing loop
    await _consumer_loop(redis)

    # Cleanup
    await redis.aclose()
    logger.info("Worker shutdown complete.")


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        stream=sys.stdout,
    )
    asyncio.run(main())
