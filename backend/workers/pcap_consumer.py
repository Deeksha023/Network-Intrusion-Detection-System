"""
workers/pcap_consumer.py — Redis Stream consumer for offline PCAP replay jobs.

Listens to Redis stream `ids:pcap_jobs`, extracts flows from uploaded .pcap files,
and publishes generated flow dictionaries to `ids:flows` for downstream ML processing.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from api.dependencies import get_redis_url
from ingestion.replay import parse_pcap

logger = logging.getLogger(__name__)

STREAM_NAME = "ids:pcap_jobs"
GROUP_NAME = "pcap_processors"
CONSUMER_NAME = f"pcap_worker_{os.getpid()}"

_running = True


def _handle_sigterm(signum: int, frame: Any) -> None:
    global _running
    logger.info("Signal %d received — initiating graceful shutdown of PCAP worker...", signum)
    _running = False


async def _init_consumer_group(redis: aioredis.Redis) -> None:
    """Ensure the Redis Stream and Consumer Group exist."""
    try:
        await redis.xgroup_create(STREAM_NAME, GROUP_NAME, id="0", mkstream=True)
        logger.info("Created consumer group '%s' for stream '%s'", GROUP_NAME, STREAM_NAME)
    except ResponseError as e:
        if "BUSYGROUP" in str(e):
            logger.debug("Consumer group '%s' already exists", GROUP_NAME)
        else:
            logger.warning("Could not create consumer group: %s", e)
    except Exception as e:
        if "BUSYGROUP" in str(e):
            logger.debug("Consumer group '%s' already exists", GROUP_NAME)
        else:
            logger.warning("Could not create consumer group: %s", e)


async def _process_pcap_job(redis: aioredis.Redis, message_id: str, fields: dict[str, str]) -> None:
    """Read PCAP job payload, run flow builder extraction, and push flows to ids:flows."""
    job_id = fields.get("job_id", "unknown")
    filepath = fields.get("filepath", "")

    logger.info("Processing PCAP job %s for file: %s", job_id, filepath)

    if not os.path.exists(filepath):
        error_msg = f"PCAP file not found: {filepath}"
        logger.error(error_msg)
        await redis.hset(f"ids:pcap_job:{job_id}", mapping={
            "status": "failed",
            "error": error_msg,
            "failed_at": str(asyncio.get_event_loop().time()),
        })
        return

    try:
        await redis.hset(f"ids:pcap_job:{job_id}", mapping={"status": "processing"})

        # Extract flows synchronously in thread pool to avoid blocking async loop
        loop = asyncio.get_running_loop()
        flows = await loop.run_in_executor(None, parse_pcap, filepath)

        logger.info("Extracted %d flows from PCAP job %s. Publishing to ids:flows...", len(flows), job_id)

        # Publish flows to ids:flows Redis stream
        pipeline = redis.pipeline()
        for flow in flows:
            payload = {k: str(v) for k, v in flow.items()}
            pipeline.xadd("ids:flows", payload)
        await pipeline.execute()

        await redis.hset(f"ids:pcap_job:{job_id}", mapping={
            "status": "completed",
            "total_flows": len(flows),
            "completed_at": str(asyncio.get_event_loop().time()),
        })
        logger.info("Successfully completed PCAP job %s (%d flows)", job_id, len(flows))

    except Exception as e:
        logger.exception("Error processing PCAP job %s: %s", job_id, e)
        await redis.hset(f"ids:pcap_job:{job_id}", mapping={
            "status": "failed",
            "error": str(e),
            "failed_at": str(asyncio.get_event_loop().time()),
        })


async def main() -> None:
    global _running

    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT, _handle_sigterm)

    redis_url = get_redis_url()
    logger.info("Connecting PCAP worker to Redis at %s", redis_url)
    redis = aioredis.Redis.from_url(redis_url, encoding="utf-8", decode_responses=True, protocol=2)

    await _init_consumer_group(redis)

    logger.info("PCAP Consumer Worker '%s' ready. Listening on '%s'...", CONSUMER_NAME, STREAM_NAME)

    while _running:
        try:
            entries = await redis.xreadgroup(
                groupname=GROUP_NAME,
                consumername=CONSUMER_NAME,
                streams={STREAM_NAME: ">"},
                count=1,
                block=2000,
            )

            if not entries:
                continue

            for _, message_list in entries:
                for message_id, fields in message_list:
                    await _process_pcap_job(redis, message_id, fields)
                    await redis.xack(STREAM_NAME, GROUP_NAME, message_id)
                    logger.debug("ACK'd PCAP job message %s", message_id)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Error in PCAP worker loop: %s", e)
            await asyncio.sleep(1)

    await redis.aclose()
    logger.info("PCAP worker exited cleanly.")


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        stream=sys.stdout,
    )
    asyncio.run(main())
