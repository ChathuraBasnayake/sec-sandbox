"""Kafka consumer that buffers syscall events per detonation session."""

import json
import time
from collections import defaultdict

from kafka import KafkaConsumer

from .models import SyscallEvent


def consume_detonations(broker: str, topic: str, idle_timeout: float = 8.0):
    """Yield complete detonation event batches from Kafka.
    
    Groups events by detonation_id and yields the batch when no new events
    arrive for `idle_timeout` seconds (meaning the detonation is complete).
    
    Yields:
        tuple[str, str, list[SyscallEvent]]: (package_name, detonation_id, events)
    """
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=broker,
        auto_offset_reset="latest",  # Only process new detonations
        enable_auto_commit=True,
        group_id=None,  # No consumer group — always read latest
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    )
    
    print(f"  📡 Listening on Kafka topic '{topic}' at {broker}...")
    print(f"  ⏱  Idle timeout: {idle_timeout}s (detonation considered complete after {idle_timeout}s of silence)")
    print()
    
    # Buffer: detonation_id -> list of events
    buffers: dict[str, list[SyscallEvent]] = defaultdict(list)
    metadata: dict[str, str] = {}  # detonation_id -> package_name
    last_seen: dict[str, float] = {}  # detonation_id -> last event timestamp
    
    try:
        while True:
            # Use poll() instead of iterator — much more reliable
            raw = consumer.poll(timeout_ms=2000, max_records=500)
            
            msg_count = 0
            for tp, messages in raw.items():
                for message in messages:
                    msg_count += 1
                    try:
                        event = SyscallEvent(**message.value)
                        det_id = event.detonation_id
                        buffers[det_id].append(event)
                        metadata[det_id] = event.package_name
                        last_seen[det_id] = time.time()
                    except Exception:
                        continue
            
            if msg_count > 0:
                active = ", ".join(
                    f"{metadata.get(d, '?')}({len(buffers[d])})"
                    for d in buffers
                )
                print(f"\r  📥 Receiving: {active}   ", end="", flush=True)
            
            # Check for completed detonations (idle for > idle_timeout)
            now = time.time()
            completed = [
                det_id for det_id, ts in last_seen.items()
                if now - ts > idle_timeout
            ]
            
            for det_id in completed:
                events = buffers.pop(det_id)
                pkg_name = metadata.pop(det_id, "unknown")
                del last_seen[det_id]
                print()  # Clear the buffering line
                yield pkg_name, det_id, events
    
    except KeyboardInterrupt:
        print("\n  ⛔ Consumer stopped.")
    finally:
        consumer.close()
