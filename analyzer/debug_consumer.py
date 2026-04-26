"""Quick Kafka consumer debug script — bypasses the full analyzer."""

import json
import sys
from kafka import KafkaConsumer

broker = "localhost:9092"
topic = "syscall-telemetry"

print(f"[DEBUG] Connecting to {broker}, topic={topic}")
print(f"[DEBUG] Using auto_offset_reset=earliest, no group_id")
print()

try:
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=broker,
        auto_offset_reset="earliest",  # Read ALL messages from start
        group_id=None,  # No consumer group = no offset tracking
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        consumer_timeout_ms=10000,  # Wait up to 10s
    )

    count = 0
    for msg in consumer:
        count += 1
        val = msg.value
        print(f"  [{count}] {val.get('event_type', '?'):6s} | {val.get('process_name', '?'):15s} → {val.get('filename', '?')[:50]}")
        if count >= 10:
            print(f"\n  ... showing first 10 of potentially more messages")
            break

    if count == 0:
        print("  ❌ No messages found! Possible issues:")
        print("     1. Kafka not running?")
        print("     2. Topic doesn't exist?")
        print("     3. No messages in topic?")
        print()
        print("  Checking topic list...")
        topics = consumer.topics()
        print(f"  Available topics: {topics}")
    else:
        print(f"\n  ✅ Successfully read {count} messages from Kafka")

    consumer.close()

except Exception as e:
    print(f"  ❌ Error: {e}")
    import traceback
    traceback.print_exc()
