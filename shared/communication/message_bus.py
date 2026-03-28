# Message bus for inter-agent communication


# Redis-based Message Bus for inter-agent communication
import json
from datetime import datetime
from typing import Dict, Callable
import threading
import redis


class RedisMessageBus:
    def __init__(self, host="localhost", port=6379, db=0):
        self.redis = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self.sub_threads = []

    def publish(self, channel: str, message: Dict):
        # Add timestamp and channel info
        msg = {**message, "timestamp": datetime.now().isoformat(), "channel": channel}
        self.redis.publish(channel, json.dumps(msg))
        print(
            f"[RedisMessageBus] Published to '{channel}': {message.get('type', 'unknown')}"
        )

    def subscribe(self, channel: str, callback: Callable):
        def listen():
            pubsub = self.redis.pubsub()
            pubsub.subscribe(channel)
            print(f"[RedisMessageBus] Subscribed to '{channel}'")
            for item in pubsub.listen():
                if item["type"] == "message":
                    try:
                        msg = json.loads(item["data"])
                        callback(msg)
                    except Exception as e:
                        print(f"[RedisMessageBus] Error: {e}")

        t = threading.Thread(target=listen, daemon=True)
        t.start()
        self.sub_threads.append(t)

    def heartbeat(self, agent_id: str, status: str = "running"):
        """Write agent heartbeat to Redis for dashboard monitoring"""
        now = datetime.now().isoformat()
        # setex = SET with EXpiry. Key auto-deletes after 30 seconds
        # if agent fails to update, it will appear "Stopped"
        self.redis.setex(f"agent:{agent_id}:heartbeat", 30, now)
        self.redis.setex(f"agent:{agent_id}:status", 30, status)


# Global message bus instance
message_bus = RedisMessageBus()
