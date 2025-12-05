# core/orchestrator.py
"""
Orchestrator: central coordinator that wires agents together and dispatches messages.

Responsibilities:
- Hold references to agents (agent_id -> agent_object)
- Maintain EventQueue and register agents for fast routing
- Pull messages from queue and deliver to the target agent
- Optionally capture synchronous return values from process_message
- Simple auditing / visibility into message flows for demo

Notes:
- This orchestrator performs synchronous delivery for simplicity (suitable for hackathon).
- To scale/up, replace the loop with async workers or threads and persist queue to Redis/RabbitMQ.
"""

import time
from typing import Dict, Any
from core.event_queue import EventQueue


class Orchestrator:
    def __init__(self, poll_interval: float = 0.05):
        self.queue = EventQueue()
        self.agents: Dict[str, object] = {}  # agent_id -> agent instance
        self.poll_interval = poll_interval
        self.running = False

    # --------------------------
    # Agent management
    # --------------------------
    def register_agent(self, agent_id: str, agent_obj) -> None:
        """
        Register an agent instance with the orchestrator.
        The agent will receive an event_queue reference so it can send messages.
        """
        agent_obj.event_queue = self.queue
        self.agents[agent_id] = agent_obj
        # Register agent for direct routing (fast-path)
        self.queue.register(agent_id, agent_obj)
        print(f"[Orchestrator] Registered agent: {agent_id}")

    def unregister_agent(self, agent_id: str) -> None:
        if agent_id in self.agents:
            self.agents[agent_id].event_queue = None
            del self.agents[agent_id]
            self.queue.unregister(agent_id)
            print(f"[Orchestrator] Unregistered agent: {agent_id}")

    # --------------------------
    # Message dispatching
    # --------------------------
    def dispatch_message(self, message: Dict[str, Any]) -> Any:
        """
        Deliver message to the intended recipient. Returns recipient's response if any.
        Strategy:
        1. If EventQueue.route_if_possible handles it, we return None (recipient handled inline).
        2. Otherwise, look up agent by id and call process_message synchronously.
        3. If recipient missing, write a warning and return an error envelope.
        """
        # Fast-path: let the queue attempt a direct route to a registered subscriber
        handled = False  # disable fast-path


        target = message.get("to")
        if not target:
            return {"status": "error", "message": "Message missing 'to' field"}

        agent = self.agents.get(target)
        if not agent:
            # Optionally log to audit_logger if registered
            print(f"[Orchestrator] No agent registered under id '{target}'. Dropping message.")
            return {"status": "error", "message": f"No agent '{target}'"}

        try:
            response = agent.process_message(message)
            return response
        except Exception as exc:
            print(f"[Orchestrator] Exception while processing message for {target}: {exc}")
            return {"status": "error", "message": str(exc)}

    # --------------------------
    # Event loop
    # --------------------------
    def start(self):
        """Start the orchestrator loop (blocking)."""
        self.running = True
        print("[Orchestrator] Starting main loop...")
        try:
            while self.running:
                msg = self.queue.pop()
                if msg:
                    # Basic visibility for demo: print a concise trace
                    print(f"[Orc] Dispatching {msg.get('action')} from {msg.get('from')} -> {msg.get('to')}")
                    resp = self.dispatch_message(msg)
                    # If the response is a dict and has a 'reply_to' or similar, you can route it.
                    # For hackathon, agents can send their own messages back into queue.
                    if resp is not None:
                        # Optionally publish response to any 'reply_to' address inside message
                        reply_to = msg.get("reply_to")
                        if reply_to:
                            self.queue.push({
                                "from": msg.get("to"),
                                "to": reply_to,
                                "action": "response",
                                "data": resp,
                                "timestamp": msg.get("timestamp")
                            })
                else:
                    time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            print("[Orchestrator] Interrupted by user.")
        finally:
            self.running = False
            print("[Orchestrator] Stopped.")

    def stop(self):
        self.running = False
