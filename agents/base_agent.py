# base_agent.py
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any


class BaseAgent(ABC):
    """
    The foundation for all hospital agents.
    Handles messaging, permission checks, audit logging.
    """

    def __init__(self, agent_id: str, role: str, permissions: list):
        self.agent_id = agent_id
        self.role = role
        self.permissions = permissions  # ['read_patient', 'write_record', etc.]
        self.event_queue = None  # Injected by orchestrator

    @abstractmethod
    def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """All agents must implement this message router."""
        pass

    # -------------------------------------------------------------------------
    # MESSAGE SENDING
    # -------------------------------------------------------------------------
    def send_message(self, target_agent: str, action: str, data: Dict, reply_to: str = None):
        message = {
            "from": self.agent_id,
            "to": target_agent,
            "action": action,
            "data": data,
            "timestamp": datetime.now().isoformat()
        }
        if reply_to:
            message["reply_to"] = reply_to

        if self.event_queue:
            self.event_queue.push(message)
        else:
            print("[WARNING] Event queue not set on", self.agent_id)


    # -------------------------------------------------------------------------
    # PERMISSIONS
    # -------------------------------------------------------------------------
    def check_permission(self, action: str) -> bool:
        return action in self.permissions

    # -------------------------------------------------------------------------
    # AUDIT LOGGING
    # -------------------------------------------------------------------------
    def audit_log(self, action: str, patient_id: str, details: str):
        """Send audit event to Audit Logger Agent."""
        log_entry = {
            "agent_id": self.agent_id,
            "action": action,
            "patient_id": patient_id,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }

        self.send_message(
            target_agent="audit_logger",
            action="log_event",
            data=log_entry
        )
