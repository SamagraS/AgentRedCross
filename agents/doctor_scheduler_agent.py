# agents/doctor_scheduler_agent.py
from datetime import datetime, timedelta
from agents.base_agent import BaseAgent

class DoctorSchedulerAgent(BaseAgent):
    """
    Simple scheduler that assigns the next available doctor time.
    """

    def __init__(self, agent_id="doctor_scheduler"):
        super().__init__(
            agent_id=agent_id,
            role="scheduler",
            permissions=["schedule_doctor"]
        )

    def process_message(self, message):
        action = message.get("action")
        data = message.get("data", {})

        if action == "schedule_next_available":
            patient_id = data.get("patient_id")
            appointment_time = (datetime.now() + timedelta(minutes=15)).isoformat()

            print(f"[Scheduler] Scheduled doctor appointment for patient {patient_id} at {appointment_time}")

            return {
                "status": "scheduled",
                "patient_id": patient_id,
                "appointment_time": appointment_time
            }

        return {"status": "error", "message": f"Unknown action {action}"}
