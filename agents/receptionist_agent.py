# receptionist_agent.py
from typing import Dict, Any
from datetime import datetime
from agents.base_agent import BaseAgent

class ReceptionistAgent(BaseAgent):
    """
    Handles patient intake:
    - Registers patient (via EHR Agent)
    - Schedules doctor
    - Logs events
    """

    def __init__(self, agent_id: str):
        super().__init__(
            agent_id=agent_id,
            role="receptionist",
            permissions=[
                "create_patient",
                "read_patient_basics",
                "update_appointment",
                "schedule_doctor"
            ]
        )
        self.last_patient_id = None

    # -------------------------------------------------------------------------
    # MESSAGE ROUTER
    # -------------------------------------------------------------------------
    def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        action = message.get("action")

        # Handle asynchronous reply from EHR Agent
        if action == "response":
            data = message.get("data", {})
            if "patient_id" in data:
                self.last_patient_id = data["patient_id"]
                print(f"[Receptionist] ✔ Received real patient_id: {self.last_patient_id}")

                # Continue workflow after receiving UUID
                self._finalize_intake(self.last_patient_id)

            return {"status": "ok"}

        if action == "patient_intake":
            return self.handle_patient_intake(message["data"])

        return {"status": "error", "message": f"Unknown action {action}"}

    # -------------------------------------------------------------------------
    # PATIENT INTAKE WORKFLOW
    # -------------------------------------------------------------------------
    def handle_patient_intake(self, patient_data: Dict[str, Any]) -> Dict[str, Any]:

        # 1. Validate permission
        if not self.check_permission("create_patient"):
            return {"status": "denied", "reason": "Permission denied"}

        # 2. Ask EHR Agent to create the patient
        self.send_message(
            target_agent="ehr_agent",
            action="create_patient",
            data=patient_data,
            reply_to=self.agent_id
        )

        # Wait for EHR to reply with patient_id
        print("[Receptionist] Waiting for patient_id from EHR...")

        return {"status": "processing", "message": "Waiting for EHR to return patient_id"}

    # -------------------------------------------------------------------------
    # FINALIZE INTAKE AFTER RECEIVING PATIENT UUID
    # -------------------------------------------------------------------------
    def _finalize_intake(self, patient_id):

        # 3. Audit creation
        self.audit_log(
            action="patient_registered",
            patient_id=patient_id,
            details="Receptionist registered new patient."
        )

        # 4. Schedule doctor
        self.send_message(
            target_agent="doctor_scheduler",
            action="schedule_next_available",
            data={"patient_id": patient_id}
        )

        # 5. Update appointment in EHR
        self.send_message(
            target_agent="ehr_agent",
            action="update_appointment",
            data={
                "patient_id": patient_id,
                "appointment_time": datetime.now().isoformat()
            }
        )

        # Audit appointment scheduling
        self.audit_log(
            action="doctor_scheduled",
            patient_id=patient_id,
            details="Appointment scheduled within 15 minutes."
        )
