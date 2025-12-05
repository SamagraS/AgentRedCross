# main.py
import time
import threading

from core.orchestrator import Orchestrator
from core.database import init_db_pool

from agents.receptionist_agent import ReceptionistAgent
from agents.ehr_agent import EHRAgent
from agents.doctor_agent import DoctorAgent
from agents.lab_agent import LabAgent
from agents.access_control_agent import AccessControlAgent
from agents.privacy_guard import PrivacyGuardAgent
from agents.ids_agent import IDSAgent
from agents.audit_logger_agent import AuditLoggerAgent
from agents.doctor_scheduler_agent import DoctorSchedulerAgent


# -------------------------------------------------------
# SYSTEM INITIALIZATION
# -------------------------------------------------------

print("\n==============================")
print("🏥  MULTI-AGENT HOSPITAL SYSTEM (LIVE MODE)")
print("==============================\n")

init_db_pool()
orc = Orchestrator()

# Create agents
receptionist = ReceptionistAgent("receptionist_agent")
ehr = EHRAgent("ehr_agent")
doctor = DoctorAgent("doctor_agent", "Dr. John", "Cardiology")
lab = LabAgent("lab_agent")
access_control = AccessControlAgent("access_control_agent")
privacy = PrivacyGuardAgent("privacy_guard")
ids = IDSAgent("ids_agent")
audit = AuditLoggerAgent("audit_logger")
scheduler = DoctorSchedulerAgent("doctor_scheduler")

# Register agents
agents = [
    receptionist, ehr, doctor, lab,
    access_control, privacy, ids, audit, scheduler
]

for agent in agents:
    orc.register_agent(agent.agent_id, agent)

print("🎉 System boot completed. Agents online.\n")


# -------------------------------------------------------
# START ORCHESTRATOR LOOP (NON-BLOCKING)
# -------------------------------------------------------

threading.Thread(target=orc.start, daemon=True).start()
time.sleep(0.5)


# -------------------------------------------------------
# SIMULATED REAL WORKFLOW CALLS (NO DEMO LOGGING)
# -------------------------------------------------------

# Patient arrives at front desk
print("\n[System] Incoming patient → Reception desk")
receptionist.process_message({
    "action": "patient_intake",
    "data": {
        "name": "John Doe",
        "dob": "1980-01-01",
        "contact": "9876543210"
    }
})

time.sleep(1)

# Doctor fetches most recent patient (realistic behavior)
print("\n[System] Doctor is checking today's first patient...")

latest_patient = ehr.get_latest_patient_id()   # We will implement this small helper
doctor.process_message({
    "action": "retrieve_patient",
    "data": {"patient_id": latest_patient}
})

time.sleep(1)

# Doctor updates medical record
doctor.process_message({
    "action": "update_medical_record",
    "data": {
        "patient_id": latest_patient,
        "diagnosis": "Seasonal fever",
        "medications": "Paracetamol 500mg",
        "lab_results": None,
        "imaging_results": None
    }
})

time.sleep(1)

# Doctor sends lab test
# Doctor sends lab test
doctor.process_message({
    "action": "order_lab_test",
    "data": {
        "patient_id": latest_patient,
        "test_type": "blood_glucose",  # or 'cbc' if you add it to reference_ranges
        "priority": "routine"
    }
})


print("\n[System] Live workflow execution finished.\n")


time.sleep(1)
lab.batch_process_pending_orders()
