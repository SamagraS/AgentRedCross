import sys, os
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
from core.database import init_db_pool
from database.db_pool import PostgresPool

# Initialize DB pool only once
if PostgresPool.pool is None:
    init_db_pool()


import streamlit as st
from datetime import date
from agents.ehr_agent import EHRAgent
from agents.doctor_agent import DoctorAgent

# ========== INITIALIZE AGENTS ==========
ehr = EHRAgent("ehr_agent")
doctor = DoctorAgent("doctor_agent", "Dr. John", "Cardiology")

# ========== PAGE CONFIG ==========
st.set_page_config(
    page_title="AgentRedCross Hospital AI",
    page_icon="🏥",
    layout="wide",
)

# ========== CUSTOM CSS FOR BEAUTIFUL UI ==========
st.markdown("""
<style>
/* Clean dashboard-like styling */
body {
    background-color: #F7F9FC;
}

/* Big header */
.big-title {
    font-size: 42px !important;
    font-weight: 700 !important;
    color: #1A73E8;
}

/* Section headers */
.section-title {
    font-size: 26px;
    font-weight: 650;
    margin-top: 25px;
}

/* Cards */
.card {
    background: white;
    padding: 22px 28px;
    border-radius: 14px;
    box-shadow: 1px 3px 12px rgba(0,0,0,0.08);
    margin-bottom: 25px;
}

/* Buttons */
.stButton button {
    width: 100%;
    background: linear-gradient(90deg, #1A73E8, #4285F4);
    color: white;
    border-radius: 8px;
    padding: 10px 0px;
    font-size: 17px;
    border: none;
}
.stButton button:hover {
    background: linear-gradient(90deg, #1665cc, #2f77da);
}
</style>
""", unsafe_allow_html=True)

# ========== MAIN TITLE ==========
st.markdown("<div class='big-title'>🏥 AgentRedCross – AI Hospital System</div>", unsafe_allow_html=True)
st.write("### Live multi-agent collaboration: EHR, Doctors, Lab, Privacy & Access Control")

st.write("---")

# ========== LAYOUT 2 COLUMN ==========
col1, col2 = st.columns([1.2, 1])

# ============================================================
# LEFT COLUMN — INTERACTIVE CONTROLS
# ============================================================
with col1:

    st.markdown("<div class='section-title'>🧍 Register New Patient</div>", unsafe_allow_html=True)
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        name = st.text_input("Full Name")
        dob = st.date_input("Date of Birth", date(1990, 1, 1))
        contact = st.text_input("Contact Number")

        if st.button("Register Patient"):
            result = ehr.process_message({
                "action": "create_patient",
                "data": {
                    "name": name,
                    "dob": dob.isoformat(),
                    "contact": contact
                }
            })

            st.success(f"Patient Registered Successfully! 🆔 ID: **{result['patient_id']}**")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='section-title'>🔎 Retrieve Patient Record</div>", unsafe_allow_html=True)
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        retrieve_id = st.text_input("Enter Patient ID to Retrieve")

        if st.button("Retrieve Record"):
            doctor.process_message({
                "action": "retrieve_patient",
                "data": { "patient_id": retrieve_id }
            })
            st.success("Record retrieved instantly (EHR Agent → Doctor Agent).")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='section-title'>📝 Add Diagnosis</div>", unsafe_allow_html=True)
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        diag_pid = st.text_input("Patient ID")
        diag_text = st.text_area("Diagnosis")
        diag_meds = st.text_input("Medications")

        if st.button("Update Diagnosis"):
            doctor.process_message({
                "action": "update_medical_record",
                "data": {
                    "patient_id": diag_pid,
                    "diagnosis": diag_text,
                    "medications": diag_meds,
                    "lab_results": None,
                    "imaging_results": None
                }
            })
            st.success("Diagnosis updated in EHR successfully.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='section-title'>🧪 Order Lab Test</div>", unsafe_allow_html=True)
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        lab_pid = st.text_input("Patient ID for Lab Test")
        lab_test = st.selectbox("Test Type", ["CBC", "blood_glucose", "lipid_profile"])
        priority = st.selectbox("Priority", ["routine", "urgent"])

        if st.button("Send Lab Order"):
            doctor.process_message({
                "action": "process_lab_request",
                "data": {
                    "patient_id": lab_pid,
                    "test_type": lab_test,
                    "priority": priority
                }
            })
            st.success("Lab Test Order sent!")
        st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# RIGHT COLUMN — AUTO DEMO + AGENT LOG AREA
# ============================================================
with col2:

    st.markdown("<div class='section-title'>🚀 Full System Demonstration</div>", unsafe_allow_html=True)

    st.markdown("<div class='card'>", unsafe_allow_html=True)

    if st.button("Run Automated Demo"):
        st.info("Registering demo patient...")
        result = ehr.process_message({
            "action": "create_patient",
            "data": {
                "name": "Demo Patient",
                "dob": "1990-01-01",
                "contact": "9999999999"
            }
        })
        pid = result["patient_id"]
        st.success(f"Demo patient registered. ID: **{pid}**")

        st.info("Doctor retrieving patient record…")
        doctor.process_message({
            "action": "retrieve_patient",
            "data": {"patient_id": pid}
        })
        st.success("Patient record retrieved instantly.")

        st.info("Doctor writing diagnosis…")
        doctor.process_message({
            "action": "update_medical_record",
            "data": {
                "patient_id": pid,
                "diagnosis": "Seasonal Fever",
                "medications": "Paracetamol 500mg",
                "lab_results": None,
                "imaging_results": None
            }
        })
        st.success("Diagnosis updated.")

        st.info("Ordering CBC test…")
        doctor.process_message({
            "action": "process_lab_request",
            "data": {
                "patient_id": pid,
                "test_type": "CBC",
                "priority": "routine"
            }
        })
        st.success("Lab order sent! Lab Agent will process it.")

        st.success("🎉 DEMO COMPLETE — All agents worked together.")
    
    st.markdown("</div>", unsafe_allow_html=True)
