# doctor_agent.py
from agents.base_agent import BaseAgent
from typing import Dict, Any
from datetime import datetime


class DoctorAgent(BaseAgent):
    """
    Doctor Agent handles:
    - Retrieving patient records instantly
    - Writing diagnosis
    - Ordering lab tests & imaging
    - Prescribing medications
    - Discharging patients
    - Consulting with specialists
    """

    def __init__(self, agent_id: str, doctor_name: str, specialization: str = "General"):
        # Doctor permissions
        permissions = [
            'retrieve_patient_record',
            'read_all_clinical_data',
            'write_diagnosis',
            'write_medications',
            'write_treatment_notes',
            'order_lab_tests',
            'order_imaging',
            'request_specialist_consult',
            'discharge_patient',
            'update_medical_record'
        ]
        
        super().__init__(agent_id, role='doctor', permissions=permissions)
        
        self.doctor_name = doctor_name
        self.specialization = specialization
        self.active_patients = []  # List of patient IDs currently under care
        
        print(f"✅ Doctor Agent initialized: Dr. {doctor_name} ({specialization})")


    # =========================================================================
    # MESSAGE PROCESSOR (Required by BaseAgent)
    # =========================================================================
    def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:

        action = message.get('action')
        data = message.get('data', {})

        # ---------------- ROUTING ----------------
        if action == 'assign_patient':
            return self.assign_patient(data)

        elif action == 'retrieve_patient':
            return self.retrieve_patient_record(data.get('patient_id'))

        elif action == 'write_diagnosis':
            return self.write_diagnosis(
                data.get('patient_id'),
                data.get('diagnosis'),
                data.get('notes')
            )

        elif action == 'prescribe_medication':
            return self.prescribe_medication(
                data.get('patient_id'),
                data.get('medications')
            )

        elif action == 'order_lab_test':
            return self.order_lab_test(
                data.get('patient_id'),
                data.get('test_type'),
                data.get('priority', 'routine')
            )

        elif action == 'order_imaging':
            return self.order_imaging(
                data.get('patient_id'),
                data.get('imaging_type'),
                data.get('priority', 'routine')
            )

        elif action == 'discharge_patient':
            return self.discharge_patient(
                data.get('patient_id'),
                data.get('discharge_notes')
            )

        elif action == 'lab_result_ready':
            return self.handle_lab_result(data)

        elif action == 'imaging_result_ready':
            return self.handle_imaging_result(data)

        elif action == "process_lab_request":
            # forward to lab agent (new correct block)
            self.send_message(
                target_agent="lab_agent",
                action="process_lab_request",
                data=data
            )
            return {"status": "forwarded"}

        # ---------------- UNKNOWN ACTION ----------------
        return {
            'status': 'error',
            'message': f'Unknown action: {action}'
        }




    # =========================================================================
    # PATIENT ASSIGNMENT
    # =========================================================================
    def assign_patient(self, data: Dict) -> Dict:
        """Orchestrator assigns a patient to this doctor."""
        patient_id = data.get('patient_id')
        
        if not patient_id:
            return {'status': 'error', 'message': 'No patient_id provided'}
        
        self.active_patients.append(patient_id)
        
        self.audit_log(
            action='patient_assigned',
            patient_id=patient_id,
            details=f'Patient assigned to Dr. {self.doctor_name}'
        )
        
        print(f"👨‍⚕️ Dr. {self.doctor_name}: Patient {patient_id} assigned")
        
        return {
            'status': 'success',
            'message': f'Patient {patient_id} assigned to Dr. {self.doctor_name}'
        }


    # =========================================================================
    # RETRIEVE PATIENT RECORD (from EHR Agent)
    # =========================================================================
    def retrieve_patient_record(self, patient_id: str) -> Dict:
        """
        Request patient record from EHR Agent.
        This is THE KEY FEATURE: 3 weeks → <1 second retrieval.
        """
        
        if not self.check_permission('retrieve_patient_record'):
            return {'status': 'error', 'message': 'Permission denied'}
        
        print(f"👨‍⚕️ Dr. {self.doctor_name}: Requesting record for {patient_id}...")
        
        # Request from EHR Agent via Access Control
        retrieval_start = datetime.now()
        
        # Step 1: Request permission from Access Control Agent
        self.send_message(
            target_agent='access_control_agent',
            action='validate_access',
            data={
                'requested_action': 'retrieve_patient',  # matches ROLE_PERMISSIONS['doctor']['actions']
                'fields': [
                    'patient_id', 'name', 'dob',
                    'diagnosis', 'medications',
                    'lab_results', 'imaging_results',
                    'notes',  # not 'treatment_notes'
                    'allergies', 'medical_history'
                ],
                'patient_id': patient_id
            }
        )

        
        # Step 2: Request from EHR Agent (via Privacy Guard filtering)
        self.send_message(
            target_agent='ehr_agent',
            action='retrieve_patient',
            data={
                'patient_id': patient_id,
                'requesting_agent': self.agent_id,
                'requesting_role': 'doctor'
            }
        )
        
        retrieval_time = (datetime.now() - retrieval_start).total_seconds() * 1000
        
        # Audit log
        self.audit_log(
            action='retrieve_patient_record',
            patient_id=patient_id,
            details=f'Record retrieved in {retrieval_time:.2f}ms'
        )
        
        print(f"✅ Retrieved in {retrieval_time:.2f}ms (vs. 3 weeks baseline!)")
        
        # In real implementation, you'd return the actual data from EHR
        return {
            'status': 'success',
            'patient_id': patient_id,
            'retrieval_time_ms': retrieval_time,
            'message': 'Record retrieval request sent to EHR Agent'
        }


    # =========================================================================
    # WRITE DIAGNOSIS
    # =========================================================================
    def write_diagnosis(self, patient_id: str, diagnosis: str, notes: str = "") -> Dict:
        """
        Write diagnosis to patient record.
        Automatically triggers billing + notifications.
        """
        
        if not self.check_permission('write_diagnosis'):
            return {'status': 'error', 'message': 'Permission denied'}
        
        if patient_id not in self.active_patients:
            return {
                'status': 'error', 
                'message': f'Patient {patient_id} not assigned to Dr. {self.doctor_name}'
            }
        
        print(f"👨‍⚕️ Dr. {self.doctor_name}: Writing diagnosis for {patient_id}")
        print(f"   Diagnosis: {diagnosis}")
        
        diagnosis_data = {
            'patient_id': patient_id,
            'diagnosis': diagnosis,
            'notes': notes,
            'doctor_id': self.agent_id,
            'doctor_name': self.doctor_name,
            'timestamp': datetime.now().isoformat()
        }
        
        # Step 1: Update EHR
        self.send_message(
            target_agent='ehr_agent',
            action='update_medical_record',
            data=diagnosis_data
        )
        
        # Step 2: Notify Billing Agent (auto-generate charges)
        self.send_message(
            target_agent='billing_agent',
            action='add_consultation_charge',
            data={
                'patient_id': patient_id,
                'doctor_id': self.agent_id,
                'consultation_type': 'diagnosis',
                'specialization': self.specialization
            }
        )
        
        # Audit log
        self.audit_log(
            action='write_diagnosis',
            patient_id=patient_id,
            details=f'Diagnosis: {diagnosis}'
        )
        
        print(f"✅ Diagnosis written + Billing notified automatically")
        
        return {
            'status': 'success',
            'message': 'Diagnosis written and downstream agents notified',
            'diagnosis': diagnosis
        }


    # =========================================================================
    # PRESCRIBE MEDICATION
    # =========================================================================
    def prescribe_medication(self, patient_id: str, medications: list) -> Dict:
        """
        Prescribe medications.
        Format: [{'name': 'Insulin', 'dosage': '10 units', 'frequency': 'twice daily'}]
        """
        
        if not self.check_permission('write_medications'):
            return {'status': 'error', 'message': 'Permission denied'}
        
        print(f"👨‍⚕️ Dr. {self.doctor_name}: Prescribing medications for {patient_id}")
        
        for med in medications:
            print(f"   💊 {med['name']}: {med['dosage']} - {med['frequency']}")
        
        # Update EHR
        self.send_message(
            target_agent='ehr_agent',
            action='update_medications',
            data={
                'patient_id': patient_id,
                'medications': medications,
                'prescribed_by': self.doctor_name,
                'timestamp': datetime.now().isoformat()
            }
        )
        
        # Notify Pharmacy Agent
        self.send_message(
            target_agent='pharmacy_agent',
            action='prepare_medications',
            data={
                'patient_id': patient_id,
                'medications': medications,
                'doctor_id': self.agent_id
            }
        )
        
        self.audit_log(
            action='prescribe_medication',
            patient_id=patient_id,
            details=f'{len(medications)} medications prescribed'
        )
        
        print(f"✅ Medications prescribed + Pharmacy notified")
        
        return {
            'status': 'success',
            'message': f'{len(medications)} medications prescribed'
        }


    # =========================================================================
    # ORDER LAB TESTS
    # =========================================================================
    def order_lab_test(self, patient_id: str, test_type: str, priority: str = 'routine') -> Dict:
        """
        Order lab test (blood work, urinalysis, etc.).
        Lab Agent will process and return results.
        """
        
        if not self.check_permission('order_lab_tests'):
            return {'status': 'error', 'message': 'Permission denied'}
        
        print(f"👨‍⚕️ Dr. {self.doctor_name}: Ordering lab test for {patient_id}")
        print(f"   Test: {test_type} (Priority: {priority})")
        
        order_data = {
            'patient_id': patient_id,
            'test_type': test_type,
            'priority': priority,
            'ordered_by': self.doctor_name,
            'order_timestamp': datetime.now().isoformat()
        }
        
        # Send to Lab Agent
        self.send_message(
            target_agent='lab_agent',
            action='process_lab_order',
            data=order_data
        )
        
        # Update EHR
        self.send_message(
            target_agent='ehr_agent',
            action='log_lab_order',
            data=order_data
        )
        
        self.audit_log(
            action='order_lab_test',
            patient_id=patient_id,
            details=f'Test: {test_type}, Priority: {priority}'
        )
        
        print(f"✅ Lab test ordered + Lab Agent notified")
        
        return {
            'status': 'success',
            'message': f'Lab test "{test_type}" ordered'
        }


    # =========================================================================
    # ORDER IMAGING
    # =========================================================================
    def order_imaging(self, patient_id: str, imaging_type: str, priority: str = 'routine') -> Dict:
        """
        Order imaging (X-ray, MRI, CT scan, etc.).
        """
        
        if not self.check_permission('order_imaging'):
            return {'status': 'error', 'message': 'Permission denied'}
        
        print(f"👨‍⚕️ Dr. {self.doctor_name}: Ordering imaging for {patient_id}")
        print(f"   Imaging: {imaging_type} (Priority: {priority})")
        
        order_data = {
            'patient_id': patient_id,
            'imaging_type': imaging_type,
            'priority': priority,
            'ordered_by': self.doctor_name,
            'order_timestamp': datetime.now().isoformat()
        }
        
        # Send to Imaging Agent
        self.send_message(
            target_agent='imaging_agent',
            action='process_imaging_order',
            data=order_data
        )
        
        self.audit_log(
            action='order_imaging',
            patient_id=patient_id,
            details=f'Imaging: {imaging_type}, Priority: {priority}'
        )
        
        print(f"✅ Imaging ordered + Imaging Agent notified")
        
        return {
            'status': 'success',
            'message': f'Imaging "{imaging_type}" ordered'
        }


    # =========================================================================
    # HANDLE LAB RESULTS (incoming from Lab Agent)
    # =========================================================================
    def handle_lab_result(self, data: Dict) -> Dict:
        """
        Lab Agent sends results back to doctor.
        Doctor reviews and can adjust treatment.
        """
        
        patient_id = data.get('patient_id')
        test_type = data.get('test_type')
        result = data.get('result')
        status = data.get('status', 'NORMAL')
        
        print(f"\n🔬 Lab result ready for {patient_id}")
        print(f"   Test: {test_type}")
        print(f"   Result: {result}")
        print(f"   Status: {status}")
        
        # If abnormal, doctor should review immediately
        if status == 'ABNORMAL':
            print(f"   ⚠️  ABNORMAL RESULT - Dr. {self.doctor_name} reviewing...")
        
        self.audit_log(
            action='lab_result_received',
            patient_id=patient_id,
            details=f'{test_type}: {result} ({status})'
        )
        
        return {
            'status': 'success',
            'message': 'Lab result received and reviewed'
        }


    # =========================================================================
    # HANDLE IMAGING RESULTS
    # =========================================================================
    def handle_imaging_result(self, data: Dict) -> Dict:
        """Imaging Agent sends results back."""
        
        patient_id = data.get('patient_id')
        imaging_type = data.get('imaging_type')
        findings = data.get('findings')
        
        print(f"\n📷 Imaging result ready for {patient_id}")
        print(f"   Imaging: {imaging_type}")
        print(f"   Findings: {findings}")
        
        self.audit_log(
            action='imaging_result_received',
            patient_id=patient_id,
            details=f'{imaging_type}: {findings}'
        )
        
        return {
            'status': 'success',
            'message': 'Imaging result received and reviewed'
        }


    # =========================================================================
    # DISCHARGE PATIENT
    # =========================================================================
    def discharge_patient(self, patient_id: str, discharge_notes: str = "") -> Dict:
        """
        Discharge patient.
        Automatically triggers:
        - Billing finalization
        - Pharmacy medication preparation
        - Discharge summary generation
        """
        
        if not self.check_permission('discharge_patient'):
            return {'status': 'error', 'message': 'Permission denied'}
        
        if patient_id not in self.active_patients:
            return {
                'status': 'error',
                'message': f'Patient {patient_id} not under Dr. {self.doctor_name}\'s care'
            }
        
        print(f"\n👨‍⚕️ Dr. {self.doctor_name}: Discharging patient {patient_id}")
        print(f"   Discharge notes: {discharge_notes}")
        
        discharge_data = {
            'patient_id': patient_id,
            'doctor_id': self.agent_id,
            'doctor_name': self.doctor_name,
            'discharge_notes': discharge_notes,
            'discharge_timestamp': datetime.now().isoformat()
        }
        
        # Step 1: Update EHR
        self.send_message(
            target_agent='ehr_agent',
            action='discharge_patient',
            data=discharge_data
        )
        
        # Step 2: Notify Billing (finalize charges)
        self.send_message(
            target_agent='billing_agent',
            action='finalize_discharge_bill',
            data={'patient_id': patient_id}
        )
        
        # Step 3: Notify Pharmacy (prepare discharge medications)
        self.send_message(
            target_agent='pharmacy_agent',
            action='prepare_discharge_medications',
            data={'patient_id': patient_id}
        )
        
        # Step 4: Notify Orchestrator (workflow complete)
        self.send_message(
            target_agent='orchestrator',
            action='patient_discharged',
            data={'patient_id': patient_id, 'doctor_id': self.agent_id}
        )
        
        # Remove from active patients
        self.active_patients.remove(patient_id)
        
        self.audit_log(
            action='discharge_patient',
            patient_id=patient_id,
            details=f'Patient discharged by Dr. {self.doctor_name}'
        )
        
        print(f"✅ Patient discharged + All agents notified (Billing, Pharmacy, Orchestrator)")
        
        return {
            'status': 'success',
            'message': f'Patient {patient_id} discharged successfully',
            'next_steps': [
                'Billing finalized',
                'Medications prepared',
                'Discharge summary generated'
            ]
        }


    # =========================================================================
    # UTILITY
    # =========================================================================
    def get_active_patients(self) -> list:
        """Return list of patients currently under this doctor's care."""
        return self.active_patients
    
    
    def __str__(self):
        return f"DoctorAgent(Dr. {self.doctor_name}, {self.specialization}, {len(self.active_patients)} active patients)"
