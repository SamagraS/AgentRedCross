# agents/access_control_agent.py
from agents.base_agent import BaseAgent
from typing import Dict, Any, List
from datetime import datetime

class AccessControlAgent(BaseAgent):
    """
    Enforces role-based access control (RBAC).
    Validates every request before allowing access to patient data.
    Integrates with your event queue system.
    """
    
    def __init__(self, agent_id: str = "access_control_agent"):
        # Initialize with BaseAgent
        super().__init__(
            agent_id=agent_id,
            role="security",
            permissions=['validate_all_requests', 'enforce_rbac', 'audit_all_access_decisions']
        )
        
        # Define role-based permissions matrix
        self.ROLE_PERMISSIONS = {
            'receptionist': {
                'read_fields': ['patient_id', 'name', 'dob', 'contact', 'appointment_time'],
                'write_fields': ['contact', 'appointment_time'],
                'actions': [
                    'create_patient',
                    'update_appointment',
                    'read_patient_basics',
                    'schedule_doctor',
                    'patient_intake'  # Add this for your receptionist workflow
                ]
            },
            'doctor': {
                'read_fields': [
                    'patient_id', 'name', 'dob', 'contact',
                    'diagnosis', 'medications', 'lab_results', 'imaging_results',
                    'notes', 'psychiatric_history', 'substance_abuse_history',
                    'allergies', 'medical_history'
                ],
                'write_fields': [
                    'diagnosis', 'medications', 'notes',
                    'treatment_plan', 'prescription'
                ],
                'actions': [
                    'retrieve_patient',
                    'write_diagnosis',
                    'order_lab',
                    'order_imaging',
                    'prescribe_medication',
                    'update_medical_record',
                    'discharge_patient'
                ]
            },
            'lab_tech': {
                'read_fields': ['patient_id', 'name', 'dob', 'test_order'],
                'write_fields': ['lab_results'],
                'actions': [
                    'retrieve_test_order',
                    'submit_lab_results',
                    'update_test_status'
                ]
            },
            'billing': {
                'read_fields': [
                    'patient_id', 'name', 'dob', 'ssn',
                    'insurance_details', 'charges', 'address',
                    'account_number'
                ],
                'write_fields': [
                    'charges', 'insurance_status', 'payment_status'
                ],
                'actions': [
                    'generate_bill',
                    'update_insurance',
                    'process_payment',
                    'retrieve_billing_info'
                ]
            },
            'ehr_system': {
                'read_fields': ['*'],  # EHR can read all
                'write_fields': ['*'],  # EHR can write all
                'actions': ['*']  # EHR has full access
            }
        }
        
        # Track denied access attempts for security monitoring
        self.denied_attempts = []
    
    # -------------------------------------------------------------------------
    # MESSAGE ROUTER
    # -------------------------------------------------------------------------
    def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for access validation.
        
        Expected message format:
        {
            'from': 'agent_id',
            'action': 'validate_access',
            'data': {
                'requested_action': 'retrieve_patient',
                'fields': ['diagnosis', 'medications'],
                'patient_id': 'P001'
            }
        }
        """
        
        action = message.get('action', 'unknown')
        
        if action == 'validate_access':
            return self._validate_access(message)
        
        elif action == 'check_write_permission':
            return self._check_write_permission(message)
        
        elif action == 'get_denied_attempts':
            return self._get_denied_attempts(message.get('data', {}))
        
        else:
            return {
                'status': 'error',
                'message': f'Unknown action: {action}'
            }
    
    # -------------------------------------------------------------------------
    # VALIDATE ACCESS
    # -------------------------------------------------------------------------
    def _validate_access(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate if requesting agent can perform the requested action.
        """
        
        requesting_agent = message.get('from', 'unknown')
        requesting_role = self._get_role(requesting_agent)
        data = message.get('data', {})
        
        requested_action = data.get('requested_action', 'unknown')
        requested_fields = data.get('fields', [])
        patient_id = data.get('patient_id', 'unknown')
        
        # Validate role exists
        if requesting_role == 'unknown':
            return self._deny_access(
                requesting_agent,
                requested_action,
                patient_id,
                f"Unknown agent: {requesting_agent}"
            )
        
        # EHR system has full access
        if requesting_role == 'ehr_system':
            return {
                'status': 'approved',
                'role': requesting_role,
                'allowed_fields': ['*'],
                'allowed_actions': ['*']
            }
        
        # Check if role can perform action
        allowed_actions = self.ROLE_PERMISSIONS[requesting_role]['actions']
        if requested_action not in allowed_actions:
            return self._deny_access(
                requesting_agent,
                requested_action,
                patient_id,
                f"Action '{requested_action}' not permitted for role '{requesting_role}'"
            )
        
        # Check if role can access requested fields (if fields specified)
        if requested_fields:
            allowed_read_fields = self.ROLE_PERMISSIONS[requesting_role]['read_fields']
            unauthorized_fields = [f for f in requested_fields if f not in allowed_read_fields]
            
            if unauthorized_fields:
                return self._deny_access(
                    requesting_agent,
                    requested_action,
                    patient_id,
                    f"Cannot access fields: {unauthorized_fields}"
                )
        
        # ACCESS GRANTED - Use BaseAgent's audit_log method
        self.audit_log(
            action='access_granted',
            patient_id=patient_id,
            details=f"Agent: {requesting_agent}, Role: {requesting_role}, Action: {requested_action}"
        )
        
        return {
            'status': 'approved',
            'role': requesting_role,
            'allowed_fields': self.ROLE_PERMISSIONS[requesting_role]['read_fields'],
            'allowed_actions': allowed_actions
        }
    
    # -------------------------------------------------------------------------
    # DENY ACCESS
    # -------------------------------------------------------------------------
    def _deny_access(self, agent: str, action: str, patient_id: str, reason: str) -> Dict:
        """
        Log denied access attempt and alert security monitoring.
        """
        
        denial_record = {
            'timestamp': datetime.now().isoformat(),
            'agent': agent,
            'action': action,
            'patient_id': patient_id,
            'reason': reason
        }
        
        self.denied_attempts.append(denial_record)
        
        # Use BaseAgent's audit_log method
        self.audit_log(
            action='access_denied',
            patient_id=patient_id,
            details=f"🚨 SECURITY ALERT - Agent: {agent}, Action: {action}, Reason: {reason}"
        )
        
        # Alert IDS Agent using BaseAgent's send_message
        if self.event_queue:
            self.send_message('ids_agent', 'log_denied_attempt', denial_record)
        
        return {
            'status': 'denied',
            'reason': reason,
            'severity': 'SECURITY_ALERT'
        }
    
    # -------------------------------------------------------------------------
    # CHECK WRITE PERMISSION
    # -------------------------------------------------------------------------
    def _check_write_permission(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if agent can write to a specific field.
        """
        agent_id = message.get('from', 'unknown')
        field = message.get('data', {}).get('field', '')
        
        role = self._get_role(agent_id)
        
        if role == 'unknown':
            return {'status': 'denied', 'can_write': False}
        
        if role == 'ehr_system':
            return {'status': 'approved', 'can_write': True}
        
        write_fields = self.ROLE_PERMISSIONS[role]['write_fields']
        can_write = field in write_fields
        
        return {
            'status': 'approved' if can_write else 'denied',
            'can_write': can_write
        }
    
    # -------------------------------------------------------------------------
    # GET DENIED ATTEMPTS
    # -------------------------------------------------------------------------
    def _get_denied_attempts(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Retrieve denied access attempts within time window.
        """
        time_window_minutes = data.get('time_window_minutes', 60)
        cutoff = datetime.now().timestamp() - (time_window_minutes * 60)
        
        recent_denials = []
        for attempt in self.denied_attempts:
            attempt_time = datetime.fromisoformat(attempt['timestamp']).timestamp()
            if attempt_time > cutoff:
                recent_denials.append(attempt)
        
        return {
            'status': 'success',
            'denial_count': len(recent_denials),
            'denials': recent_denials
        }
    
    # -------------------------------------------------------------------------
    # HELPER METHODS
    # -------------------------------------------------------------------------
    def _get_role(self, agent_id: str) -> str:
        """
        Map agent ID to role.
        """
        role_mapping = {
            'receptionist_agent': 'receptionist',
            'receptionist_agent_1': 'receptionist',
            'doctor_agent': 'doctor',
            'doctor_agent_1': 'doctor',
            'lab_agent': 'lab_tech',
            'lab_agent_1': 'lab_tech',
            'billing_agent': 'billing',
            'billing_agent_1': 'billing',
            'ehr_agent': 'ehr_system',
            'ehr_agent_1': 'ehr_system'
        }
        
        return role_mapping.get(agent_id, 'unknown')
    
    def get_role_permissions_summary(self, role: str) -> Dict:
        """
        Return complete permissions summary for a role.
        """
        return self.ROLE_PERMISSIONS.get(role, {
            'read_fields': [],
            'write_fields': [],
            'actions': []
        })


# ============================================
# DEMO USAGE (Standalone testing)
# ============================================

if __name__ == "__main__":
    print("=" * 70)
    print("ACCESS CONTROL AGENT - DEMO")
    print("=" * 70)
    
    # Initialize agent (no event queue for standalone demo)
    access_control = AccessControlAgent()
    
    # Test 1: Authorized access (Receptionist)
    print("\n" + "=" * 70)
    print("TEST 1: RECEPTIONIST - Patient intake (AUTHORIZED)")
    print("=" * 70)
    
    receptionist_msg = {
        'from': 'receptionist_agent',
        'action': 'validate_access',
        'data': {
            'requested_action': 'patient_intake',
            'fields': ['name', 'dob', 'contact'],
            'patient_id': 'P001'
        }
    }
    
    response = access_control.process_message(receptionist_msg)
    print(f"✅ Status: {response['status']}")
    print(f"📝 Role: {response.get('role', 'N/A')}")
    
    # Test 2: Unauthorized access (Receptionist trying to access diagnosis)
    print("\n" + "=" * 70)
    print("TEST 2: RECEPTIONIST - Access diagnosis (DENIED)")
    print("=" * 70)
    
    unauthorized_msg = {
        'from': 'receptionist_agent',
        'action': 'validate_access',
        'data': {
            'requested_action': 'write_diagnosis',
            'fields': ['diagnosis'],
            'patient_id': 'P001'
        }
    }
    
    response = access_control.process_message(unauthorized_msg)
    print(f"🚫 Status: {response['status']}")
    print(f"📝 Reason: {response.get('reason', 'N/A')}")
    
    # Test 3: Doctor accessing patient (AUTHORIZED)
    print("\n" + "=" * 70)
    print("TEST 3: DOCTOR - Retrieve patient (AUTHORIZED)")
    print("=" * 70)
    
    doctor_msg = {
        'from': 'doctor_agent',
        'action': 'validate_access',
        'data': {
            'requested_action': 'retrieve_patient',
            'fields': ['diagnosis', 'medications', 'lab_results'],
            'patient_id': 'P001'
        }
    }
    
    response = access_control.process_message(doctor_msg)
    print(f"✅ Status: {response['status']}")
    print(f"👨‍⚕️ Role: {response.get('role', 'N/A')}")
    
    print("\n" + "=" * 70)
    print("✅ Access Control Demo Complete")
    print("=" * 70)