# agents/privacy_guard.py
from agents.base_agent import BaseAgent
from typing import Dict, Any, List
from datetime import datetime

class PrivacyGuardAgent(BaseAgent):
    """
    Enforces field-level privacy filtering based on role.
    Prevents data exposure by redacting sensitive fields not authorized for the requesting role.
    """
    
    def __init__(self, agent_id: str = "privacy_guard_agent"):
        # Initialize with BaseAgent
        super().__init__(
            agent_id=agent_id,
            role="security",
            permissions=['filter_patient_data', 'apply_field_level_access', 'redact_sensitive_fields']
        )
        
        # Define sensitive field categories
        self.SENSITIVE_FIELDS = {
            # Financial/Identity PII
            'ssn': 'financial_pii',
            'address': 'location_pii',
            'insurance_details': 'financial_pii',
            'account_number': 'financial_pii',
            'credit_card': 'financial_pii',
            
            # Sensitive Medical
            'psychiatric_history': 'sensitive_medical',
            'substance_abuse_history': 'sensitive_medical',
            'hiv_status': 'sensitive_medical',
            'abortion_records': 'sensitive_medical',
            'genetic_predisposition': 'sensitive_medical',
            'sexual_history': 'sensitive_medical'
        }
        
        # Define role-based field access
        self.ROLE_FIELD_ACCESS = {
            'receptionist': {
                'allowed': ['patient_id', 'name', 'dob', 'contact', 'appointment_time', 'created_at'],
                'blocked': ['diagnosis', 'medications', 'lab_results', 'imaging_results', 
                           'ssn', 'insurance_details', 'psychiatric_history', 'substance_abuse_history']
            },
            'doctor': {
                'allowed': ['patient_id', 'name', 'dob', 'contact', 'diagnosis', 'medications', 
                           'lab_results', 'imaging_results', 'notes', 'psychiatric_history', 
                           'substance_abuse_history', 'hiv_status', 'genetic_predisposition'],
                'blocked': ['ssn', 'insurance_details', 'address', 'account_number']
            },
            'lab_tech': {
                'allowed': ['patient_id', 'name', 'dob', 'test_order', 'lab_results'],
                'blocked': ['diagnosis', 'medications', 'psychiatric_history', 'ssn', 
                           'insurance_details', 'imaging_results']
            },
            'billing': {
                'allowed': ['patient_id', 'name', 'dob', 'ssn', 'insurance_details', 
                           'account_number', 'charges', 'address'],
                'blocked': ['diagnosis', 'medications', 'lab_results', 'psychiatric_history', 
                           'substance_abuse_history', 'hiv_status']
            },
            'pharmacy': {
                'allowed': ['patient_id', 'name', 'dob', 'medications', 'allergies'],
                'blocked': ['diagnosis', 'psychiatric_history', 'ssn', 'insurance_details', 
                           'lab_results', 'imaging_results']
            }
        }
    
    def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for privacy filtering.
        Implements abstract method from BaseAgent.
        
        Expected message format:
        {
            'from': 'agent_id',
            'action': 'filter_patient_data',
            'data': {patient_data_dict},
            'patient_id': 'P001'
        }
        """
        
        requesting_agent = message.get('from', 'unknown')
        requesting_role = self._get_role(requesting_agent)
        patient_data = message.get('data', {})
        patient_id = message.get('patient_id', 'unknown')
        
        # Filter data based on role
        filtered_data = self._filter_by_role(patient_data, requesting_role)
        
        # Count redacted fields
        original_fields = set(patient_data.keys())
        filtered_fields = set(filtered_data.keys())
        redacted_fields = original_fields - filtered_fields
        
        # Use BaseAgent's audit_log method
        self.audit_log(
            'privacy_filter_applied',
            patient_id,
            f"Role: {requesting_role}, Fields redacted: {len(redacted_fields)}, " +
            f"Redacted: {list(redacted_fields)}"
        )
        
        return {
            'status': 'success',
            'data': filtered_data,
            'redacted_fields': list(redacted_fields),
            'role': requesting_role
        }
    
    def _filter_by_role(self, data: Dict, role: str) -> Dict:
        """
        Remove fields not authorized for the given role.
        """
        
        if role not in self.ROLE_FIELD_ACCESS:
            # Unknown role - default to minimal access
            return {
                'patient_id': data.get('patient_id'),
                'error': f'Unknown role: {role}'
            }
        
        allowed_fields = self.ROLE_FIELD_ACCESS[role]['allowed']
        filtered = {}
        
        for field, value in data.items():
            if field in allowed_fields:
                filtered[field] = value
            else:
                # Field is redacted (not included in filtered result)
                pass
        
        return filtered
    
    def _get_role(self, agent_id: str) -> str:
        """
        Map agent ID to role.
        """
        role_mapping = {
            'receptionist_agent_1': 'receptionist',
            'receptionist_agent': 'receptionist',
            'doctor_agent_1': 'doctor',
            'doctor_agent': 'doctor',
            'lab_agent_1': 'lab_tech',
            'lab_agent': 'lab_tech',
            'billing_agent_1': 'billing',
            'billing_agent': 'billing',
            'pharmacy_agent_1': 'pharmacy',
            'pharmacy_agent': 'pharmacy'
        }
        
        return role_mapping.get(agent_id, 'unknown')
    
    def check_field_sensitivity(self, field_name: str) -> str:
        """
        Return sensitivity level of a field.
        """
        return self.SENSITIVE_FIELDS.get(field_name, 'standard')
    
    def get_role_permissions(self, role: str) -> Dict:
        """
        Return allowed and blocked fields for a role.
        """
        return self.ROLE_FIELD_ACCESS.get(role, {
            'allowed': [],
            'blocked': []
        })


# ============================================
# DEMO USAGE (Standalone testing)
# ============================================

if __name__ == "__main__":
    print("=" * 60)
    print("PRIVACY GUARD AGENT - DEMO (Standalone Mode)")
    print("=" * 60)
    
    # Initialize agent (no event queue for standalone demo)
    privacy_guard = PrivacyGuardAgent()
    
    # Sample patient data with sensitive fields
    patient_data = {
        'patient_id': 'P001',
        'name': 'Rajesh Kumar',
        'dob': '1975-05-15',
        'contact': '9876543210',
        'address': '123 Main St, Mumbai',
        'diagnosis': 'Type 2 Diabetes',
        'medications': 'Metformin 500mg',
        'lab_results': 'Blood Glucose: 145 mg/dL (HIGH)',
        'imaging_results': 'Chest X-ray: Normal',
        'ssn': '123-45-6789',
        'insurance_details': 'Health Insurance Corp - Policy #12345',
        'psychiatric_history': 'Anxiety disorder, ongoing therapy',
        'substance_abuse_history': 'None',
        'notes': 'Patient reports recent weight loss'
    }
    
    print("\n📋 ORIGINAL PATIENT DATA")
    print(f"Fields: {list(patient_data.keys())}")
    print(f"Total fields: {len(patient_data)}")
    
    # Test 1: Doctor accessing patient data
    print("\n" + "=" * 60)
    print("TEST 1: DOCTOR ACCESSING PATIENT DATA")
    print("=" * 60)
    
    doctor_message = {
        'from': 'doctor_agent_1',
        'action': 'filter_patient_data',
        'data': patient_data,
        'patient_id': 'P001'
    }
    
    doctor_response = privacy_guard.process_message(doctor_message)
    
    print(f"\n✅ Status: {doctor_response['status']}")
    print(f"👨‍⚕️ Role: {doctor_response['role']}")
    print(f"📊 Fields visible to doctor: {list(doctor_response['data'].keys())}")
    print(f"🚫 Fields redacted: {doctor_response['redacted_fields']}")
    print(f"\nDoctor CAN see: diagnosis ✓")
    print(f"Doctor CANNOT see: ssn ✗ (Redacted: {('ssn' in doctor_response['redacted_fields'])})")
    
    # Test 2: Billing accessing patient data
    print("\n" + "=" * 60)
    print("TEST 2: BILLING ACCESSING PATIENT DATA")
    print("=" * 60)
    
    billing_message = {
        'from': 'billing_agent_1',
        'action': 'filter_patient_data',
        'data': patient_data,
        'patient_id': 'P001'
    }
    
    billing_response = privacy_guard.process_message(billing_message)
    
    print(f"\n✅ Status: {billing_response['status']}")
    print(f"💳 Role: {billing_response['role']}")
    print(f"📊 Fields visible to billing: {list(billing_response['data'].keys())}")
    print(f"🚫 Fields redacted: {billing_response['redacted_fields']}")
    print(f"\nBilling CAN see: ssn ✓")
    print(f"Billing CANNOT see: diagnosis ✗ (Redacted: {('diagnosis' in billing_response['redacted_fields'])})")
    
    # Test 3: Receptionist accessing patient data
    print("\n" + "=" * 60)
    print("TEST 3: RECEPTIONIST ACCESSING PATIENT DATA")
    print("=" * 60)
    
    receptionist_message = {
        'from': 'receptionist_agent_1',
        'action': 'filter_patient_data',
        'data': patient_data,
        'patient_id': 'P001'
    }
    
    receptionist_response = privacy_guard.process_message(receptionist_message)
    
    print(f"\n✅ Status: {receptionist_response['status']}")
    print(f"📝 Role: {receptionist_response['role']}")
    print(f"📊 Fields visible to receptionist: {list(receptionist_response['data'].keys())}")
    print(f"🚫 Fields redacted: {receptionist_response['redacted_fields']}")
    print(f"\nReceptionist CAN see: name, contact ✓")
    print(f"Receptionist CANNOT see: diagnosis, ssn ✗ (All medical and financial data redacted)")
    
    # Summary
    print("\n" + "=" * 60)
    print("DEMO SUMMARY")
    print("=" * 60)
    print("\n✅ PRIVACY ENFORCEMENT WORKING:")
    print(f"   - Doctor sees clinical data, blocked from financial PII")
    print(f"   - Billing sees financial PII, blocked from clinical data")
    print(f"   - Receptionist sees only basic contact info")
    print(f"   - All filtering actions logged for audit trail")
    print("\n🎯 DEMO TALKING POINT:")
    print("   'The Indian healthcare sector has suffered multiple breaches")
    print("   because sensitive data was visible to all staff. Our Privacy")
    print("   Guard Agent enforces field-level access—doctors see diagnoses")
    print("   but not SSNs, billing sees insurance but not medical data.")
    print("   This is how you prevent data breaches.'")
    print("\n" + "=" * 60)