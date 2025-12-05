# lab_agent.py
from agents.base_agent import BaseAgent
from typing import Dict, Any, List
from datetime import datetime
import random


class LabAgent(BaseAgent):
    """
    Lab Agent handles:
    - Receiving lab test orders from doctors
    - Processing lab tests (blood work, urinalysis, cultures, etc.)
    - Detecting abnormal results
    - Auto-notifying Doctor Agent when results are ready
    - Updating EHR with results
    - Tracking test status in real-time
    
    KEY FEATURE: Results ready in 2-4 hours vs. 24-48 hour baseline
    """

    def __init__(self, agent_id: str, lab_name: str = "Central Lab"):
        # Lab permissions
        permissions = [
            'receive_lab_orders',
            'process_lab_tests',
            'write_lab_results',
            'read_test_orders',
            'notify_doctor',
            'update_ehr'
        ]
        
        super().__init__(agent_id, role='lab_tech', permissions=permissions)
        
        self.lab_name = lab_name
        self.pending_orders = {}  # order_id -> order_data
        self.completed_tests = {}  # order_id -> result_data
        
        # Reference ranges for common tests (for abnormal detection)
        self.reference_ranges = {
            'blood_glucose': {'min': 70, 'max': 100, 'unit': 'mg/dL'},
            'hemoglobin': {'min': 12.0, 'max': 16.0, 'unit': 'g/dL'},
            'wbc_count': {'min': 4000, 'max': 11000, 'unit': 'cells/μL'},
            'platelet_count': {'min': 150000, 'max': 450000, 'unit': 'cells/μL'},
            'creatinine': {'min': 0.6, 'max': 1.2, 'unit': 'mg/dL'},
            'alt_liver': {'min': 7, 'max': 56, 'unit': 'U/L'},
            'cholesterol': {'min': 0, 'max': 200, 'unit': 'mg/dL'},
            'triglycerides': {'min': 0, 'max': 150, 'unit': 'mg/dL'}
        }
        
        print(f"✅ Lab Agent initialized: {lab_name}")


    # =========================================================================
    # MESSAGE PROCESSOR (Required by BaseAgent)
    # =========================================================================
    def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Route incoming messages to appropriate handlers."""
        
        action = message.get('action')
        data = message.get('data', {})
        
        # Route to appropriate handler
        if action == 'process_lab_order':
            return self.receive_lab_order(data)
        
        elif action == 'check_order_status':
            return self.check_order_status(data.get('order_id'))
        
        elif action == 'get_pending_orders':
            return self.get_pending_orders()
        
        elif action == 'simulate_result_ready':
            # For demo purposes: instantly "complete" a test
            return self.simulate_test_completion(data.get('order_id'))
        
        else:
            return {
                'status': 'error',
                'message': f'Unknown action: {action}'
            }


    # =========================================================================
    # RECEIVE LAB ORDER (from Doctor Agent)
    # =========================================================================
    def receive_lab_order(self, order_data: Dict) -> Dict:
        """
        Receive lab test order from Doctor Agent.
        Validates order and queues for processing.
        """
        
        if not self.check_permission('receive_lab_orders'):
            return {'status': 'error', 'message': 'Permission denied'}
        
        patient_id = order_data.get('patient_id')
        test_type = order_data.get('test_type')
        priority = order_data.get('priority', 'routine')
        ordered_by = order_data.get('ordered_by', 'Unknown Doctor')
        
        if not patient_id or not test_type:
            return {
                'status': 'error',
                'message': 'Missing patient_id or test_type'
            }
        
        # Generate order ID
        order_id = f"LAB{len(self.pending_orders) + 1:04d}"
        
        # Store order
        self.pending_orders[order_id] = {
            'order_id': order_id,
            'patient_id': patient_id,
            'test_type': test_type,
            'priority': priority,
            'ordered_by': ordered_by,
            'order_timestamp': datetime.now().isoformat(),
            'status': 'PENDING',
            'estimated_completion': self._estimate_completion_time(priority)
        }
        
        print(f"\n🔬 {self.lab_name}: New lab order received")
        print(f"   Order ID: {order_id}")
        print(f"   Patient: {patient_id}")
        print(f"   Test: {test_type}")
        print(f"   Priority: {priority}")
        print(f"   Ordered by: {ordered_by}")
        
        # Audit log
        self.audit_log(
            action='lab_order_received',
            patient_id=patient_id,
            details=f'Order {order_id}: {test_type} ({priority})'
        )
        
        # Update EHR with order status
        self.send_message(
            target_agent='ehr_agent',
            action='log_lab_order',
            data={
                'order_id': order_id,
                'patient_id': patient_id,
                'test_type': test_type,
                'status': 'PENDING'
            }
        )
        
        # Auto-process if priority is STAT/URGENT
        if priority in ['STAT', 'urgent']:
            print(f"   ⚡ URGENT order - processing immediately")
            self._process_test(order_id)
        else:
            print(f"   ⏳ Queued for processing")
        
        return {
            'status': 'success',
            'order_id': order_id,
            'message': f'Lab order {order_id} received',
            'estimated_completion': self.pending_orders[order_id]['estimated_completion']
        }


    # =========================================================================
    # PROCESS LAB TEST
    # =========================================================================
    def _process_test(self, order_id: str) -> Dict:
        """
        Internal method: Process the lab test.
        In a real system, this would interface with lab equipment.
        For demo, we simulate results.
        """
        
        if order_id not in self.pending_orders:
            return {'status': 'error', 'message': f'Order {order_id} not found'}
        
        order = self.pending_orders[order_id]
        order['status'] = 'IN_PROGRESS'
        
        print(f"\n🔬 Processing lab test {order_id}...")
        print(f"   Test type: {order['test_type']}")
        
        # Simulate test processing (in real system, this takes time)
        result = self._generate_test_result(order['test_type'])
        
        # Check if result is abnormal
        status = self._check_abnormality(order['test_type'], result['value'])
        
        # Create result data
        result_data = {
            'order_id': order_id,
            'patient_id': order['patient_id'],
            'test_type': order['test_type'],
            'result': result['value'],
            'unit': result['unit'],
            'reference_range': result['reference_range'],
            'status': status,  # NORMAL, ABNORMAL, CRITICAL
            'completed_timestamp': datetime.now().isoformat(),
            'processed_by': self.agent_id
        }
        
        # Store completed result
        self.completed_tests[order_id] = result_data
        order['status'] = 'COMPLETED'
        
        print(f"✅ Test completed:")
        print(f"   Result: {result['value']} {result['unit']}")
        print(f"   Reference: {result['reference_range']}")
        print(f"   Status: {status}")
        
        # Send results to stakeholders
        self._send_results(result_data, order['ordered_by'])
        
        return {
            'status': 'success',
            'result': result_data
        }


    # =========================================================================
    # GENERATE TEST RESULT (Simulation)
    # =========================================================================
    def _generate_test_result(self, test_type: str) -> Dict:
        """
        Simulate lab test results.
        In production, this would interface with actual lab equipment.
        """
        
        if test_type in self.reference_ranges:
            ref_range = self.reference_ranges[test_type]
            
            # 80% of tests are normal, 20% abnormal (for demo realism)
            if random.random() < 0.8:
                # Generate normal result
                value = random.uniform(ref_range['min'], ref_range['max'])
            else:
                # Generate abnormal result
                if random.random() < 0.5:
                    value = random.uniform(ref_range['min'] * 0.5, ref_range['min'])
                else:
                    value = random.uniform(ref_range['max'], ref_range['max'] * 1.5)
            
            return {
                'value': round(value, 2),
                'unit': ref_range['unit'],
                'reference_range': f"{ref_range['min']}-{ref_range['max']} {ref_range['unit']}"
            }
        
        else:
            # Unknown test type - return generic result
            return {
                'value': 'NORMAL',
                'unit': '',
                'reference_range': 'N/A'
            }


    # =========================================================================
    # CHECK ABNORMALITY
    # =========================================================================
    def _check_abnormality(self, test_type: str, value: float) -> str:
        """
        Determine if result is NORMAL, ABNORMAL, or CRITICAL.
        """
        
        if test_type not in self.reference_ranges:
            return 'NORMAL'
        
        ref_range = self.reference_ranges[test_type]
        
        # Critical levels (20% outside reference range)
        critical_low = ref_range['min'] * 0.8
        critical_high = ref_range['max'] * 1.2
        
        if value < critical_low or value > critical_high:
            return 'CRITICAL'
        elif value < ref_range['min'] or value > ref_range['max']:
            return 'ABNORMAL'
        else:
            return 'NORMAL'


    # =========================================================================
    # SEND RESULTS (to Doctor Agent, EHR)
    # =========================================================================
    def _send_results(self, result_data: Dict, ordered_by: str):
        """
        Send lab results to:
        1. Doctor Agent (who ordered it)
        2. EHR Agent (for patient record)
        3. Audit Logger
        
        KEY FEATURE: Auto-notification = no manual chasing!
        """
        
        patient_id = result_data['patient_id']
        test_type = result_data['test_type']
        status = result_data['status']
        
        print(f"\n📤 Sending lab results for {patient_id}...")
        
        # 1. Send to Doctor Agent
        self.send_message(
            target_agent=ordered_by.lower().replace(' ', '_'),  # 'Dr. Smith' -> 'dr._smith'
            action='lab_result_ready',
            data=result_data
        )
        
        # 2. Update EHR Agent
        self.send_message(
            target_agent='ehr_agent',
            action='update_lab_results',
            data=result_data
        )
        
        # 3. If ABNORMAL or CRITICAL, alert Orchestrator
        if status in ['ABNORMAL', 'CRITICAL']:
            print(f"   ⚠️  {status} result - alerting Orchestrator")
            self.send_message(
                target_agent='orchestrator',
                action='abnormal_lab_result',
                data={
                    'patient_id': patient_id,
                    'test_type': test_type,
                    'status': status,
                    'ordered_by': ordered_by
                }
            )
        
        # Audit log
        self.audit_log(
            action='lab_result_sent',
            patient_id=patient_id,
            details=f'{test_type}: {result_data["result"]} {result_data["unit"]} ({status})'
        )
        
        print(f"✅ Results sent to Doctor + EHR (auto-notification complete)")
        print(f"   Time saved: Doctor doesn't need to call lab for status ✓")


    # =========================================================================
    # CHECK ORDER STATUS
    # =========================================================================
    def check_order_status(self, order_id: str) -> Dict:
        """
        Check the status of a lab order.
        Real-time status visibility = no manual chasing!
        """
        
        if order_id in self.pending_orders:
            order = self.pending_orders[order_id]
            
            if order['status'] == 'COMPLETED' and order_id in self.completed_tests:
                return {
                    'status': 'success',
                    'order_status': 'COMPLETED',
                    'result': self.completed_tests[order_id]
                }
            else:
                return {
                    'status': 'success',
                    'order_status': order['status'],
                    'estimated_completion': order['estimated_completion']
                }
        
        return {
            'status': 'error',
            'message': f'Order {order_id} not found'
        }


    # =========================================================================
    # GET PENDING ORDERS
    # =========================================================================
    def get_pending_orders(self) -> Dict:
        """Return list of all pending orders (for dashboard)."""
        
        pending = [order for order in self.pending_orders.values() 
                   if order['status'] != 'COMPLETED']
        
        return {
            'status': 'success',
            'pending_orders': pending,
            'count': len(pending)
        }


    # =========================================================================
    # ESTIMATE COMPLETION TIME
    # =========================================================================
    def _estimate_completion_time(self, priority: str) -> str:
        """
        Estimate when test will be completed based on priority.
        
        Baseline (real hospitals): 24-48 hours
        Our system: 2-4 hours routine, <1 hour urgent, <15 min STAT
        """
        
        if priority == 'STAT':
            return '10-15 minutes'
        elif priority in ['urgent', 'URGENT']:
            return '30-60 minutes'
        else:
            return '2-4 hours'


    # =========================================================================
    # SIMULATE TEST COMPLETION (for demo)
    # =========================================================================
    def simulate_test_completion(self, order_id: str) -> Dict:
        """
        For hackathon demo: instantly complete a pending test.
        In production, tests take time based on priority.
        """
        
        if order_id not in self.pending_orders:
            return {'status': 'error', 'message': f'Order {order_id} not found'}
        
        return self._process_test(order_id)


    # =========================================================================
    # BATCH PROCESS (for multiple orders)
    # =========================================================================
    def batch_process_pending_orders(self) -> Dict:
        """
        Process all pending ROUTINE orders.
        STAT/URGENT are processed immediately upon receipt.
        """
        
        processed_count = 0
        
        for order_id, order in self.pending_orders.items():
            if order['status'] == 'PENDING':
                self._process_test(order_id)
                processed_count += 1
        
        return {
            'status': 'success',
            'message': f'{processed_count} orders processed',
            'processed_count': processed_count
        }


    # =========================================================================
    # STATISTICS (for demo dashboard)
    # =========================================================================
    def get_statistics(self) -> Dict:
        """Return lab statistics for demo dashboard."""
        
        total_orders = len(self.pending_orders)
        completed = sum(1 for o in self.pending_orders.values() if o['status'] == 'COMPLETED')
        pending = total_orders - completed
        
        abnormal_count = sum(1 for r in self.completed_tests.values() 
                           if r['status'] in ['ABNORMAL', 'CRITICAL'])
        
        return {
            'total_orders': total_orders,
            'completed': completed,
            'pending': pending,
            'abnormal_results': abnormal_count,
            'completion_rate': f"{(completed/total_orders*100):.1f}%" if total_orders > 0 else "0%"
        }


    # =========================================================================
    # UTILITY
    # =========================================================================
    def __str__(self):
        pending = sum(1 for o in self.pending_orders.values() if o['status'] != 'COMPLETED')
        return f"LabAgent({self.lab_name}, {pending} pending orders, {len(self.completed_tests)} completed)"


# =============================================================================
# EXAMPLE USAGE (for testing)
# =============================================================================
if __name__ == '__main__':
    # Initialize Lab Agent
    lab = LabAgent('lab_agent_1', 'Central Laboratory')
    
    # Simulate receiving an order from Doctor
    order = {
        'patient_id': 'P001',
        'test_type': 'blood_glucose',
        'priority': 'routine',
        'ordered_by': 'Dr. Smith'
    }
    
    result = lab.receive_lab_order(order)
    print(f"\nOrder received: {result}")
    
    # Process the test
    if result['status'] == 'success':
        order_id = result['order_id']
        lab.simulate_test_completion(order_id)
    
    # Check statistics
    stats = lab.get_statistics()
    print(f"\nLab Statistics: {stats}")
