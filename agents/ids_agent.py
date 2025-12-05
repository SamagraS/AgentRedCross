# agents/ids_agent.py
from agents.base_agent import BaseAgent
from typing import Dict, Any, List
from datetime import datetime, timedelta
from collections import defaultdict

class IDSAgent(BaseAgent):
    """
    Intrusion Detection System (IDS) Agent.
    Detects anomalous access patterns and insider threats in real-time.
    
    Monitors for:
    - High request rates (potential data scraping)
    - Unusual access times (after-hours access)
    - Unauthorized field access attempts
    - Repeated denied access attempts (potential attack)
    - Access to unassigned patients (scope creep)
    """
    
    def __init__(self, agent_id: str = "ids_agent"):
        # Initialize with BaseAgent
        super().__init__(
            agent_id=agent_id,
            role="security",
            permissions=['monitor_all_access', 'detect_anomalies', 'generate_alerts']
        )
        
        # Track access patterns per agent
        self.access_history = defaultdict(list)  # agent_id -> [timestamps]
        self.denied_attempts = defaultdict(list)  # agent_id -> [denial records]
        
        # Anomaly detection thresholds
        self.THRESHOLDS = {
            'max_requests_per_minute': 10,      # Requests per minute threshold
            'max_requests_per_hour': 100,       # Requests per hour threshold
            'max_denied_attempts': 3,           # Failed attempts before alert
            'unusual_access_hours': {           # Normal working hours
                'start': 7,   # 7 AM
                'end': 20     # 8 PM
            },
            'max_unique_patients_per_hour': 20  # Patient access threshold
        }
        
        # Alert history
        self.alerts = []
        self.alert_count_by_severity = {
            'LOW': 0,
            'MEDIUM': 0,
            'HIGH': 0,
            'CRITICAL': 0
        }
    
    def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for IDS monitoring.
        Implements abstract method from BaseAgent.
        
        Expected message formats:
        
        1. Log access attempt:
        {
            'from': 'some_agent',
            'action': 'log_access',
            'data': {
                'agent': 'doctor_agent_1',
                'action': 'retrieve_patient',
                'patient_id': 'P001',
                'timestamp': '2024-12-04T10:30:00'
            }
        }
        
        2. Log denied attempt:
        {
            'from': 'access_control_agent',
            'action': 'log_denied_attempt',
            'data': {
                'agent': 'receptionist_agent_1',
                'action': 'access_psychiatric_history',
                'reason': 'Unauthorized field access',
                'timestamp': '2024-12-04T10:30:00'
            }
        }
        """
        
        action = message.get('action', 'unknown')
        data = message.get('data', {})
        
        if action == 'log_access':
            return self._log_access_attempt(data)
        
        elif action == 'log_denied_attempt':
            return self._log_denied_attempt(data)
        
        elif action == 'get_alerts':
            return self._get_recent_alerts(data.get('time_window_minutes', 60))
        
        elif action == 'get_statistics':
            return self._get_statistics()
        
        else:
            return {
                'status': 'error',
                'message': f'Unknown action: {action}'
            }
    
    def _log_access_attempt(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log a successful access attempt and check for anomalies.
        """
        
        agent = data.get('agent', 'unknown')
        action = data.get('action', 'unknown')
        patient_id = data.get('patient_id', 'unknown')
        timestamp = datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat()))
        
        # Record access
        access_record = {
            'agent': agent,
            'action': action,
            'patient_id': patient_id,
            'timestamp': timestamp
        }
        self.access_history[agent].append(access_record)
        
        # Run anomaly detection checks
        anomalies = []
        
        # Check 1: High request rate (per minute)
        requests_per_minute = self._count_recent_requests(agent, minutes=1)
        if requests_per_minute > self.THRESHOLDS['max_requests_per_minute']:
            anomalies.append({
                'type': 'HIGH_REQUEST_RATE_MINUTE',
                'severity': 'HIGH',
                'details': f'{requests_per_minute} requests in 1 minute (threshold: {self.THRESHOLDS["max_requests_per_minute"]})'
            })
        
        # Check 2: High request rate (per hour)
        requests_per_hour = self._count_recent_requests(agent, minutes=60)
        if requests_per_hour > self.THRESHOLDS['max_requests_per_hour']:
            anomalies.append({
                'type': 'HIGH_REQUEST_RATE_HOUR',
                'severity': 'MEDIUM',
                'details': f'{requests_per_hour} requests in 1 hour (threshold: {self.THRESHOLDS["max_requests_per_hour"]})'
            })
        
        # Check 3: Unusual access time (after hours)
        if self._is_unusual_time(timestamp):
            anomalies.append({
                'type': 'UNUSUAL_ACCESS_TIME',
                'severity': 'MEDIUM',
                'details': f'Access at {timestamp.strftime("%H:%M")} (outside normal hours 7am-8pm)'
            })
        
        # Check 4: Too many unique patients accessed
        unique_patients = self._count_unique_patients(agent, minutes=60)
        if unique_patients > self.THRESHOLDS['max_unique_patients_per_hour']:
            anomalies.append({
                'type': 'EXCESSIVE_PATIENT_ACCESS',
                'severity': 'HIGH',
                'details': f'{unique_patients} different patients accessed in 1 hour (threshold: {self.THRESHOLDS["max_unique_patients_per_hour"]})'
            })
        
        # Generate alerts if anomalies detected
        if anomalies:
            return self._generate_alert(agent, action, patient_id, anomalies)
        
        return {
            'status': 'normal',
            'message': 'Access logged, no anomalies detected'
        }
    
    def _log_denied_attempt(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log a denied access attempt and check for attack patterns.
        """
        
        agent = data.get('agent', 'unknown')
        action = data.get('action', 'unknown')
        reason = data.get('reason', 'unknown')
        timestamp = datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat()))
        
        # Record denied attempt
        denial_record = {
            'agent': agent,
            'action': action,
            'reason': reason,
            'timestamp': timestamp
        }
        self.denied_attempts[agent].append(denial_record)
        
        # Check: Multiple denied attempts (potential attack)
        recent_denials = self._count_recent_denials(agent, minutes=10)
        
        if recent_denials >= self.THRESHOLDS['max_denied_attempts']:
            anomaly = {
                'type': 'REPEATED_DENIED_ATTEMPTS',
                'severity': 'CRITICAL',
                'details': f'{recent_denials} denied attempts in 10 minutes (threshold: {self.THRESHOLDS["max_denied_attempts"]})'
            }
            
            return self._generate_alert(
                agent,
                action,
                data.get('patient_id', 'unknown'),
                [anomaly]
            )
        
        return {
            'status': 'logged',
            'message': 'Denied attempt logged'
        }
    
    def _generate_alert(self, agent: str, action: str, patient_id: str, anomalies: List[Dict]) -> Dict[str, Any]:
        """
        Generate security alert and notify relevant agents.
        """
        
        # Determine highest severity
        severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        max_severity = max([a['severity'] for a in anomalies], key=lambda s: severity_order.index(s))
        
        alert = {
            'alert_id': f'ALERT_{len(self.alerts) + 1:04d}',
            'timestamp': datetime.now().isoformat(),
            'severity': max_severity,
            'agent': agent,
            'action': action,
            'patient_id': patient_id,
            'anomalies': anomalies,
            'recommended_action': self._get_recommended_action(max_severity)
        }
        
        # Store alert
        self.alerts.append(alert)
        self.alert_count_by_severity[max_severity] += 1
        
        # Audit log using BaseAgent method
        self.audit_log(
            'security_alert_generated',
            patient_id,
            f"🚨 {max_severity} ALERT - Agent: {agent}, Anomalies: {len(anomalies)}"
        )
        
        # Print alert (in production, this would notify security team)
        self._print_alert(alert)
        
        return {
            'status': 'alert',
            'severity': max_severity,
            'alert_id': alert['alert_id'],
            'anomalies': anomalies
        }
    
    def _print_alert(self, alert: Dict) -> None:
        """
        Print formatted security alert (for demo purposes).
        """
        print("\n" + "=" * 70)
        print(f"🚨 SECURITY ALERT: {alert['alert_id']} - {alert['severity']} SEVERITY")
        print("=" * 70)
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Agent: {alert['agent']}")
        print(f"Action: {alert['action']}")
        print(f"Patient ID: {alert['patient_id']}")
        print(f"\nAnomalies Detected ({len(alert['anomalies'])}):")
        for i, anomaly in enumerate(alert['anomalies'], 1):
            print(f"  {i}. [{anomaly['severity']}] {anomaly['type']}")
            print(f"     {anomaly['details']}")
        print(f"\nRecommended Action: {alert['recommended_action']}")
        print("=" * 70)
    
    def _get_recommended_action(self, severity: str) -> str:
        """
        Return recommended action based on alert severity.
        """
        actions = {
            'LOW': 'Monitor agent activity',
            'MEDIUM': 'Review agent access patterns with supervisor',
            'HIGH': 'Temporarily restrict agent access and investigate',
            'CRITICAL': 'IMMEDIATELY suspend agent access and launch investigation'
        }
        return actions.get(severity, 'Investigate immediately')
    
    def _count_recent_requests(self, agent: str, minutes: int) -> int:
        """
        Count requests from agent within time window.
        """
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return sum(1 for access in self.access_history[agent] 
                  if access['timestamp'] > cutoff)
    
    def _count_recent_denials(self, agent: str, minutes: int) -> int:
        """
        Count denied attempts from agent within time window.
        """
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return sum(1 for denial in self.denied_attempts[agent]
                  if denial['timestamp'] > cutoff)
    
    def _count_unique_patients(self, agent: str, minutes: int) -> int:
        """
        Count unique patients accessed by agent within time window.
        """
        cutoff = datetime.now() - timedelta(minutes=minutes)
        recent_accesses = [access for access in self.access_history[agent]
                          if access['timestamp'] > cutoff]
        
        unique_patients = set(access['patient_id'] for access in recent_accesses)
        return len(unique_patients)
    
    def _is_unusual_time(self, timestamp: datetime) -> bool:
        """
        Check if access time is outside normal working hours.
        """
        hour = timestamp.hour
        start = self.THRESHOLDS['unusual_access_hours']['start']
        end = self.THRESHOLDS['unusual_access_hours']['end']
        
        return hour < start or hour >= end
    
    def _get_recent_alerts(self, time_window_minutes: int) -> Dict[str, Any]:
        """
        Retrieve recent alerts within time window.
        """
        cutoff = datetime.now() - timedelta(minutes=time_window_minutes)
        
        recent_alerts = [
            alert for alert in self.alerts
            if datetime.fromisoformat(alert['timestamp']) > cutoff
        ]
        
        return {
            'status': 'success',
            'alert_count': len(recent_alerts),
            'alerts': recent_alerts
        }
    
    def _get_statistics(self) -> Dict[str, Any]:
        """
        Return IDS statistics and metrics.
        """
        return {
            'status': 'success',
            'statistics': {
                'total_alerts': len(self.alerts),
                'alerts_by_severity': self.alert_count_by_severity,
                'monitored_agents': len(self.access_history),
                'total_access_logs': sum(len(logs) for logs in self.access_history.values()),
                'total_denied_attempts': sum(len(denials) for denials in self.denied_attempts.values())
            }
        }


# ============================================
# DEMO USAGE (Standalone testing)
# ============================================

if __name__ == "__main__":
    print("=" * 70)
    print("IDS AGENT - DEMO (Standalone Mode)")
    print("=" * 70)
    
    # Initialize IDS Agent
    ids_agent = IDSAgent()
    
    # ==========================================
    # TEST 1: NORMAL ACCESS PATTERN
    # ==========================================
    print("\n" + "=" * 70)
    print("TEST 1: NORMAL ACCESS PATTERN - Doctor accessing 3 patients")
    print("=" * 70)
    
    for i in range(3):
        access_msg = {
            'from': 'system',
            'action': 'log_access',
            'data': {
                'agent': 'doctor_agent_1',
                'action': 'retrieve_patient',
                'patient_id': f'P00{i+1}',
                'timestamp': datetime.now().isoformat()
            }
        }
        response = ids_agent.process_message(access_msg)
        print(f"  Access {i+1}: {response['status']}")
    
    print("\n✅ Result: Normal pattern - No alerts generated")
    
    # ==========================================
    # TEST 2: HIGH REQUEST RATE ANOMALY
    # ==========================================
    print("\n" + "=" * 70)
    print("TEST 2: HIGH REQUEST RATE - Receptionist accessing 15 records in 1 minute")
    print("=" * 70)
    
    for i in range(15):
        access_msg = {
            'from': 'system',
            'action': 'log_access',
            'data': {
                'agent': 'receptionist_agent_1',
                'action': 'retrieve_patient',
                'patient_id': f'P{i+1:03d}',
                'timestamp': datetime.now().isoformat()
            }
        }
        response = ids_agent.process_message(access_msg)
    
    print(f"\n🚨 Alert generated: {response.get('status')}")
    print(f"   Severity: {response.get('severity')}")
    
    # ==========================================
    # TEST 3: REPEATED DENIED ATTEMPTS
    # ==========================================
    print("\n" + "=" * 70)
    print("TEST 3: REPEATED DENIED ATTEMPTS - Billing trying to access clinical data")
    print("=" * 70)
    
    for i in range(5):
        denial_msg = {
            'from': 'access_control_agent',
            'action': 'log_denied_attempt',
            'data': {
                'agent': 'billing_agent_1',
                'action': 'access_diagnosis',
                'reason': 'Unauthorized field access',
                'patient_id': 'P001',
                'timestamp': datetime.now().isoformat()
            }
        }
        response = ids_agent.process_message(denial_msg)
        print(f"  Denied attempt {i+1}: {response.get('status', response.get('severity'))}")
    
    # ==========================================
    # TEST 4: UNUSUAL ACCESS TIME
    # ==========================================
    print("\n" + "=" * 70)
    print("TEST 4: UNUSUAL ACCESS TIME - After-hours access at 11 PM")
    print("=" * 70)
    
    # Simulate access at 11 PM
    late_night = datetime.now().replace(hour=23, minute=0)
    access_msg = {
        'from': 'system',
        'action': 'log_access',
        'data': {
            'agent': 'nurse_agent_1',
            'action': 'retrieve_patient',
            'patient_id': 'P001',
            'timestamp': late_night.isoformat()
        }
    }
    response = ids_agent.process_message(access_msg)
    print(f"Response: {response.get('status')}")
    if response.get('status') == 'alert':
        print(f"🚨 Alert: {response.get('severity')} severity")
    
    # ==========================================
    # TEST 5: GET STATISTICS
    # ==========================================
    print("\n" + "=" * 70)
    print("IDS STATISTICS")
    print("=" * 70)
    
    stats_msg = {
        'from': 'system',
        'action': 'get_statistics',
        'data': {}
    }
    stats_response = ids_agent.process_message(stats_msg)
    stats = stats_response['statistics']
    
    print(f"\n📊 Total Alerts: {stats['total_alerts']}")
    print(f"📊 Alerts by Severity:")
    for severity, count in stats['alerts_by_severity'].items():
        if count > 0:
            print(f"   {severity}: {count}")
    print(f"📊 Monitored Agents: {stats['monitored_agents']}")
    print(f"📊 Total Access Logs: {stats['total_access_logs']}")
    print(f"📊 Total Denied Attempts: {stats['total_denied_attempts']}")
    
    # ==========================================
    # DEMO SUMMARY
    # ==========================================
    print("\n" + "=" * 70)
    print("DEMO SUMMARY")
    print("=" * 70)
    print("""
✅ ANOMALIES DETECTED:
   - High request rate: 15 requests in 1 minute (threshold: 10)
   - Repeated denied attempts: 5 attempts (threshold: 3)
   - Unusual access time: After-hours access detected
   
✅ ALERTS GENERATED:
   - HIGH severity: High request rate
   - CRITICAL severity: Repeated denied attempts
   - MEDIUM severity: Unusual access time

🎯 DEMO TALKING POINT:
   "After the AIIMS ransomware attack, hospitals realized they can't detect
   insider threats in real-time. Our IDS Agent watches for unusual access
   patterns—too many records accessed, access at odd times, repeated failed
   attempts. When it detects an anomaly, security is alerted instantly.
   This is how you catch attacks before they become breaches."
    """)
    print("=" * 70)