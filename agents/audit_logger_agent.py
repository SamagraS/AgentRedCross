# agents/audit_logger_agent.py
from agents.base_agent import BaseAgent
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from psycopg2.extras import RealDictCursor
from database.db_pool import PostgresPool


class AuditLoggerAgent(BaseAgent):
    """
    PostgreSQL-based Audit Logger Agent.
    Creates immutable audit trail for compliance (HIPAA, DPDP Act).
    
    Logs ALL system events:
    - Patient record access (WHO accessed WHAT, WHEN, WHY)
    - Data modifications (field changes with before/after values)
    - Security events (access denied, alerts generated)
    - Agent actions (diagnosis written, lab ordered, etc.)
    """
    
    def __init__(self, agent_id: str = "audit_logger"):
        # Initialize with BaseAgent
        super().__init__(
            agent_id=agent_id,
            role="system",
            permissions=['log_all_events', 'maintain_immutable_log', 'query_audit_trail']
        )
        
        # Event type categories
        self.EVENT_CATEGORIES = {
            'ACCESS': ['access_granted', 'access_denied', 'retrieve_patient', 'read_patient_basics'],
            'MODIFICATION': ['create_patient', 'update_medical_record', 'write_diagnosis', 
                           'update_appointment', 'update_vitals'],
            'SECURITY': ['security_alert_generated', 'privacy_filter_applied', 
                        'access_control_validation', 'ids_anomaly_detected'],
            'CLINICAL': ['write_diagnosis', 'order_lab', 'order_imaging', 
                        'prescribe_medication', 'discharge_patient'],
            'ADMINISTRATIVE': ['patient_registered', 'doctor_scheduled', 
                             'generate_bill', 'update_insurance']
        }
        
        # Initialize database tables
        self._initialize_tables()
    
    def _initialize_tables(self):
        """
        Create audit_logs table if it doesn't exist.
        """
        conn = PostgresPool.get_conn()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                agent_id VARCHAR(100) NOT NULL,
                action VARCHAR(100) NOT NULL,
                patient_id VARCHAR(50),
                details TEXT,
                category VARCHAR(50),
                severity VARCHAR(20) DEFAULT 'INFO',
                result VARCHAR(50) DEFAULT 'SUCCESS',
                ip_address VARCHAR(50),
                session_id VARCHAR(100)
            );
        """)
        
        # Create indexes for fast querying
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_patient 
            ON audit_logs(patient_id);
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_agent 
            ON audit_logs(agent_id);
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
            ON audit_logs(timestamp);
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_category 
            ON audit_logs(category);
        """)
        
        conn.commit()
        PostgresPool.return_conn(conn)
    
    # -------------------------------------------------------------------------
    # MESSAGE ROUTER
    # -------------------------------------------------------------------------
    def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for audit logging.
        
        Expected message format:
        {
            'from': 'agent_id',
            'action': 'log_event' | 'query_logs' | 'get_statistics',
            'data': {
                'agent_id': 'doctor_agent_1',
                'action': 'retrieve_patient',
                'patient_id': 'P001',
                'details': 'Additional context',
                'timestamp': '2024-12-04T10:30:00'
            }
        }
        """
        
        action = message.get('action', 'unknown')
        data = message.get('data', {})
        
        if action == 'log_event':
            return self._log_event(data)
        
        elif action == 'query_logs':
            return self._query_logs(data)
        
        elif action == 'get_statistics':
            return self._get_statistics()
        
        elif action == 'export_logs':
            return self._export_logs(data)
        
        else:
            return {
                'status': 'error',
                'message': f'Unknown action: {action}'
            }
    
    # -------------------------------------------------------------------------
    # LOG EVENT
    # -------------------------------------------------------------------------
    def _log_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log an event to the PostgreSQL audit trail.
        """
        
        conn = PostgresPool.get_conn()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Categorize event
        category = self._categorize_event(data.get('action', 'unknown'))
        
        # Insert log entry
        cursor.execute("""
            INSERT INTO audit_logs 
                (agent_id, action, patient_id, details, category, severity, result)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING log_id, timestamp;
        """, (
            data.get('agent_id', 'unknown'),
            data.get('action', 'unknown'),
            data.get('patient_id', 'N/A'),
            data.get('details', ''),
            category,
            data.get('severity', 'INFO'),
            data.get('result', 'SUCCESS')
        ))
        
        result = cursor.fetchone()
        log_id = result['log_id']
        timestamp = result['timestamp']
        
        conn.commit()
        PostgresPool.return_conn(conn)
        
        return {
            'status': 'success',
            'log_id': log_id,
            'timestamp': timestamp.isoformat(),
            'message': 'Event logged successfully'
        }
    
    def _categorize_event(self, action: str) -> str:
        """
        Categorize event based on action type.
        """
        for category, actions in self.EVENT_CATEGORIES.items():
            if action in actions:
                return category
        return 'OTHER'
    
    # -------------------------------------------------------------------------
    # QUERY LOGS
    # -------------------------------------------------------------------------
    def _query_logs(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """
        Query audit logs with filters.
        
        Supported filters:
        - patient_id: Filter by specific patient
        - agent_id: Filter by specific agent
        - action: Filter by specific action
        - category: Filter by event category
        - severity: Filter by severity level
        - time_range_minutes: Filter by time window
        - limit: Max results to return (default 100)
        """
        
        conn = PostgresPool.get_conn()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Build WHERE clause dynamically
        where_clauses = []
        params = []
        
        if 'patient_id' in query:
            where_clauses.append("patient_id = %s")
            params.append(query['patient_id'])
        
        if 'agent_id' in query:
            where_clauses.append("agent_id = %s")
            params.append(query['agent_id'])
        
        if 'action' in query:
            where_clauses.append("action = %s")
            params.append(query['action'])
        
        if 'category' in query:
            where_clauses.append("category = %s")
            params.append(query['category'])
        
        if 'severity' in query:
            where_clauses.append("severity = %s")
            params.append(query['severity'])
        
        if 'time_range_minutes' in query:
            where_clauses.append("timestamp > NOW() - INTERVAL '%s minutes'")
            params.append(query['time_range_minutes'])
        
        # Construct SQL
        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
        limit = query.get('limit', 100)
        
        sql = f"""
            SELECT * FROM audit_logs
            WHERE {where_sql}
            ORDER BY timestamp DESC
            LIMIT %s
        """
        params.append(limit)
        
        cursor.execute(sql, tuple(params))
        logs = cursor.fetchall()
        
        PostgresPool.return_conn(conn)
        
        # Convert to list of dicts with timestamp as string
        logs_list = []
        for log in logs:
            log_dict = dict(log)
            log_dict['timestamp'] = log_dict['timestamp'].isoformat()
            logs_list.append(log_dict)
        
        return {
            'status': 'success',
            'result_count': len(logs_list),
            'logs': logs_list,
            'query': query
        }
    
    # -------------------------------------------------------------------------
    # STATISTICS
    # -------------------------------------------------------------------------
    def _get_statistics(self) -> Dict[str, Any]:
        """
        Return audit trail statistics.
        """
        
        conn = PostgresPool.get_conn()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Total logs
        cursor.execute("SELECT COUNT(*) as total FROM audit_logs")
        total_logs = cursor.fetchone()['total']
        
        # Logs by category
        cursor.execute("""
            SELECT category, COUNT(*) as count
            FROM audit_logs
            GROUP BY category
        """)
        logs_by_category = {row['category']: row['count'] for row in cursor.fetchall()}
        
        # Logs by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM audit_logs
            GROUP BY severity
        """)
        logs_by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Unique agents
        cursor.execute("SELECT COUNT(DISTINCT agent_id) as count FROM audit_logs")
        unique_agents = cursor.fetchone()['count']
        
        # Unique patients
        cursor.execute("""
            SELECT COUNT(DISTINCT patient_id) as count 
            FROM audit_logs 
            WHERE patient_id != 'N/A'
        """)
        unique_patients = cursor.fetchone()['count']
        
        PostgresPool.return_conn(conn)
        
        return {
            'status': 'success',
            'statistics': {
                'total_logs': total_logs,
                'logs_by_category': logs_by_category,
                'logs_by_severity': logs_by_severity,
                'unique_agents': unique_agents,
                'unique_patients': unique_patients,
                'storage': 'PostgreSQL'
            }
        }
    
    # -------------------------------------------------------------------------
    # EXPORT LOGS
    # -------------------------------------------------------------------------
    def _export_logs(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Export logs to specific format (for compliance reporting).
        """
        export_format = data.get('format', 'json')
        query = data.get('query', {})
        
        # Query logs
        query_result = self._query_logs(query)
        logs = query_result['logs']
        
        if export_format == 'json':
            return {
                'status': 'success',
                'format': 'json',
                'logs': logs
            }
        
        elif export_format == 'csv':
            csv_data = self._convert_to_csv(logs)
            return {
                'status': 'success',
                'format': 'csv',
                'data': csv_data
            }
        
        else:
            return {
                'status': 'error',
                'message': f'Unsupported export format: {export_format}'
            }
    
    def _convert_to_csv(self, logs: List[Dict]) -> str:
        """
        Convert logs to CSV format.
        """
        if not logs:
            return "No logs to export"
        
        # CSV header
        headers = ['log_id', 'timestamp', 'agent_id', 'action', 'patient_id', 
                  'category', 'severity', 'result', 'details']
        csv_lines = [','.join(headers)]
        
        # CSV rows
        for log in logs:
            row = [
                str(log.get('log_id', '')),
                log.get('timestamp', ''),
                log.get('agent_id', ''),
                log.get('action', ''),
                log.get('patient_id', ''),
                log.get('category', ''),
                log.get('severity', ''),
                log.get('result', ''),
                log.get('details', '').replace(',', ';')  # Escape commas
            ]
            csv_lines.append(','.join(row))
        
        return '\n'.join(csv_lines)
    
    # -------------------------------------------------------------------------
    # COMPLIANCE REPORT
    # -------------------------------------------------------------------------
    def generate_compliance_report(self, patient_id: str) -> Dict[str, Any]:
        """
        Generate compliance report for a specific patient.
        (Who accessed this patient's data? When? Why?)
        """
        query_result = self._query_logs({'patient_id': patient_id, 'limit': 1000})
        logs = query_result['logs']
        
        # Aggregate data
        access_count = sum(1 for log in logs if log['category'] == 'ACCESS')
        modification_count = sum(1 for log in logs if log['category'] == 'MODIFICATION')
        agents_accessed = set(log['agent_id'] for log in logs)
        
        return {
            'status': 'success',
            'patient_id': patient_id,
            'total_events': len(logs),
            'access_events': access_count,
            'modification_events': modification_count,
            'unique_agents': len(agents_accessed),
            'agents_list': list(agents_accessed),
            'timeline': logs[:10],  # Most recent 10 events
            'compliance_status': 'COMPLIANT' if len(logs) > 0 else 'NO_ACTIVITY'
        }


# ============================================
# DEMO USAGE (Standalone testing)
# ============================================

if __name__ == "__main__":
    print("=" * 70)
    print("AUDIT LOGGER AGENT - DEMO (PostgreSQL)")
    print("=" * 70)
    print("\n⚠️  Note: This demo requires PostgreSQL connection.")
    print("Make sure database.db_pool is configured.\n")
    
    # Initialize Audit Logger
    try:
        audit_logger = AuditLoggerAgent()
        print("✅ Audit Logger initialized with PostgreSQL")
    except Exception as e:
        print(f"❌ Failed to initialize: {e}")
        print("Ensure PostgreSQL is running and db_pool is configured.")
        exit(1)
    
    # Test logging events
    print("\n" + "=" * 70)
    print("TEST: LOGGING EVENTS TO POSTGRESQL")
    print("=" * 70)
    
    events = [
        {
            'agent_id': 'receptionist_agent_1',
            'action': 'patient_registered',
            'patient_id': 'P001',
            'details': 'New patient registration',
            'severity': 'INFO'
        },
        {
            'agent_id': 'doctor_agent_1',
            'action': 'retrieve_patient',
            'patient_id': 'P001',
            'details': 'Doctor accessed patient record',
            'severity': 'INFO'
        },
        {
            'agent_id': 'access_control_agent',
            'action': 'access_denied',
            'patient_id': 'P001',
            'details': 'Receptionist tried to access diagnosis',
            'severity': 'WARNING'
        }
    ]
    
    for event in events:
        msg = {
            'from': 'system',
            'action': 'log_event',
            'data': event
        }
        response = audit_logger.process_message(msg)
        print(f"  ✅ Logged: {event['action']} - Log ID: {response['log_id']}")
    
    # Query logs
    print("\n" + "=" * 70)
    print("TEST: QUERY LOGS FROM POSTGRESQL")
    print("=" * 70)
    
    query_msg = {
        'from': 'system',
        'action': 'query_logs',
        'data': {'patient_id': 'P001', 'limit': 10}
    }
    query_response = audit_logger.process_message(query_msg)
    
    print(f"\n📊 Found {query_response['result_count']} events for patient P001:")
    for log in query_response['logs']:
        print(f"   [{log['timestamp'][:19]}] {log['agent_id']}: {log['action']}")
    
    # Statistics
    print("\n" + "=" * 70)
    print("TEST: AUDIT STATISTICS")
    print("=" * 70)
    
    stats_msg = {'from': 'system', 'action': 'get_statistics', 'data': {}}
    stats_response = audit_logger.process_message(stats_msg)
    stats = stats_response['statistics']
    
    print(f"\n📊 Total Logs: {stats['total_logs']}")
    print(f"📊 Unique Agents: {stats['unique_agents']}")
    print(f"📊 Unique Patients: {stats['unique_patients']}")
    print(f"📊 Storage: {stats['storage']}")
    
    print("\n" + "=" * 70)
    print("✅ PostgreSQL Audit Logger Demo Complete")
    print("=" * 70)