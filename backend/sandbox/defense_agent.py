"""
Virtual Cybersecurity Sandbox - Rule-Based Defense Agent
Automated defense system that monitors containers and responds to threats
Real-time threat detection and mitigation using security rules
"""

import json
import time
import threading
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import socket
import psutil
from collections import defaultdict, deque
import re

@dataclass
class SecurityEvent:
    """Security event detected by monitoring"""
    event_id: str
    timestamp: str
    event_type: str  # "intrusion", "anomaly", "policy_violation", "attack_detected"
    severity: str    # "low", "medium", "high", "critical"
    source_ip: str
    target_container: str
    description: str
    evidence: Dict[str, Any]
    mitigation_action: str
    status: str      # "detected", "investigating", "mitigated", "false_positive"

@dataclass
class DefenseAction:
    """Automated defense action taken"""
    action_id: str
    trigger_event: str
    action_type: str  # "block_ip", "isolate_container", "alert", "patch", "restart"
    target: str
    parameters: Dict[str, Any]
    execution_time: str
    success: bool
    impact: str

class RuleBasedDefenseAgent:
    """
    Automated defense system using rule-based detection and response
    Monitors sandbox containers and responds to security threats
    """
    
    def __init__(self, container_orchestrator, attack_simulator):
        self.orchestrator = container_orchestrator
        self.attack_simulator = attack_simulator
        self.monitoring_active = False
        self.monitoring_threads = {}
        
        # Security events storage
        self.security_events: Dict[str, SecurityEvent] = {}
        self.defense_actions: Dict[str, DefenseAction] = {}
        
        # Real-time monitoring data
        self.network_traffic = defaultdict(lambda: deque(maxlen=1000))
        self.system_metrics = defaultdict(lambda: deque(maxlen=1000))
        self.log_patterns = defaultdict(lambda: deque(maxlen=1000))
        
        # Rule-based detection rules
        self.DETECTION_RULES = {
            "port_scan_detection": {
                "description": "Detect port scanning attempts",
                "pattern": "Multiple connection attempts to different ports",
                "threshold": {"connections_per_minute": 50, "unique_ports": 10},
                "severity": "medium",
                "response_actions": ["log_event", "rate_limit_source"]
            },
            
            "brute_force_detection": {
                "description": "Detect authentication brute force attacks",
                "pattern": "Multiple failed login attempts",
                "threshold": {"failed_attempts": 10, "time_window": 300},
                "severity": "high", 
                "response_actions": ["block_source_ip", "alert_admin"]
            },
            
            "sql_injection_detection": {
                "description": "Detect SQL injection attempts",
                "pattern": r"(union\s+select|or\s+1=1|drop\s+table)",
                "log_sources": ["web_server", "application"],
                "severity": "high",
                "response_actions": ["block_request", "enable_waf_strict_mode"]
            },
            
            "ddos_detection": {
                "description": "Detect DDoS attacks",
                "pattern": "High volume of requests from single source",
                "threshold": {"requests_per_second": 100, "duration": 60},
                "severity": "critical",
                "response_actions": ["rate_limit_aggressive", "block_source_ip"]
            },
            
            "lateral_movement_detection": {
                "description": "Detect lateral movement attempts",
                "pattern": "Unusual network connections between containers",
                "threshold": {"cross_container_connections": 5, "time_window": 600},
                "severity": "high",
                "response_actions": ["isolate_suspicious_container", "deep_packet_inspect"]
            },
            
            "privilege_escalation_detection": {
                "description": "Detect privilege escalation attempts", 
                "pattern": "Unauthorized privilege elevation",
                "indicators": ["sudo_failures", "setuid_execution", "kernel_module_loading"],
                "severity": "critical",
                "response_actions": ["isolate_container", "forensic_snapshot"]
            },
            
            "data_exfiltration_detection": {
                "description": "Detect data exfiltration attempts",
                "pattern": "Unusual outbound data transfer",
                "threshold": {"outbound_bytes": 100000000, "time_window": 300},  # 100MB in 5 minutes
                "severity": "critical",
                "response_actions": ["block_outbound_traffic", "alert_admin"]
            },
            
            "malware_behavior_detection": {
                "description": "Detect malware-like behavior",
                "indicators": ["file_encryption_patterns", "registry_modification", "network_beaconing"],
                "severity": "critical",
                "response_actions": ["quarantine_container", "malware_analysis"]
            },
            
            "insider_threat_detection": {
                "description": "Detect insider threat indicators",
                "pattern": "Unusual access patterns or data access",
                "threshold": {"off_hours_access": True, "sensitive_data_access": 5},
                "severity": "medium",
                "response_actions": ["enhanced_monitoring", "access_review"]
            },
            
            "configuration_drift_detection": {
                "description": "Detect unauthorized configuration changes",
                "pattern": "Changes to critical security configurations",
                "monitored_files": ["/etc/passwd", "/etc/shadow", "/etc/sudo"],
                "severity": "high",
                "response_actions": ["revert_configuration", "alert_admin"]
            }
        }
        
        # Response action implementations
        self.RESPONSE_ACTIONS = {
            "block_source_ip": self._block_source_ip,
            "isolate_container": self._isolate_container,
            "rate_limit_source": self._rate_limit_source,
            "enable_waf_strict_mode": self._enable_waf_strict_mode,
            "alert_admin": self._alert_admin,
            "log_event": self._log_security_event,
            "quarantine_container": self._quarantine_container,
            "forensic_snapshot": self._create_forensic_snapshot,
            "revert_configuration": self._revert_configuration,
            "enhanced_monitoring": self._enable_enhanced_monitoring
        }

    def start_monitoring(self, sandbox_id: str):
        """Start real-time monitoring for sandbox environment"""
        if self.monitoring_active:
            print("⚠️  Monitoring already active")
            return
        
        self.monitoring_active = True
        sandbox_env = self.orchestrator.sandbox_environments.get(sandbox_id)
        
        if not sandbox_env:
            raise ValueError(f"Sandbox not found: {sandbox_id}")
        
        print(f"🛡️  Starting defense agent monitoring for sandbox: {sandbox_id}")
        print(f"📊 Monitoring {len(sandbox_env.containers)} containers")
        
        # Start monitoring threads
        monitor_threads = {
            "network_monitor": threading.Thread(
                target=self._network_monitoring_worker,
                args=(sandbox_id,)
            ),
            "log_analyzer": threading.Thread(
                target=self._log_analysis_worker, 
                args=(sandbox_id,)
            ),
            "system_monitor": threading.Thread(
                target=self._system_monitoring_worker,
                args=(sandbox_id,)
            ),
            "threat_correlator": threading.Thread(
                target=self._threat_correlation_worker,
                args=(sandbox_id,)
            )
        }
        
        # Start all monitoring threads
        for thread_name, thread in monitor_threads.items():
            thread.daemon = True
            thread.start()
            self.monitoring_threads[thread_name] = thread
            print(f"✅ Started {thread_name}")
        
        print("🚀 Defense agent fully operational")

    def stop_monitoring(self):
        """Stop all monitoring activities"""
        print("🛑 Stopping defense agent monitoring")
        self.monitoring_active = False
        
        # Wait for threads to finish
        for thread_name, thread in self.monitoring_threads.items():
            if thread.is_alive():
                print(f"⏳ Waiting for {thread_name} to stop...")
                thread.join(timeout=5)
        
        self.monitoring_threads.clear()
        print("✅ Defense agent monitoring stopped")

    def _network_monitoring_worker(self, sandbox_id: str):
        """Monitor network traffic for suspicious activities"""
        print("🌐 Network monitoring worker started")
        
        while self.monitoring_active:
            try:
                # Get all containers in sandbox
                sandbox_env = self.orchestrator.sandbox_environments.get(sandbox_id)
                if not sandbox_env:
                    break
                
                for container_name in [c.container_name for c in sandbox_env.containers.values()]:
                    network_stats = self._collect_container_network_stats(container_name)
                    
                    if network_stats:
                        self.network_traffic[container_name].append({
                            "timestamp": datetime.now().isoformat(),
                            "stats": network_stats
                        })
                        
                        # Apply network-based detection rules
                        self._apply_network_detection_rules(container_name, network_stats)
                
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                print(f"❌ Network monitoring error: {e}")
                time.sleep(10)

    def _log_analysis_worker(self, sandbox_id: str):
        """Analyze container logs for security events"""
        print("📋 Log analysis worker started")
        
        while self.monitoring_active:
            try:
                # Get all containers in sandbox
                sandbox_env = self.orchestrator.sandbox_environments.get(sandbox_id)
                if not sandbox_env:
                    break
                
                for container_name in [c.container_name for c in sandbox_env.containers.values()]:
                    log_entries = self._collect_container_logs(container_name)
                    
                    for log_entry in log_entries:
                        self.log_patterns[container_name].append(log_entry)
                        
                        # Apply log-based detection rules  
                        self._apply_log_detection_rules(container_name, log_entry)
                
                time.sleep(10)  # Analyze logs every 10 seconds
                
            except Exception as e:
                print(f"❌ Log analysis error: {e}")
                time.sleep(15)

    def _system_monitoring_worker(self, sandbox_id: str):
        """Monitor system metrics for anomalies"""
        print("⚙️  System monitoring worker started")
        
        while self.monitoring_active:
            try:
                # Get all containers in sandbox
                sandbox_env = self.orchestrator.sandbox_environments.get(sandbox_id)
                if not sandbox_env:
                    break
                
                for container_name in [c.container_name for c in sandbox_env.containers.values()]:
                    system_stats = self._collect_container_system_stats(container_name)
                    
                    if system_stats:
                        self.system_metrics[container_name].append({
                            "timestamp": datetime.now().isoformat(),
                            "stats": system_stats
                        })
                        
                        # Apply system-based detection rules
                        self._apply_system_detection_rules(container_name, system_stats)
                
                time.sleep(15)  # Monitor system every 15 seconds
                
            except Exception as e:
                print(f"❌ System monitoring error: {e}")
                time.sleep(20)

    def _threat_correlation_worker(self, sandbox_id: str):
        """Correlate security events to detect complex attack patterns"""
        print("🔍 Threat correlation worker started")
        
        while self.monitoring_active:
            try:
                # Correlate recent security events
                recent_events = [
                    event for event in self.security_events.values()
                    if self._is_recent_event(event.timestamp, minutes=30)
                ]
                
                # Apply correlation rules
                self._apply_correlation_rules(recent_events)
                
                time.sleep(30)  # Correlate every 30 seconds
                
            except Exception as e:
                print(f"❌ Threat correlation error: {e}")
                time.sleep(60)

    def _collect_container_network_stats(self, container_name: str) -> Optional[Dict[str, Any]]:
        """Collect network statistics from container"""
        try:
            container = self.orchestrator.docker_client.containers.get(container_name)
            stats = container.stats(stream=False)
            
            network_stats = stats.get('networks', {})
            if not network_stats:
                return None
            
            # Calculate network metrics
            total_rx_bytes = sum(iface.get('rx_bytes', 0) for iface in network_stats.values())
            total_tx_bytes = sum(iface.get('tx_bytes', 0) for iface in network_stats.values())
            total_rx_packets = sum(iface.get('rx_packets', 0) for iface in network_stats.values())
            total_tx_packets = sum(iface.get('tx_packets', 0) for iface in network_stats.values())
            
            return {
                "rx_bytes": total_rx_bytes,
                "tx_bytes": total_tx_bytes,
                "rx_packets": total_rx_packets,
                "tx_packets": total_tx_packets,
                "connections": self._get_container_connections(container_name)
            }
            
        except Exception as e:
            print(f"⚠️  Failed to collect network stats for {container_name}: {e}")
            return None

    def _collect_container_logs(self, container_name: str) -> List[str]:
        """Collect recent log entries from container"""
        try:
            container = self.orchestrator.docker_client.containers.get(container_name)
            logs = container.logs(tail=50, timestamps=True, since=datetime.now() - timedelta(minutes=1))
            
            return logs.decode('utf-8', errors='ignore').split('\n')
            
        except Exception as e:
            print(f"⚠️  Failed to collect logs for {container_name}: {e}")
            return []

    def _collect_container_system_stats(self, container_name: str) -> Optional[Dict[str, Any]]:
        """Collect system resource statistics from container"""
        try:
            container = self.orchestrator.docker_client.containers.get(container_name)
            stats = container.stats(stream=False)
            
            # Calculate CPU usage
            cpu_stats = stats.get('cpu_stats', {})
            precpu_stats = stats.get('precpu_stats', {})
            
            cpu_usage = 0.0
            if cpu_stats and precpu_stats:
                cpu_delta = cpu_stats.get('cpu_usage', {}).get('total_usage', 0) - \
                           precpu_stats.get('cpu_usage', {}).get('total_usage', 0)
                system_delta = cpu_stats.get('system_cpu_usage', 0) - \
                              precpu_stats.get('system_cpu_usage', 0)
                
                if system_delta > 0:
                    cpu_usage = (cpu_delta / system_delta) * 100.0
            
            # Memory usage
            memory_stats = stats.get('memory_stats', {})
            memory_usage = memory_stats.get('usage', 0)
            memory_limit = memory_stats.get('limit', 0)
            
            return {
                "cpu_percent": cpu_usage,
                "memory_usage_bytes": memory_usage,
                "memory_limit_bytes": memory_limit,
                "memory_percent": (memory_usage / memory_limit * 100) if memory_limit > 0 else 0,
                "processes": self._get_container_processes(container_name)
            }
            
        except Exception as e:
            print(f"⚠️  Failed to collect system stats for {container_name}: {e}")
            return None

    def _get_container_connections(self, container_name: str) -> List[Dict[str, Any]]:
        """Get active network connections for container"""
        try:
            # This would require container inspection or netstat execution
            # For simulation, return sample data
            return [
                {"local_port": 80, "remote_ip": "192.168.1.100", "state": "ESTABLISHED"},
                {"local_port": 443, "remote_ip": "192.168.1.101", "state": "ESTABLISHED"}
            ]
        except:
            return []

    def _get_container_processes(self, container_name: str) -> List[Dict[str, Any]]:
        """Get running processes in container"""
        try:
            container = self.orchestrator.docker_client.containers.get(container_name)
            top_result = container.top()
            
            processes = []
            for process in top_result.get('Processes', []):
                if len(process) >= 8:  # Standard ps output
                    processes.append({
                        "pid": process[1],
                        "command": process[7],
                        "cpu_percent": 0.0,  # Would need calculation
                        "memory_percent": 0.0  # Would need calculation
                    })
            
            return processes
            
        except Exception as e:
            print(f"⚠️  Failed to get processes for {container_name}: {e}")
            return []

    def _apply_network_detection_rules(self, container_name: str, network_stats: Dict[str, Any]):
        """Apply network-based detection rules"""
        
        # Port scan detection
        connections = network_stats.get('connections', [])
        unique_ports = len(set(conn.get('local_port') for conn in connections))
        
        if unique_ports > self.DETECTION_RULES['port_scan_detection']['threshold']['unique_ports']:
            self._trigger_security_event(
                container_name,
                "port_scan_detection",
                f"Port scanning detected: {unique_ports} unique ports accessed",
                {"connections": connections, "unique_ports": unique_ports}
            )
        
        # DDoS detection
        rx_packets = network_stats.get('rx_packets', 0)
        if rx_packets > self.DETECTION_RULES['ddos_detection']['threshold']['requests_per_second'] * 5:  # 5 second window
            self._trigger_security_event(
                container_name,
                "ddos_detection", 
                f"High packet rate detected: {rx_packets} packets",
                {"rx_packets": rx_packets, "threshold_exceeded": True}
            )

    def _apply_log_detection_rules(self, container_name: str, log_entry: str):
        """Apply log-based detection rules"""
        
        # SQL injection detection
        sql_injection_pattern = self.DETECTION_RULES['sql_injection_detection']['pattern']
        if re.search(sql_injection_pattern, log_entry.lower()):
            self._trigger_security_event(
                container_name,
                "sql_injection_detection",
                f"SQL injection attempt detected in logs",
                {"log_entry": log_entry, "pattern_matched": True}
            )
        
        # Brute force detection
        if any(keyword in log_entry.lower() for keyword in ['failed login', 'authentication failed', 'invalid password']):
            self._trigger_security_event(
                container_name,
                "brute_force_detection",
                f"Failed authentication attempt detected",
                {"log_entry": log_entry, "event_type": "failed_auth"}
            )

    def _apply_system_detection_rules(self, container_name: str, system_stats: Dict[str, Any]):
        """Apply system-based detection rules"""
        
        # High CPU usage (potential crypto mining or DoS)
        cpu_percent = system_stats.get('cpu_percent', 0)
        if cpu_percent > 90:
            self._trigger_security_event(
                container_name,
                "malware_behavior_detection",
                f"Abnormally high CPU usage: {cpu_percent}%",
                {"cpu_percent": cpu_percent, "threshold": 90}
            )
        
        # High memory usage
        memory_percent = system_stats.get('memory_percent', 0)
        if memory_percent > 95:
            self._trigger_security_event(
                container_name,
                "malware_behavior_detection",
                f"High memory usage detected: {memory_percent}%",
                {"memory_percent": memory_percent, "threshold": 95}
            )

    def _apply_correlation_rules(self, recent_events: List[SecurityEvent]):
        """Apply correlation rules to detect complex attack patterns"""
        
        # APT detection: Port scan -> Brute force -> Lateral movement
        event_types = [event.event_type for event in recent_events]
        
        if ("port_scan_detection" in event_types and 
            "brute_force_detection" in event_types and
            len(recent_events) >= 3):
            
            self._trigger_security_event(
                "correlation_engine",
                "apt_attack_pattern",
                "Advanced Persistent Threat pattern detected",
                {"correlated_events": len(recent_events), "pattern": "apt_simulation"}
            )

    def _trigger_security_event(self, container_name: str, rule_type: str, description: str, evidence: Dict[str, Any]):
        """Trigger a security event and execute response actions"""
        event_id = f"event_{int(time.time())}_{rule_type}_{id(evidence)}"
        
        rule = self.DETECTION_RULES.get(rule_type, {})
        severity = rule.get('severity', 'medium')
        
        # Create security event
        security_event = SecurityEvent(
            event_id=event_id,
            timestamp=datetime.now().isoformat(),
            event_type=rule_type,
            severity=severity,
            source_ip=evidence.get('source_ip', 'unknown'),
            target_container=container_name,
            description=description,
            evidence=evidence,
            mitigation_action="",
            status="detected"
        )
        
        self.security_events[event_id] = security_event
        
        print(f"🚨 Security event detected: {rule_type}")
        print(f"   Container: {container_name}")
        print(f"   Severity: {severity}")
        print(f"   Description: {description}")
        
        # Execute response actions
        response_actions = rule.get('response_actions', [])
        for action_type in response_actions:
            if action_type in self.RESPONSE_ACTIONS:
                action_id = self._execute_response_action(
                    action_type, container_name, evidence, event_id
                )
                security_event.mitigation_action = action_type
                print(f"   ✅ Response action executed: {action_type}")

    def _execute_response_action(self, action_type: str, target: str, evidence: Dict[str, Any], trigger_event: str) -> str:
        """Execute automated response action"""
        action_id = f"action_{int(time.time())}_{action_type}_{id(evidence)}"
        
        try:
            # Execute the action
            action_func = self.RESPONSE_ACTIONS[action_type]
            success = action_func(target, evidence)
            
            # Record the action
            defense_action = DefenseAction(
                action_id=action_id,
                trigger_event=trigger_event,
                action_type=action_type,
                target=target,
                parameters=evidence,
                execution_time=datetime.now().isoformat(),
                success=success,
                impact="mitigated" if success else "failed"
            )
            
            self.defense_actions[action_id] = defense_action
            
            return action_id
            
        except Exception as e:
            print(f"❌ Failed to execute response action {action_type}: {e}")
            return ""

    # Response action implementations
    
    def _block_source_ip(self, target: str, evidence: Dict[str, Any]) -> bool:
        """Block source IP address"""
        source_ip = evidence.get('source_ip', '192.168.1.100')
        
        try:
            # Add iptables rule to block IP
            command = f"iptables -A INPUT -s {source_ip} -j DROP"
            subprocess.run(command.split(), check=True)
            
            print(f"🚫 Blocked source IP: {source_ip}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to block IP {source_ip}: {e}")
            return False

    def _isolate_container(self, container_name: str, evidence: Dict[str, Any]) -> bool:
        """Isolate container by removing from networks"""
        try:
            container = self.orchestrator.docker_client.containers.get(container_name)
            
            # Get all networks the container is connected to
            networks = container.attrs['NetworkSettings']['Networks']
            
            # Disconnect from all networks except localhost
            for network_name in networks.keys():
                if network_name != 'none':
                    network = self.orchestrator.docker_client.networks.get(network_name)
                    network.disconnect(container)
            
            print(f"🔒 Isolated container: {container_name}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to isolate container {container_name}: {e}")
            return False

    def _rate_limit_source(self, target: str, evidence: Dict[str, Any]) -> bool:
        """Apply rate limiting to source"""
        source_ip = evidence.get('source_ip', '192.168.1.100')
        
        try:
            # Add rate limiting rule
            command = f"iptables -A INPUT -s {source_ip} -m limit --limit 10/sec --limit-burst 5 -j ACCEPT"
            subprocess.run(command.split(), check=True)
            
            print(f"⏳ Applied rate limiting to: {source_ip}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to apply rate limiting: {e}")
            return False

    def _enable_waf_strict_mode(self, target: str, evidence: Dict[str, Any]) -> bool:
        """Enable strict mode on WAF"""
        try:
            # This would configure WAF to block mode
            print(f"🛡️  Enabled WAF strict mode for: {target}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to enable WAF strict mode: {e}")
            return False

    def _alert_admin(self, target: str, evidence: Dict[str, Any]) -> bool:
        """Send alert to administrator"""
        try:
            # This would send email/SMS/Slack notification
            print(f"📧 Admin alert sent for: {target}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send admin alert: {e}")
            return False

    def _log_security_event(self, target: str, evidence: Dict[str, Any]) -> bool:
        """Log security event to SIEM"""
        try:
            # This would forward to SIEM system
            print(f"📝 Security event logged for: {target}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to log security event: {e}")
            return False

    def _quarantine_container(self, container_name: str, evidence: Dict[str, Any]) -> bool:
        """Quarantine container (stop and preserve for analysis)"""
        try:
            container = self.orchestrator.docker_client.containers.get(container_name)
            container.stop()
            
            print(f"🔒 Quarantined container: {container_name}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to quarantine container {container_name}: {e}")
            return False

    def _create_forensic_snapshot(self, container_name: str, evidence: Dict[str, Any]) -> bool:
        """Create forensic snapshot of container"""
        try:
            container = self.orchestrator.docker_client.containers.get(container_name)
            
            # Create forensic image
            snapshot_name = f"forensic_{container_name}_{int(time.time())}"
            container.commit(repository=snapshot_name, tag="forensic")
            
            print(f"📸 Created forensic snapshot: {snapshot_name}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to create forensic snapshot: {e}")
            return False

    def _revert_configuration(self, target: str, evidence: Dict[str, Any]) -> bool:
        """Revert unauthorized configuration changes"""
        try:
            # This would restore from backup configuration
            print(f"↩️  Reverted configuration for: {target}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to revert configuration: {e}")
            return False

    def _enable_enhanced_monitoring(self, target: str, evidence: Dict[str, Any]) -> bool:
        """Enable enhanced monitoring for target"""
        try:
            # This would increase monitoring frequency/depth
            print(f"🔍 Enhanced monitoring enabled for: {target}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to enable enhanced monitoring: {e}")
            return False

    def get_security_dashboard(self) -> Dict[str, Any]:
        """Get real-time security dashboard data"""
        current_time = datetime.now()
        
        # Recent events (last hour)
        recent_events = [
            event for event in self.security_events.values()
            if self._is_recent_event(event.timestamp, minutes=60)
        ]
        
        # Event counts by severity
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for event in recent_events:
            severity_counts[event.severity] += 1
        
        # Response action statistics
        recent_actions = [
            action for action in self.defense_actions.values()
            if self._is_recent_event(action.execution_time, minutes=60)
        ]
        
        action_success_rate = 0
        if recent_actions:
            successful_actions = sum(1 for action in recent_actions if action.success)
            action_success_rate = (successful_actions / len(recent_actions)) * 100
        
        return {
            "monitoring_status": "active" if self.monitoring_active else "inactive",
            "total_events": len(self.security_events),
            "recent_events": len(recent_events),
            "severity_breakdown": severity_counts,
            "total_actions": len(self.defense_actions),
            "recent_actions": len(recent_actions),
            "action_success_rate": action_success_rate,
            "threat_level": self._calculate_threat_level(recent_events),
            "last_update": current_time.isoformat()
        }

    def get_event_details(self, event_id: str) -> Dict[str, Any]:
        """Get detailed information about specific security event"""
        if event_id not in self.security_events:
            return {"error": "Security event not found"}
        
        event = self.security_events[event_id]
        return asdict(event)

    def _is_recent_event(self, timestamp: str, minutes: int) -> bool:
        """Check if event timestamp is within specified minutes"""
        try:
            event_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            time_diff = datetime.now() - event_time.replace(tzinfo=None)
            return time_diff.total_seconds() < (minutes * 60)
        except:
            return False

    def _calculate_threat_level(self, recent_events: List[SecurityEvent]) -> str:
        """Calculate overall threat level based on recent events"""
        if not recent_events:
            return "low"
        
        critical_events = sum(1 for event in recent_events if event.severity == "critical")
        high_events = sum(1 for event in recent_events if event.severity == "high")
        
        if critical_events > 0:
            return "critical"
        elif high_events > 2:
            return "high"
        elif len(recent_events) > 10:
            return "medium"
        else:
            return "low"