#!/usr/bin/env python3
"""
🔍 Port Scanning Attack Script
Network reconnaissance and port discovery against virtual environments
"""

import asyncio
import socket
import subprocess
import logging
import time
import ipaddress
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class PortScanAttack:
    def __init__(self):
        self.attack_name = "Port Scanning"
        self.attack_id = "port_scan"
        self.mitre_techniques = ["T1595.001", "T1046"]  # Active Scanning: Scanning IP Blocks, Network Service Discovery
        self.owasp_category = "A06:2021 - Vulnerable and Outdated Components"
        self.stride_category = "Information Disclosure"
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
            993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443
        ]
        
        # Extended port range for comprehensive scan
        self.extended_ports = list(range(1, 1025))
        
    async def execute_attack(self, environment: Dict, target_components: List[str], orchestrator) -> Dict:
        """
        Execute port scanning attack against target components
        
        Args:
            environment: Virtual environment containing target containers
            target_components: List of component IDs to target
            orchestrator: Main orchestrator instance
            
        Returns:
            Attack results with discovered services and vulnerabilities
        """
        logger.info(f"🔍 Starting Port Scan attack on environment {environment['id']}")
        
        results = {
            'attack_type': self.attack_name,
            'attack_id': self.attack_id,
            'success': False,
            'vulnerabilities_exploited': [],
            'systems_compromised': [],
            'data_accessed': [],
            'persistence_achieved': False,
            'lateral_movement': [],
            'attack_timeline': [],
            'technical_details': {
                'discovered_services': {},
                'open_ports': {},
                'service_versions': {},
                'potential_vulnerabilities': []
            }
        }
        
        # Phase 1: Network Discovery
        network_info = await self._discover_network(environment, results)
        
        # Phase 2: Port Scanning
        if network_info['targets']:
            scan_results = await self._port_scan_targets(network_info['targets'], results)
            
        # Phase 3: Service Enumeration
        if results['technical_details']['open_ports']:
            service_results = await self._enumerate_services(results)
            
        # Phase 4: Vulnerability Assessment
        if results['technical_details']['discovered_services']:
            vuln_results = await self._assess_vulnerabilities(results)
            
        # Determine overall attack success
        if (results['technical_details']['open_ports'] and 
            results['technical_details']['discovered_services']):
            results['success'] = True
            
        logger.info(f"✅ Port Scan attack completed. Open ports found: {len(results['technical_details']['open_ports'])}")
        return results
    
    async def _discover_network(self, environment: Dict, results: Dict) -> Dict:
        """Discover network topology and target IP addresses"""
        logger.info("🌐 Phase 1: Network Discovery")
        
        targets = []
        container_ips = {}
        
        try:
            # Get container network information
            for container_id, container in environment.get('containers', {}).items():
                try:
                    container.reload()
                    networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
                    
                    for network_name, network_info in networks.items():
                        ip_address = network_info.get('IPAddress')
                        if ip_address:
                            targets.append({
                                'ip': ip_address,
                                'container_id': container_id,
                                'network': network_name
                            })
                            container_ips[container_id] = ip_address
                            
                            logger.info(f"🎯 Discovered target: {container_id} at {ip_address}")
                            
                except Exception as e:
                    logger.warning(f"⚠️ Could not get network info for {container_id}: {e}")
            
            # Also scan localhost interfaces for exposed ports
            targets.append({
                'ip': '127.0.0.1',
                'container_id': 'localhost',
                'network': 'host'
            })
            
            results['attack_timeline'].append({
                'timestamp': time.time(),
                'action': 'network_discovery',
                'result': 'success',
                'targets_found': len(targets)
            })
            
        except Exception as e:
            logger.error(f"❌ Network discovery failed: {e}")
            results['attack_timeline'].append({
                'timestamp': time.time(),
                'action': 'network_discovery',
                'result': 'failed',
                'error': str(e)
            })
        
        return {'targets': targets, 'container_ips': container_ips}
    
    async def _port_scan_targets(self, targets: List[Dict], results: Dict) -> Dict:
        """Perform port scanning against discovered targets"""
        logger.info("🔍 Phase 2: Port Scanning")
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            scan_tasks = []
            
            for target in targets:
                # Quick scan with common ports first
                task = executor.submit(
                    self._scan_target_ports, 
                    target['ip'], 
                    target['container_id'],
                    self.common_ports,
                    'quick'
                )
                scan_tasks.append((task, target))
            
            # Collect results
            for task, target in scan_tasks:
                try:
                    scan_result = task.result(timeout=30)
                    
                    if scan_result['open_ports']:
                        results['technical_details']['open_ports'][target['container_id']] = scan_result['open_ports']
                        
                        logger.info(f"🔓 Open ports on {target['container_id']}: {scan_result['open_ports']}")
                        
                        results['attack_timeline'].append({
                            'timestamp': time.time(),
                            'action': 'port_scan',
                            'target': target['container_id'],
                            'result': 'success',
                            'open_ports': scan_result['open_ports']
                        })
                        
                except Exception as e:
                    logger.error(f"❌ Port scan failed for {target['container_id']}: {e}")
                    results['attack_timeline'].append({
                        'timestamp': time.time(),
                        'action': 'port_scan',
                        'target': target['container_id'],
                        'result': 'failed',
                        'error': str(e)
                    })
        
        return results
    
    def _scan_target_ports(self, target_ip: str, target_id: str, ports: List[int], scan_type: str) -> Dict:
        """Scan specific ports on a target"""
        open_ports = []
        
        for port in ports:
            try:
                # TCP Connect scan
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # 2 second timeout
                
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:  # Port is open
                    open_ports.append(port)
                    logger.debug(f"✅ Port {port} open on {target_ip}")
                
                sock.close()
                
            except Exception as e:
                logger.debug(f"❌ Error scanning port {port} on {target_ip}: {e}")
        
        return {
            'target_ip': target_ip,
            'target_id': target_id,
            'open_ports': open_ports,
            'scan_type': scan_type
        }
    
    async def _enumerate_services(self, results: Dict) -> Dict:
        """Enumerate services running on discovered open ports"""
        logger.info("🔬 Phase 3: Service Enumeration")
        
        service_map = {
            21: 'FTP',
            22: 'SSH', 
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        for container_id, ports in results['technical_details']['open_ports'].items():
            services = {}
            
            for port in ports:
                service_name = service_map.get(port, f'Unknown-{port}')
                services[port] = {
                    'name': service_name,
                    'version': 'Unknown',
                    'banner': None
                }
                
                # Try to grab service banner
                banner = await self._grab_service_banner(container_id, port)
                if banner:
                    services[port]['banner'] = banner
                    
                    # Try to extract version from banner
                    version = self._extract_version_from_banner(banner, service_name)
                    if version:
                        services[port]['version'] = version
            
            if services:
                results['technical_details']['discovered_services'][container_id] = services
                
                results['attack_timeline'].append({
                    'timestamp': time.time(),
                    'action': 'service_enumeration',
                    'target': container_id,
                    'result': 'success',
                    'services_found': len(services)
                })
        
        return results
    
    async def _grab_service_banner(self, container_id: str, port: int) -> str:
        """Attempt to grab service banner from open port"""
        try:
            # For localhost scanning (exposed container ports)
            if container_id == 'localhost':
                target_ip = '127.0.0.1'
            else:
                # This would need to be adapted for actual container IPs
                target_ip = '127.0.0.1'
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target_ip, port))
            
            # Send appropriate probe based on service
            if port == 80 or port == 8080:
                sock.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25:
                sock.send(b'HELO localhost\r\n')
            else:
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                logger.info(f"🏷️ Banner from {container_id}:{port}: {banner[:100]}...")
                return banner
                
        except Exception as e:
            logger.debug(f"❌ Banner grab failed for {container_id}:{port}: {e}")
        
        return None
    
    def _extract_version_from_banner(self, banner: str, service_name: str) -> str:
        """Extract version information from service banner"""
        import re
        
        # Common version patterns
        version_patterns = [
            r'(\d+\.\d+\.\d+)',  # X.Y.Z
            r'(\d+\.\d+)',       # X.Y
            r'version\s+(\d+\.\d+\.\d+)',
            r'Apache/(\d+\.\d+\.\d+)',
            r'nginx/(\d+\.\d+\.\d+)',
            r'MySQL\s+(\d+\.\d+\.\d+)',
            r'OpenSSH_(\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'Unknown'
    
    async def _assess_vulnerabilities(self, results: Dict) -> Dict:
        """Assess potential vulnerabilities based on discovered services"""
        logger.info("🚨 Phase 4: Vulnerability Assessment")
        
        vulnerability_db = {
            'SSH': {
                'common_vulns': ['weak_authentication', 'default_credentials', 'protocol_vulnerabilities'],
                'default_creds': [('root', 'root'), ('admin', 'admin'), ('user', 'password')]
            },
            'FTP': {
                'common_vulns': ['anonymous_access', 'weak_authentication', 'plaintext_transmission'],
                'default_creds': [('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin')]
            },
            'HTTP': {
                'common_vulns': ['web_application_vulnerabilities', 'information_disclosure', 'weak_authentication'],
                'default_creds': [('admin', 'admin'), ('admin', 'password')]
            },
            'MySQL': {
                'common_vulns': ['weak_authentication', 'sql_injection', 'privilege_escalation'],
                'default_creds': [('root', ''), ('root', 'root'), ('admin', 'admin123')]
            },
            'Telnet': {
                'common_vulns': ['plaintext_transmission', 'weak_authentication', 'protocol_vulnerabilities'],
                'default_creds': [('admin', 'admin'), ('root', 'root')]
            }
        }
        
        potential_vulns = []
        
        for container_id, services in results['technical_details']['discovered_services'].items():
            for port, service_info in services.items():
                service_name = service_info['name']
                
                if service_name in vulnerability_db:
                    vuln_info = vulnerability_db[service_name]
                    
                    for vuln in vuln_info['common_vulns']:
                        potential_vulns.append({
                            'container_id': container_id,
                            'port': port,
                            'service': service_name,
                            'vulnerability': vuln,
                            'severity': self._get_vulnerability_severity(vuln),
                            'default_credentials': vuln_info.get('default_creds', [])
                        })
                
                # Check for known vulnerable versions
                version = service_info.get('version', 'Unknown')
                if version != 'Unknown':
                    version_vulns = self._check_version_vulnerabilities(service_name, version)
                    potential_vulns.extend(version_vulns)
        
        results['technical_details']['potential_vulnerabilities'] = potential_vulns
        
        if potential_vulns:
            results['vulnerabilities_exploited'] = [
                {
                    'type': vuln['vulnerability'],
                    'component': vuln['container_id'],
                    'service': f"{vuln['service']}:{vuln['port']}",
                    'severity': vuln['severity']
                } for vuln in potential_vulns
            ]
            
            results['attack_timeline'].append({
                'timestamp': time.time(),
                'action': 'vulnerability_assessment',
                'result': 'success',
                'vulnerabilities_found': len(potential_vulns)
            })
        
        return results
    
    def _get_vulnerability_severity(self, vulnerability: str) -> str:
        """Determine severity level of vulnerability"""
        high_severity = [
            'sql_injection',
            'privilege_escalation', 
            'plaintext_transmission',
            'anonymous_access'
        ]
        
        medium_severity = [
            'weak_authentication',
            'default_credentials',
            'information_disclosure'
        ]
        
        if vulnerability in high_severity:
            return 'high'
        elif vulnerability in medium_severity:
            return 'medium'
        else:
            return 'low'
    
    def _check_version_vulnerabilities(self, service_name: str, version: str) -> List[Dict]:
        """Check for known vulnerabilities in specific service versions"""
        # Simplified vulnerability database
        # In real implementation, this would query CVE databases
        
        known_vulns = {
            'Apache': {
                '2.4.0': ['CVE-2017-15710', 'CVE-2017-15715'],
                '2.2.0': ['CVE-2017-9798', 'CVE-2017-7679']
            },
            'nginx': {
                '1.18.0': ['CVE-2021-23017'],
                '1.16.0': ['CVE-2019-20372']
            },
            'MySQL': {
                '5.7.0': ['CVE-2019-2805', 'CVE-2019-2740'],
                '8.0.0': ['CVE-2020-14765', 'CVE-2020-14776']
            },
            'OpenSSH': {
                '7.4': ['CVE-2018-15473'],
                '6.6': ['CVE-2016-0777', 'CVE-2016-0778']
            }
        }
        
        vulnerabilities = []
        
        if service_name in known_vulns:
            for vuln_version, cves in known_vulns[service_name].items():
                if version.startswith(vuln_version):
                    for cve in cves:
                        vulnerabilities.append({
                            'service': service_name,
                            'version': version,
                            'vulnerability': f'known_cve_{cve}',
                            'cve_id': cve,
                            'severity': 'high'
                        })
        
        return vulnerabilities

# Attack module interface
async def execute_attack(environment: Dict, target_components: List[str], orchestrator) -> Dict:
    """Main entry point for port scanning attack"""
    attack = PortScanAttack()
    return await attack.execute_attack(environment, target_components, orchestrator)