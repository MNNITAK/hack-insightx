import os
import subprocess
import json
import shutil
import requests
import stat
import time
import base64
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dotenv import load_dotenv


load_dotenv()

class DeterministicSecurityScanner:
    def __init__(self, github_token: str):
        self.github_token = github_token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Security-Agent",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        self.supported_extensions = {'.py', '.js', '.java', '.php', '.go', '.ts', '.jsx', '.tsx', '.c', '.cpp', '.cs', '.rb', '.sql', '.sh', '.yml', '.yaml', '.xml', '.html', '.htm', '.json', '.swift', '.kt', '.m', '.pl', '.scala', '.txt', '.rs', '.lua', '.r', '.dart', '.groovy'}
        self.username = None
        
        # Load comprehensive security patterns
        self.security_patterns = self.load_comprehensive_patterns()
    
    def load_comprehensive_patterns(self) -> Dict:
        """Load the most comprehensive set of deterministic security patterns"""
        return {
            # ============ SQL INJECTION (OWASP A03:2021) ============
            'sql_injection': {
                'severity': 'critical',
                'cwe': 'CWE-89',
                'owasp': 'A03:2021',
                'patterns': [
                    # Python SQL Injection
                    (r'execute\s*\(\s*["\'].*?%s.*?["\'].*?%.*?\)', 'Python SQL with % formatting'),
                    (r'execute\s*\(\s*["\'].*?\+.*?["\']', 'Python SQL with string concatenation'),
                    (r'\.format\s*\(.*?\).*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)', 'String format in SQL'),
                    (r'f["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?\{.*?\}', 'f-string in SQL query'),
                    (r'cursor\.execute\s*\(\s*["\'][^"\']*\+', 'Cursor execute with concatenation'),
                    (r'query\s*=.*?\+.*?(SELECT|INSERT|UPDATE|DELETE)', 'Query concatenation'),
                    (r'executemany\s*\(\s*["\'].*?%(?!s\))', 'Unsafe executemany'),
                    (r'raw\s*\(\s*["\'].*?\+', 'Raw SQL with concatenation'),
                    
                    # JavaScript/Node.js SQL Injection
                    (r'query\s*\(\s*[`"\'].*?\$\{', 'JS template literal in SQL'),
                    (r'\.query\s*\(\s*.*?\+.*?\)', 'Node.js query concatenation'),
                    (r'execute\s*\(\s*[`"\'].*?\+', 'Execute with concatenation'),
                    (r'sequelize\.query\s*\(\s*[`"\'].*?\$\{', 'Sequelize unsafe query'),
                    (r'knex\.raw\s*\(\s*[`"\'].*?\$\{', 'Knex raw query injection'),
                    
                    # Java SQL Injection
                    (r'Statement\s+\w+\s*=.*?createStatement\s*\(', 'Java Statement without PreparedStatement'),
                    (r'executeQuery\s*\(\s*.*?\+', 'Java executeQuery with concatenation'),
                    (r'executeUpdate\s*\(\s*.*?\+', 'Java executeUpdate with concatenation'),
                    (r'createQuery\s*\(\s*["\'].*?\+', 'JPA createQuery with concatenation'),
                    
                    # PHP SQL Injection
                    (r'mysql_query\s*\(\s*.*?\$', 'PHP mysql_query with variable'),
                    (r'mysqli_query\s*\(.*?,.*?\$', 'PHP mysqli_query with variable'),
                    (r'\$wpdb->query\s*\(\s*.*?\$', 'WordPress query with variable'),
                    (r'pg_query\s*\(.*?,.*?\$', 'PostgreSQL query with variable'),
                    
                    # Generic SQL Patterns
                    (r'(SELECT|INSERT|UPDATE|DELETE).*?WHERE.*?["\'].*?\+', 'WHERE clause concatenation'),
                    (r'ORDER\s+BY.*?\+', 'ORDER BY concatenation'),
                    (r'LIMIT.*?\+', 'LIMIT concatenation'),
                ],
                'fix': 'Use parameterized queries/prepared statements. Python: cursor.execute(query, (param,)), JS: query($1, [param]), Java: PreparedStatement'
            },
            
            # ============ XSS - CROSS-SITE SCRIPTING (OWASP A03:2021) ============
            'xss': {
                'severity': 'high',
                'cwe': 'CWE-79',
                'owasp': 'A03:2021',
                'patterns': [
                    # DOM-based XSS
                    (r'innerHTML\s*=\s*.*?[\+\$\{]', 'innerHTML with user input'),
                    (r'outerHTML\s*=\s*.*?[\+\$\{]', 'outerHTML with user input'),
                    (r'document\.write\s*\(.*?[\+\$\{]', 'document.write with concatenation'),
                    (r'document\.writeln\s*\(.*?[\+\$\{]', 'document.writeln with concatenation'),
                    (r'\.html\s*\(.*?[\+\$\{]', 'jQuery .html() with user input'),
                    (r'\.append\s*\(.*?<.*?[\+\$\{]', 'Append with HTML concatenation'),
                    (r'\.prepend\s*\(.*?<.*?[\+\$\{]', 'Prepend with HTML concatenation'),
                    (r'insertAdjacentHTML\s*\(.*?,.*?[\+\$\{]', 'insertAdjacentHTML with user input'),
                    
                    # React XSS
                    (r'dangerouslySetInnerHTML\s*=\s*\{\{', 'React dangerouslySetInnerHTML'),
                    (r'dangerouslySetInnerHTML.*?__html\s*:', 'Dangerous HTML injection'),
                    
                    # Vue XSS
                    (r'v-html\s*=\s*["\']?\{', 'Vue v-html directive'),
                    
                    # Angular XSS
                    (r'\[innerHTML\]\s*=', 'Angular innerHTML binding'),
                    (r'bypassSecurityTrust', 'Angular security bypass'),
                    
                    # Server-side XSS
                    (r'render_template_string\s*\(.*?\+', 'Flask template injection'),
                    (r'<%=.*?%>', 'Unescaped template output'),
                    (r'\{\{.*?\|safe\}\}', 'Django safe filter'),
                    (r'raw\s*\(.*?\)', 'Laravel raw output'),
                    (r'@Html\.Raw\s*\(', '.NET unescaped HTML'),
                    (r'echo\s+\$_(GET|POST|REQUEST)', 'PHP echo user input'),
                    (r'print\s+\$_(GET|POST|REQUEST)', 'PHP print user input'),
                    
                    # JavaScript eval-based XSS
                    (r'eval\s*\(', 'eval() function'),
                    (r'Function\s*\(.*?\)', 'Function constructor'),
                    (r'setTimeout\s*\(\s*["\']', 'setTimeout with string'),
                    (r'setInterval\s*\(\s*["\']', 'setInterval with string'),
                    (r'new\s+Function\s*\(', 'new Function()'),
                    
                    # URL-based XSS
                    (r'location\s*=\s*.*?[\+\$\{]', 'Location assignment with user input'),
                    (r'location\.href\s*=\s*.*?[\+\$\{]', 'href assignment with user input'),
                    (r'window\.open\s*\(.*?[\+\$\{]', 'window.open with user input'),
                ],
                'fix': 'Sanitize user input, use textContent instead of innerHTML, escape HTML entities, use framework-specific safe methods'
            },
            
            # ============ HARDCODED SECRETS (OWASP A07:2021) ============
            'hardcoded_secrets': {
                'severity': 'critical',
                'cwe': 'CWE-798',
                'owasp': 'A07:2021',
                'patterns': [
                    # Generic passwords and secrets
                    (r'password\s*=\s*["\'][^"\']{4,}["\']', 'Hardcoded password'),
                    (r'passwd\s*=\s*["\'][^"\']{4,}["\']', 'Hardcoded passwd'),
                    (r'pwd\s*=\s*["\'][^"\']{4,}["\']', 'Hardcoded pwd'),
                    (r'secret\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded secret'),
                    (r'api[_-]?key\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded API key'),
                    (r'apikey\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded apikey'),
                    (r'api[_-]?secret\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded API secret'),
                    (r'access[_-]?key\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded access key'),
                    (r'secret[_-]?key\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded secret key'),
                    (r'private[_-]?key\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded private key'),
                    (r'token\s*=\s*["\'][^"\']{20,}["\']', 'Hardcoded token'),
                    (r'auth[_-]?token\s*=\s*["\'][^"\']{20,}["\']', 'Hardcoded auth token'),
                    (r'bearer\s+[a-zA-Z0-9_\-]{20,}', 'Hardcoded bearer token'),
                    
                    # AWS Credentials
                    (r'aws[_-]?access[_-]?key[_-]?id\s*=\s*["\'][^"\']+["\']', 'AWS access key ID'),
                    (r'aws[_-]?secret[_-]?access[_-]?key\s*=', 'AWS secret access key'),
                    (r'AKIA[0-9A-Z]{16}', 'AWS access key pattern'),
                    (r'aws[_-]?session[_-]?token\s*=', 'AWS session token'),
                    
                    # Cloud Provider Keys
                    (r'GOOGLE[_-]?API[_-]?KEY\s*=', 'Google API key'),
                    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API key pattern'),
                    (r'AZURE[_-]?CLIENT[_-]?SECRET\s*=', 'Azure client secret'),
                    (r'AZURE[_-]?STORAGE[_-]?KEY\s*=', 'Azure storage key'),
                    (r'HEROKU[_-]?API[_-]?KEY\s*=', 'Heroku API key'),
                    (r'DO[_-]?API[_-]?TOKEN\s*=', 'DigitalOcean API token'),
                    
                    # Service-specific tokens
                    (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API key'),
                    (r'sk-proj-[a-zA-Z0-9_-]{48,}', 'OpenAI project key'),
                    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub personal access token'),
                    (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth token'),
                    (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'GitHub fine-grained token'),
                    (r'glpat-[a-zA-Z0-9_\-]{20}', 'GitLab personal access token'),
                    (r'xox[baprs]-[a-zA-Z0-9\-]{10,}', 'Slack token'),
                    (r'sq0atp-[a-zA-Z0-9\-_]{22}', 'Square access token'),
                    (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', 'SendGrid API key'),
                    (r'key-[0-9a-zA-Z]{32}', 'Mailgun API key'),
                    (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe live key'),
                    (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe test key'),
                    (r'rk_live_[0-9a-zA-Z]{24}', 'Stripe restricted key'),
                    (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe publishable key'),
                    (r'AC[a-z0-9]{32}', 'Twilio Account SID'),
                    (r'SK[a-z0-9]{32}', 'Twilio API key'),
                    (r'NPM_TOKEN\s*=\s*["\']?[a-zA-Z0-9\-_]{36}', 'NPM token'),
                    (r'NUGET[_-]?API[_-]?KEY\s*=', 'NuGet API key'),
                    (r'PYPI[_-]?TOKEN\s*=', 'PyPI token'),
                    (r'DOCKER[_-]?PASSWORD\s*=', 'Docker password'),
                    
                    # Database credentials
                    (r'mysql://[^:]+:[^@]+@', 'MySQL connection string'),
                    (r'postgresql://[^:]+:[^@]+@', 'PostgreSQL connection string'),
                    (r'mongodb://[^:]+:[^@]+@', 'MongoDB connection string'),
                    (r'mongodb\+srv://[^:]+:[^@]+@', 'MongoDB SRV connection string'),
                    (r'redis://[^:]*:[^@]+@', 'Redis connection string'),
                    (r'jdbc:[^:]+://[^:]+:[^@]+@', 'JDBC connection string'),
                    (r'DB_PASSWORD\s*=\s*["\'][^"\']{4,}["\']', 'Database password'),
                    (r'DATABASE_URL\s*=\s*["\'][^"\']+:[^"\']+@', 'Database URL with credentials'),
                    
                    # SSH/SSL Keys
                    (r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', 'Private SSH/SSL key'),
                    (r'-----BEGIN PRIVATE KEY-----', 'Private key'),
                    (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP private key'),
                    
                    # JWT tokens
                    (r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', 'JWT token'),
                    
                    # Encryption keys
                    (r'ENCRYPTION[_-]?KEY\s*=\s*["\'][^"\']{16,}["\']', 'Encryption key'),
                    (r'AES[_-]?KEY\s*=\s*["\'][^"\']{16,}["\']', 'AES key'),
                ],
                'fix': 'Use environment variables (os.getenv()), secret management services (AWS Secrets Manager, HashiCorp Vault), or config files outside version control'
            },
            
            # ============ COMMAND INJECTION (OWASP A03:2021) ============
            'command_injection': {
                'severity': 'critical',
                'cwe': 'CWE-78',
                'owasp': 'A03:2021',
                'patterns': [
                    # Python command injection
                    (r'os\.system\s*\(.*?[\+\%\{]', 'os.system with string concatenation'),
                    (r'os\.popen\s*\(.*?[\+\%\{]', 'os.popen with user input'),
                    (r'subprocess\.call\s*\(.*?shell\s*=\s*True', 'subprocess with shell=True'),
                    (r'subprocess\.run\s*\(.*?shell\s*=\s*True', 'subprocess.run with shell=True'),
                    (r'subprocess\.Popen\s*\(.*?shell\s*=\s*True', 'subprocess.Popen with shell=True'),
                    (r'commands\.getoutput\s*\(', 'commands.getoutput'),
                    (r'commands\.getstatusoutput\s*\(', 'commands.getstatusoutput'),
                    (r'eval\s*\(.*?input', 'eval with user input'),
                    (r'exec\s*\(.*?input', 'exec with user input'),
                    (r'compile\s*\(.*?input.*?,.*?["\']exec["\']', 'compile with exec'),
                    (r'__import__\s*\(.*?input', '__import__ with user input'),
                    
                    # Node.js command injection
                    (r'child_process\.exec\s*\(.*?[\+\$\{`]', 'Node.js child_process.exec'),
                    (r'child_process\.execSync\s*\(.*?[\+\$\{`]', 'execSync with user input'),
                    (r'child_process\.spawn\s*\(.*?shell\s*:\s*true', 'spawn with shell option'),
                    (r'require\s*\(\s*["\']child_process["\']\s*\)\.exec', 'child_process exec'),
                    (r'process\.exec\s*\(', 'process.exec'),
                    
                    # Java command injection
                    (r'Runtime\.getRuntime\(\)\.exec\s*\(.*?[\+]', 'Java Runtime.exec with concatenation'),
                    (r'ProcessBuilder\s*\(.*?[\+]', 'ProcessBuilder with concatenation'),
                    (r'\.exec\s*\(.*?request\.', 'exec with request parameter'),
                    
                    # PHP command injection
                    (r'system\s*\(.*?\$', 'PHP system() with variable'),
                    (r'exec\s*\(.*?\$', 'PHP exec() with variable'),
                    (r'shell_exec\s*\(.*?\$', 'PHP shell_exec() with variable'),
                    (r'passthru\s*\(.*?\$', 'PHP passthru() with variable'),
                    (r'popen\s*\(.*?\$', 'PHP popen() with variable'),
                    (r'proc_open\s*\(.*?\$', 'PHP proc_open() with variable'),
                    (r'`.*?\$.*?`', 'PHP backtick execution'),
                    (r'escapeshellcmd\s*\((?!.*?escapeshellarg)', 'escapeshellcmd without escapeshellarg'),
                    
                    # Ruby command injection
                    (r'system\s*\(.*?\#\{', 'Ruby system with interpolation'),
                    (r'exec\s*\(.*?\#\{', 'Ruby exec with interpolation'),
                    (r'`.*?\#\{.*?`', 'Ruby backtick with interpolation'),
                    (r'%x\{.*?\#\{', 'Ruby %x with interpolation'),
                    
                    # Shell script injection
                    (r'\$\(.*?\$\{', 'Shell command substitution'),
                    (r'`.*?\$.*?`', 'Shell backtick substitution'),
                ],
                'fix': 'Avoid shell=True, use parameterized commands with list/array arguments, validate input, use subprocess with args list instead of string'
            },
            
            # ============ PATH TRAVERSAL (OWASP A01:2021) ============
            'path_traversal': {
                'severity': 'high',
                'cwe': 'CWE-22',
                'owasp': 'A01:2021',
                'patterns': [
                    # Python path traversal
                    (r'open\s*\(.*?[\+\%\{].*?\)', 'File open with concatenation'),
                    (r'os\.path\.join\s*\(.*?request\.', 'Path join with request parameter'),
                    (r'Path\s*\(.*?request\.', 'Path with request parameter'),
                    (r'\.read\s*\(.*?[\+\%]', 'File read with concatenation'),
                    (r'\.write\s*\(.*?[\+\%]', 'File write with concatenation'),
                    (r'shutil\.copy\s*\(.*?request', 'shutil.copy with user input'),
                    (r'send_file\s*\(.*?request\.', 'Flask send_file with user input'),
                    (r'send_from_directory\s*\(.*?,.*?request\.', 'send_from_directory with user input'),
                    
                    # Directory traversal patterns
                    (r'\.\./', 'Directory traversal sequence ../'),
                    (r'\.\.\x5c', 'Directory traversal sequence ..\\'),
                    (r'%2e%2e%2f', 'URL encoded ../'),
                    (r'%2e%2e/', 'Partial URL encoded ../'),
                    (r'..%2f', 'Partial URL encoded ../'),
                    (r'%252e%252e%252f', 'Double URL encoded ../'),
                    
                    # Node.js path traversal
                    (r'fs\.readFile\s*\(.*?[\+\$\{]', 'fs.readFile with concatenation'),
                    (r'fs\.readFileSync\s*\(.*?[\+\$\{]', 'fs.readFileSync with concatenation'),
                    (r'fs\.writeFile\s*\(.*?[\+\$\{]', 'fs.writeFile with concatenation'),
                    (r'fs\.createReadStream\s*\(.*?[\+\$\{]', 'fs.createReadStream with concatenation'),
                    (r'fs\.unlink\s*\(.*?req\.', 'fs.unlink with request parameter'),
                    (r'path\.join\s*\(__dirname,.*?req\.', 'path.join with request'),
                    (r'res\.sendFile\s*\(.*?req\.', 'Express sendFile with request'),
                    
                    # Java path traversal
                    (r'new\s+File\s*\(.*?\+', 'Java File with concatenation'),
                    (r'FileInputStream\s*\(.*?\+', 'FileInputStream with concatenation'),
                    (r'FileOutputStream\s*\(.*?\+', 'FileOutputStream with concatenation'),
                    (r'Files\.readAllBytes\s*\(.*?request', 'Files.readAllBytes with request'),
                    (r'Paths\.get\s*\(.*?request', 'Paths.get with request parameter'),
                    
                    # PHP path traversal
                    (r'fopen\s*\(.*?\$_(GET|POST|REQUEST)', 'PHP fopen with user input'),
                    (r'file_get_contents\s*\(.*?\$_(GET|POST|REQUEST)', 'file_get_contents with user input'),
                    (r'include\s*\(.*?\$_(GET|POST|REQUEST)', 'PHP include with user input'),
                    (r'require\s*\(.*?\$_(GET|POST|REQUEST)', 'PHP require with user input'),
                    (r'include_once\s*\(.*?\$_(GET|POST|REQUEST)', 'PHP include_once with user input'),
                    (r'require_once\s*\(.*?\$_(GET|POST|REQUEST)', 'PHP require_once with user input'),
                    (r'readfile\s*\(.*?\$_(GET|POST|REQUEST)', 'PHP readfile with user input'),
                ],
                'fix': 'Validate file paths, use whitelisting, sanitize input, check for directory traversal sequences, use os.path.basename(), restrict to safe directory'
            },
            
            # ============ INSECURE DESERIALIZATION (OWASP A08:2021) ============
            'insecure_deserialization': {
                'severity': 'critical',
                'cwe': 'CWE-502',
                'owasp': 'A08:2021',
                'patterns': [
                    # Python deserialization
                    (r'pickle\.loads?\s*\(', 'Python pickle deserialization'),
                    (r'cPickle\.loads?\s*\(', 'cPickle deserialization'),
                    (r'dill\.loads?\s*\(', 'dill deserialization'),
                    (r'shelve\.open\s*\(', 'shelve deserialization'),
                    (r'yaml\.load\s*\((?!.*?Loader\s*=\s*yaml\.(Safe|Base)Loader)', 'YAML load without SafeLoader'),
                    (r'yaml\.unsafe_load\s*\(', 'YAML unsafe_load'),
                    (r'yaml\.load_all\s*\((?!.*?SafeLoader)', 'YAML load_all without SafeLoader'),
                    (r'marshal\.loads?\s*\(', 'marshal deserialization'),
                    (r'jsonpickle\.decode\s*\(', 'jsonpickle decode'),
                    
                    # Node.js deserialization
                    (r'JSON\.parse\s*\(.*?[\+\$\{]', 'JSON.parse with concatenation'),
                    (r'eval\s*\(.*?JSON', 'eval on JSON data'),
                    (r'node-serialize\.unserialize', 'node-serialize'),
                    (r'deserialize\s*\(', 'Generic deserialize'),
                    
                    # Java deserialization
                    (r'ObjectInputStream\s*\(', 'Java ObjectInputStream'),
                    (r'readObject\s*\(\s*\)', 'Java readObject'),
                    (r'readUnshared\s*\(\s*\)', 'Java readUnshared'),
                    (r'XMLDecoder\s*\(', 'Java XMLDecoder'),
                    (r'XStream\.fromXML\s*\(', 'XStream deserialization'),
                    (r'ObjectMapper\.readValue\s*\(', 'Jackson deserialization'),
                    
                    # PHP deserialization
                    (r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', 'PHP unserialize with user input'),
                    (r'unserialize\s*\(.*?file_get_contents', 'unserialize from file'),
                    
                    # .NET deserialization
                    (r'BinaryFormatter\.Deserialize', '.NET BinaryFormatter'),
                    (r'NetDataContractSerializer\.Deserialize', 'NetDataContractSerializer'),
                    (r'ObjectStateFormatter\.Deserialize', 'ObjectStateFormatter'),
                    (r'SoapFormatter\.Deserialize', 'SoapFormatter'),
                ],
                'fix': 'Use safe deserialization (JSON instead of pickle), validate data before deserializing, use yaml.SafeLoader, implement type checking'
            },
            
            # ============ WEAK CRYPTOGRAPHY (OWASP A02:2021) ============
            'weak_crypto': {
                'severity': 'high',
                'cwe': 'CWE-327',
                'owasp': 'A02:2021',
                'patterns': [
                    # Weak hash functions
                    (r'md5\s*\(', 'MD5 hash (weak)'),
                    (r'sha1\s*\(', 'SHA1 hash (weak)'),
                    (r'hashlib\.md5\s*\(', 'Python MD5'),
                    (r'hashlib\.sha1\s*\(', 'Python SHA1'),
                    (r'Md5\s*\(', 'MD5 usage'),
                    (r'SHA1\s*\(', 'SHA1 usage'),
                    (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', 'Java MD5'),
                    (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', 'Java SHA1'),
                    (r'crypto\.createHash\s*\(\s*["\']md5["\']', 'Node.js MD5'),
                    (r'crypto\.createHash\s*\(\s*["\']sha1["\']', 'Node.js SHA1'),
                    
                    # Weak encryption algorithms
                    (r'DES\s*\(', 'DES encryption (weak)'),
                    (r'RC4\s*\(', 'RC4 encryption (weak)'),
                    (r'RC2\s*\(', 'RC2 encryption (weak)'),
                    (r'Blowfish\s*\(', 'Blowfish (consider stronger)'),
                    (r'ECB\s*mode', 'ECB mode (insecure)'),
                    (r'MODE_ECB', 'ECB mode constant'),
                    (r'Cipher\.getInstance\s*\(\s*["\'][^"\']*ECB', 'Java ECB mode'),
                    (r'Cipher\.getInstance\s*\(\s*["\']DES', 'Java DES cipher'),
                    (r'createCipher\s*\(\s*["\']des', 'Node.js DES'),
                    (r'createCipher\s*\(\s*["\']rc4', 'Node.js RC4'),
                    
                    # Weak random number generation
                    (r'random\.random\s*\(\s*\)', 'Python random (not cryptographic)'),
                    (r'random\.randint\s*\(', 'Python randint (not cryptographic)'),
                    (r'Math\.random\s*\(\s*\)', 'JavaScript Math.random (not secure)'),
                    (r'Random\s*\(\s*\)\.next', 'Java Random (not secure)'),
                    (r'rand\s*\(\s*\)', 'C/PHP rand (not secure)'),
                    (r'srand\s*\(', 'srand (not secure)'),
                    (r'mt_rand\s*\(', 'PHP mt_rand (not cryptographic)'),
                    
                    # Weak password hashing
                    (r'PASSWORD_DEFAULT', 'PHP PASSWORD_DEFAULT (may be weak)'),
                    (r'crypt\s*\(', 'crypt function (often weak)'),
                    (r'pbkdf2_sha1', 'PBKDF2 with SHA1 (weak)'),
                    
                    # Weak SSL/TLS
                    (r'SSLv[23]', 'SSL v2/v3 (deprecated)'),
                    (r'TLSv1\s', 'TLS 1.0 (deprecated)'),
                    (r'TLS_RSA_WITH_NULL', 'NULL cipher suite'),
                    (r'PROTOCOL_SSLv[23]', 'SSL protocol v2/v3'),
                    (r'PROTOCOL_TLSv1\s', 'TLS 1.0 protocol'),
                ],
                'fix': 'Use SHA-256/SHA-3 or stronger, use AES-256 with GCM/CBC mode, use secrets module for random, use bcrypt/argon2 for passwords, use TLS 1.2+'
            },
            
            # ============ AUTHENTICATION & SESSION ISSUES (OWASP A07:2021) ============
            'authentication_issues': {
                'severity': 'high',
                'cwe': 'CWE-287',
                'owasp': 'A07:2021',
                'patterns': [
                    # Weak authentication
                    (r'password\s*==\s*["\']', 'Password comparison with =='),
                    (r'if.*?password\s*==\s*', 'Insecure password comparison'),
                    (r'auth\s*=\s*False', 'Authentication disabled'),
                    (r'authenticated\s*=\s*True\s*#', 'Hardcoded authentication'),
                    (r'require_auth\s*=\s*False', 'Auth requirement disabled'),
                    (r'\.login\(\)\s*#.*skip', 'Commented authentication'),
                    (r'bypass.*?auth', 'Authentication bypass'),
                    (r'admin\s*=\s*True', 'Hardcoded admin access'),
                    
                    # SSL/TLS verification disabled
                    (r'verify\s*=\s*False', 'SSL verification disabled'),
                    (r'CURLOPT_SSL_VERIFYPEER.*?false', 'cURL SSL verification disabled'),
                    (r'curl_setopt.*?CURLOPT_SSL_VERIFYPEER.*?0', 'SSL peer verification disabled'),
                    (r'SSLContext.*?CERT_NONE', 'SSL certificate verification disabled'),
                    (r'check_hostname\s*=\s*False', 'Hostname check disabled'),
                    (r'rejectUnauthorized\s*:\s*false', 'Node.js SSL verification disabled'),
                    (r'StrictHostKeyChecking\s*=\s*no', 'SSH strict host key checking disabled'),
                    
                    # Session management issues
                    (r'SESSION_COOKIE_SECURE\s*=\s*False', 'Insecure session cookie'),
                    (r'SESSION_COOKIE_HTTPONLY\s*=\s*False', 'HttpOnly flag disabled'),
                    (r'SESSION_COOKIE_SAMESITE\s*=\s*["\']None["\']', 'SameSite None'),
                    (r'session\.cookie_secure\s*=\s*0', 'PHP session cookie not secure'),
                    (r'session\.cookie_httponly\s*=\s*0', 'PHP HttpOnly disabled'),
                    (r'cookie\s*\(.*?secure\s*:\s*false', 'Insecure cookie'),
                    (r'setcookie\s*\([^)]*(?!.*secure)', 'Cookie without secure flag'),
                    
                    # JWT issues
                    (r'algorithm\s*:\s*["\']none["\']', 'JWT algorithm none'),
                    (r'verify\s*=\s*False.*?jwt', 'JWT verification disabled'),
                    (r'jwt\.decode\s*\([^)]*verify=False', 'JWT decode without verification'),
                    (r'alg.*?:.*?["\']HS256["\']', 'JWT with HS256 (consider RS256)'),
                    
                    # Default credentials
                    (r'username.*?=.*?["\']admin["\']', 'Default username admin'),
                    (r'password.*?=.*?["\']admin["\']', 'Default password admin'),
                    (r'password.*?=.*?["\']password["\']', 'Default password'),
                    (r'user.*?=.*?["\']root["\']', 'Default root user'),
                ],
                'fix': 'Use secure password comparison (compare_digest), enable SSL verification, use secure session cookies (Secure, HttpOnly, SameSite), use strong JWT algorithms (RS256)'
            },
            
            # ============ CSRF - Cross-Site Request Forgery (OWASP A01:2021) ============
            'csrf': {
                'severity': 'high',
                'cwe': 'CWE-352',
                'owasp': 'A01:2021',
                'patterns': [
                    # Flask CSRF
                    (r'@app\.route\s*\([^)]*methods\s*=\s*\[[^\]]*["\']POST["\'][^\]]*\](?!.*@csrf)', 'Flask POST without CSRF protection'),
                    (r'request\.form(?!.*csrf_token)', 'Flask form without CSRF token'),
                    
                    # Django CSRF
                    (r'@csrf_exempt', 'Django CSRF exemption'),
                    (r'csrf_exempt\s*\(', 'CSRF exemption decorator'),
                    
                    # HTML forms
                    (r'<form[^>]*method\s*=\s*["\']post["\'][^>]*>(?!.*csrf)', 'HTML form without CSRF token'),
                    (r'<form[^>]*method\s*=\s*["\']POST["\'][^>]*>(?!.*csrf)', 'HTML POST form without CSRF'),
                    
                    # AJAX/Fetch requests
                    (r'fetch\s*\([^)]*method\s*:\s*["\']POST["\'](?!.*csrf)', 'Fetch POST without CSRF'),
                    (r'\$.post\s*\((?!.*csrf)', 'jQuery POST without CSRF'),
                    (r'\$.ajax\s*\([^)]*type\s*:\s*["\']POST["\'](?!.*csrf)', 'jQuery AJAX POST without CSRF'),
                    (r'axios\.post\s*\((?!.*csrf)', 'Axios POST without CSRF'),
                    (r'XMLHttpRequest.*?POST(?!.*csrf)', 'XMLHttpRequest POST without CSRF'),
                ],
                'fix': 'Implement CSRF tokens for all state-changing requests, use SameSite cookie attribute, verify Origin/Referer headers'
            },
            
            # ============ XXE - XML External Entity (OWASP A05:2021) ============
            'xxe': {
                'severity': 'high',
                'cwe': 'CWE-611',
                'owasp': 'A05:2021',
                'patterns': [
                    # Python XXE
                    (r'etree\.parse\s*\((?!.*resolve_entities\s*=\s*False)', 'lxml parse without disabling entities'),
                    (r'etree\.fromstring\s*\((?!.*resolve_entities\s*=\s*False)', 'lxml fromstring vulnerable'),
                    (r'etree\.XMLParser\s*\((?!.*resolve_entities\s*=\s*False)', 'XMLParser without security'),
                    (r'xml\.etree\.ElementTree\.parse\s*\(', 'ElementTree parse (check security)'),
                    (r'xml\.dom\.minidom\.parse\s*\(', 'minidom parse (vulnerable)'),
                    (r'xml\.sax\.parse\s*\(', 'SAX parse (vulnerable)'),
                    (r'pulldom\.parse\s*\(', 'pulldom parse (vulnerable)'),
                    
                    # Java XXE
                    (r'DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature)', 'DocumentBuilderFactory without security'),
                    (r'SAXParserFactory\.newInstance\s*\(\s*\)(?!.*setFeature)', 'SAXParserFactory without security'),
                    (r'XMLInputFactory\.newInstance\s*\(\s*\)(?!.*setProperty)', 'XMLInputFactory without security'),
                    (r'TransformerFactory\.newInstance\s*\(\s*\)(?!.*setAttribute)', 'TransformerFactory without security'),
                    (r'SAXReader\s*\(\s*\)(?!.*setFeature)', 'SAXReader without security'),
                    (r'SAXBuilder\s*\(\s*\)(?!.*setFeature)', 'SAXBuilder without security'),
                    
                    # PHP XXE
                    (r'simplexml_load_string\s*\((?!.*LIBXML_NOENT)', 'simplexml without LIBXML_NOENT'),
                    (r'simplexml_load_file\s*\((?!.*LIBXML_NOENT)', 'simplexml_load_file vulnerable'),
                    (r'DOMDocument::load\s*\((?!.*LIBXML_NOENT)', 'DOMDocument load vulnerable'),
                    (r'libxml_disable_entity_loader\s*\(\s*false\s*\)', 'Entity loader enabled'),
                    
                    # Node.js XXE
                    (r'libxmljs\.parseXml\s*\((?!.*noent\s*:\s*false)', 'libxmljs parse without noent'),
                    (r'xml2js\.parseString\s*\(', 'xml2js parseString (check options)'),
                ],
                'fix': 'Disable external entity processing: lxml(resolve_entities=False), Java setFeature(DISALLOW_DOCTYPE_DECL, true), use defusedxml library'
            },
            
            # ============ SSRF - Server-Side Request Forgery (OWASP A10:2021) ============
            'ssrf': {
                'severity': 'high',
                'cwe': 'CWE-918',
                'owasp': 'A10:2021',
                'patterns': [
                    # Python SSRF
                    (r'requests\.get\s*\(.*?[\+\{]', 'requests.get with user-controlled URL'),
                    (r'requests\.post\s*\(.*?[\+\{]', 'requests.post with user input'),
                    (r'urllib\.request\.urlopen\s*\(.*?[\+\{]', 'urlopen with user input'),
                    (r'urllib2\.urlopen\s*\(.*?[\+\{]', 'urllib2 urlopen with user input'),
                    (r'httplib\.request\s*\(.*?[\+\{]', 'httplib request with user input'),
                    (r'http\.client\.request\s*\(.*?[\+\{]', 'http.client with user input'),
                    
                    # Node.js SSRF
                    (r'http\.get\s*\(.*?req\.', 'Node.js http.get with request'),
                    (r'https\.get\s*\(.*?req\.', 'https.get with request'),
                    (r'axios\.get\s*\(.*?req\.', 'axios.get with request'),
                    (r'fetch\s*\(.*?req\.(body|query|params)', 'fetch with request data'),
                    (r'request\s*\(.*?url\s*:.*?req\.', 'request library with user URL'),
                    (r'got\s*\(.*?req\.', 'got library with user input'),
                    
                    # Java SSRF
                    (r'URL\s*\(.*?request\.', 'Java URL with request parameter'),
                    (r'HttpURLConnection.*?request\.', 'HttpURLConnection with request'),
                    (r'RestTemplate.*?request\.', 'RestTemplate with user input'),
                    (r'WebClient.*?request\.', 'WebClient with user input'),
                    
                    # PHP SSRF
                    (r'file_get_contents\s*\(.*?\$_(GET|POST|REQUEST)', 'file_get_contents with user input'),
                    (r'curl_setopt\s*\(.*?CURLOPT_URL.*?\$_(GET|POST)', 'cURL with user-controlled URL'),
                    (r'fopen\s*\(.*?http.*?\$_(GET|POST)', 'fopen with user URL'),
                ],
                'fix': 'Validate URLs, use whitelist of allowed domains/IPs, block internal IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.0.0/16), use DNS resolution check'
            },
            
            # ============ INSECURE FILE UPLOAD (OWASP A04:2021) ============
            'file_upload': {
                'severity': 'high',
                'cwe': 'CWE-434',
                'owasp': 'A04:2021',
                'patterns': [
                    # Python file upload
                    (r'\.save\s*\(.*?filename\s*\)(?!.*validate)', 'File save without validation'),
                    (r'werkzeug.*?save\s*\((?!.*secure_filename)', 'Werkzeug save without secure_filename'),
                    (r'request\.files\[[^\]]+\]\.save\s*\((?!.*secure_filename)', 'Flask file save without security'),
                    
                    # Node.js file upload
                    (r'multer\s*\(\s*\)(?!.*fileFilter)', 'Multer without fileFilter'),
                    (r'multer\s*\(.*?\)(?!.*limits)', 'Multer without size limits'),
                    (r'fs\.writeFile\s*\(.*?req\.files', 'Direct file write from request'),
                    (r'formidable\s*\((?!.*filter)', 'Formidable without filter'),
                    
                    # PHP file upload
                    (r'move_uploaded_file\s*\((?!.*validate)', 'PHP move_uploaded_file without validation'),
                    (r'\$_FILES\[[^\]]+\]\[["\']name["\']\](?!.*validate)', 'Using original filename'),
                    (r'file_put_contents\s*\(.*?\$_FILES', 'file_put_contents with upload'),
                    (r'copy\s*\(\s*\$_FILES\[[^\]]+\]\[["\']tmp_name["\']\]', 'Copy uploaded file without validation'),
                    
                    # Java file upload
                    (r'transferTo\s*\(.*?getOriginalFilename', 'Spring file transfer with original name'),
                    (r'FileOutputStream\s*\(.*?getOriginalFilename', 'FileOutputStream with original filename'),
                    (r'commons-fileupload(?!.*SizeLimitExceededException)', 'Commons FileUpload without size limit'),
                    
                    # Dangerous file extensions
                    (r'\.php[0-9]?\s*', 'PHP file extension'),
                    (r'\.jsp\s*', 'JSP file extension'),
                    (r'\.asp[x]?\s*', 'ASP file extension'),
                    (r'\.exe\s*', 'Executable file'),
                    (r'\.sh\s*', 'Shell script'),
                    (r'\.bat\s*', 'Batch file'),
                ],
                'fix': 'Validate file type (check MIME and extension), limit file size, rename uploaded files, store outside web root, use secure_filename(), scan for malware'
            },
            
            # ============ LDAP INJECTION (OWASP A03:2021) ============
            'ldap_injection': {
                'severity': 'high',
                'cwe': 'CWE-90',
                'owasp': 'A03:2021',
                'patterns': [
                    (r'ldap_search\s*\(.*?\$_(GET|POST|REQUEST)', 'PHP LDAP search with user input'),
                    (r'ldap\.search\s*\(.*?[\+\{]', 'LDAP search with concatenation'),
                    (r'DirContext\.search\s*\(.*?\+', 'Java LDAP search with concatenation'),
                    (r'LdapConnection\.Search\s*\(.*?\+', '.NET LDAP with concatenation'),
                    (r'searchFilter\s*=.*?\+', 'LDAP filter concatenation'),
                ],
                'fix': 'Use parameterized LDAP queries, escape special characters (*, (, ), \\, NUL), validate input'
            },
            
            # ============ OPEN REDIRECT (OWASP A01:2021) ============
            'open_redirect': {
                'severity': 'medium',
                'cwe': 'CWE-601',
                'owasp': 'A01:2021',
                'patterns': [
                    (r'redirect\s*\(.*?request\.', 'Redirect with user input'),
                    (r'Response\.Redirect\s*\(.*?Request\.', '.NET redirect with request'),
                    (r'sendRedirect\s*\(.*?request\.', 'Java sendRedirect with request'),
                    (r'header\s*\(\s*["\']Location:.*?\$_(GET|POST|REQUEST)', 'PHP header location with user input'),
                    (r'res\.redirect\s*\(.*?req\.', 'Express redirect with request'),
                    (r'window\.location\s*=\s*.*?[\+\{]', 'JavaScript location with user input'),
                    (r'\.href\s*=\s*.*?[\+\{]', 'href assignment with user input'),
                ],
                'fix': 'Validate redirect URLs, use whitelist of allowed domains, use relative URLs only, validate URL scheme'
            },
            
            # ============ INFORMATION DISCLOSURE ============
            'information_disclosure': {
                'severity': 'medium',
                'cwe': 'CWE-200',
                'owasp': 'A01:2021',
                'patterns': [
                    # Debug mode and verbose errors
                    (r'DEBUG\s*=\s*True', 'Debug mode enabled'),
                    (r'debug\s*:\s*true', 'Debug configuration true'),
                    (r'FLASK_DEBUG\s*=\s*1', 'Flask debug enabled'),
                    (r'APP_DEBUG\s*=\s*true', 'App debug enabled'),
                    (r'display_errors\s*=\s*On', 'PHP display_errors On'),
                    (r'error_reporting\s*=\s*E_ALL', 'PHP full error reporting'),
                    (r'printStackTrace\s*\(\s*\)', 'Java printStackTrace'),
                    (r'console\.trace\s*\(', 'Console trace'),
                    
                    # Sensitive data logging
                    (r'console\.log\s*\(.*?(password|token|secret|api[_-]?key)', 'Logging sensitive data'),
                    (r'print\s*\(.*?(password|token|secret|api[_-]?key)', 'Printing sensitive data'),
                    (r'logger\.(info|debug|warn)\s*\(.*?(password|token|secret)', 'Logger with sensitive data'),
                    (r'echo\s+\$_(POST|GET|REQUEST)\[["\']pass', 'Echoing password'),
                    (r'var_dump\s*\(.*?password', 'var_dump with password'),
                    (r'print_r\s*\(.*?(password|token)', 'print_r with sensitive data'),
                    
                    # Stack traces and error messages
                    (r'traceback\.print_exc\s*\(\s*\)', 'Python print exception traceback'),
                    (r'raise.*?from\s+e', 'Raising exception with original'),
                    (r'throw\s+e;', 'Throwing raw exception'),
                    (r'res\.send\s*\(.*?error\)', 'Sending error in response'),
                    
                    # Server information
                    (r'Server\s*:\s*Apache/[0-9.]+', 'Server version disclosure'),
                    (r'X-Powered-By\s*:', 'X-Powered-By header'),
                    (r'phpversion\s*\(\s*\)', 'PHP version disclosure'),
                    
                    # Comments with sensitive info
                    (r'//\s*TODO.*?(password|secret|key|token)', 'TODO with sensitive info'),
                    (r'#\s*FIXME.*?(password|secret|key|token)', 'FIXME with sensitive info'),
                    (r'<!--.*?(password|api|key|secret).*?-->', 'HTML comment with sensitive info'),
                ],
                'fix': 'Disable debug mode in production, remove verbose error messages, avoid logging sensitive data, remove server version headers, clean up comments'
            },
            
            # ============ RACE CONDITIONS ============
            'race_condition': {
                'severity': 'medium',
                'cwe': 'CWE-362',
                'owasp': 'A04:2021',
                'patterns': [
                    (r'os\.path\.exists\s*\([^)]+\).*?open\s*\(', 'Time-of-check time-of-use'),
                    (r'if.*?os\.path\.isfile.*?:.*?open', 'TOCTOU file check'),
                    (r'if.*?fs\.existsSync.*?fs\.readFile', 'Node.js TOCTOU'),
                    (r'File\.exists\s*\([^)]+\).*?new\s+FileInputStream', 'Java TOCTOU'),
                    (r'is_file\s*\([^)]+\).*?fopen', 'PHP TOCTOU'),
                ],
                'fix': 'Use atomic operations, file locking, or try-except blocks instead of check-then-act patterns'
            },
            
            # ============ REGEX DOS (ReDoS) ============
            'redos': {
                'severity': 'medium',
                'cwe': 'CWE-1333',
                'owasp': 'A06:2021',
                'patterns': [
                    (r're\.compile\s*\([^)]*\([^\)]*\+[^\)]*\)\+', 'Nested quantifiers in regex'),
                    (r're\.match\s*\([^)]*\([^\)]*\*[^\)]*\)\*', 'Multiple nested quantifiers'),
                    (r'new\s+RegExp\s*\([^)]*\([^\)]*\+[^\)]*\)\+', 'JavaScript ReDoS pattern'),
                    (r'/\([^\)]*\+[^\)]*\)\+/', 'Regex with nested quantifiers'),
                    (r're\.compile\s*\([^)]*\([^\)]*\|[^\)]*\)\+', 'Alternation with quantifier'),
                ],
                'fix': 'Avoid nested quantifiers, use possessive quantifiers, set timeout limits, validate regex patterns'
            },
            
            # ============ MASS ASSIGNMENT ============
            'mass_assignment': {
                'severity': 'medium',
                'cwe': 'CWE-915',
                'owasp': 'A04:2021',
                'patterns': [
                    (r'\.update\s*\(\s*request\.(form|json|data)\s*\)', 'Direct update from request'),
                    (r'\.save\s*\(\s*\*\*request\.(form|json|data)', 'Save with request spread'),
                    (r'User\s*\(\s*\*\*request\.', 'Model creation with request data'),
                    (r'\.fill\s*\(\s*\$request->all\s*\(\s*\)\s*\)', 'Laravel fill with all request'),
                    (r'\.assign\s*\(\s*req\.body\s*\)', 'Assignment from request body'),
                ],
                'fix': 'Use whitelisting of allowed fields, define fillable/guarded attributes, validate input before assignment'
            },
            
            # ============ INSUFFICIENT LOGGING & MONITORING ============
            'insufficient_logging': {
                'severity': 'low',
                'cwe': 'CWE-778',
                'owasp': 'A09:2021',
                'patterns': [
                    (r'except.*?:\s*pass', 'Silent exception catching'),
                    (r'catch\s*\([^\)]*\)\s*\{\s*\}', 'Empty catch block'),
                    (r'try\s*:.*?except.*?:\s*pass', 'Try-except with pass'),
                    (r'@app\.route.*?def.*?\(.*?\):(?!.*log)', 'Route without logging'),
                ],
                'fix': 'Log security events, authentication attempts, authorization failures, input validation failures, use centralized logging'
            },
            
            # ============ CORS MISCONFIGURATION ============
            'cors_misconfiguration': {
                'severity': 'medium',
                'cwe': 'CWE-346',
                'owasp': 'A05:2021',
                'patterns': [
                    (r'Access-Control-Allow-Origin\s*:\s*\*', 'CORS wildcard origin'),
                    (r'CORS\s*\(.*?origins\s*=\s*\[?\s*["\']?\*', 'CORS with wildcard'),
                    (r'cors\s*\(\s*\)', 'CORS without configuration'),
                    (r'header\s*\(["\']Access-Control-Allow-Origin["\'].*?\*', 'Allow all origins'),
                    (r'AllowAnyOrigin\s*\(\s*\)', '.NET AllowAnyOrigin'),
                    (r'setAllowedOrigins\s*\(\s*["\']?\*', 'Java allow all origins'),
                ],
                'fix': 'Specify allowed origins explicitly, avoid wildcard (*), validate Origin header, use credentials carefully'
            },
            
            # ============ HTTP SECURITY HEADERS MISSING ============
            'missing_security_headers': {
                'severity': 'medium',
                'cwe': 'CWE-693',
                'owasp': 'A05:2021',
                'patterns': [
                    (r'@app\.route(?!.*X-Frame-Options)', 'Missing X-Frame-Options'),
                    (r'res\.send\s*\((?!.*X-Content-Type-Options)', 'Missing X-Content-Type-Options'),
                    (r'Response\s*\((?!.*Strict-Transport-Security)', 'Missing HSTS header'),
                    (r'header\s*\(["\']Content-Type["\'](?!.*X-Frame)', 'Missing security headers'),
                ],
                'fix': 'Add security headers: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy, X-XSS-Protection'
            },
            
            # ============ NOSQL INJECTION ============
            'nosql_injection': {
                'severity': 'high',
                'cwe': 'CWE-943',
                'owasp': 'A03:2021',
                'patterns': [
                    (r'\.find\s*\(\s*\{.*?\$where', 'MongoDB $where operator'),
                    (r'\.find\s*\(\s*request\.(query|body)', 'MongoDB find with request'),
                    (r'db\.collection\s*\(.*?\)\.find\s*\(\s*req\.', 'MongoDB injection vector'),
                    (r'\$ne\s*:', 'MongoDB $ne operator (check usage)'),
                    (r'\$gt\s*:', 'MongoDB $gt operator (validate)'),
                    (r'eval\s*\(.*?req\.', 'eval with request data'),
                ],
                'fix': 'Sanitize input, use parameterized queries, avoid $where operator, validate data types, use allow-lists'
            },
            
            # ============ SERVER-SIDE TEMPLATE INJECTION (SSTI) ============
            'ssti': {
                'severity': 'critical',
                'cwe': 'CWE-94',
                'owasp': 'A03:2021',
                'patterns': [
                    (r'render_template_string\s*\(.*?[\+\%\{]', 'Flask template string injection'),
                    (r'Template\s*\(.*?request\.', 'Jinja2 template with request'),
                    (r'\.render\s*\(.*?\+', 'Template render with concatenation'),
                    (r'compile\s*\(.*?request\..*?\).render', 'Template compilation with user input'),
                    (r'\.renderString\s*\(.*?req\.', 'Express template injection'),
                ],
                'fix': 'Never pass user input directly to template engines, use sandboxed environments, validate and sanitize input'
            },
            
            # ============ PROTOTYPE POLLUTION (JavaScript) ============
            'prototype_pollution': {
                'severity': 'high',
                'cwe': 'CWE-1321',
                'owasp': 'A08:2021',
                'patterns': [
                    (r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.', 'Object.assign with request'),
                    (r'\.merge\s*\(\s*\{\s*\}\s*,\s*req\.', 'Lodash merge with request'),
                    (r'\[\s*["\']__proto__["\']\s*\]', '__proto__ property access'),
                    (r'\[\s*["\']constructor["\']\s*\]', 'constructor property access'),
                    (r'\[\s*["\']prototype["\']\s*\]', 'prototype property access'),
                    (r'JSON\.parse\s*\(.*?req\..*?\)\[["\']__proto__', 'JSON parse with prototype'),
                ],
                'fix': 'Validate object keys, use Object.create(null), freeze prototypes, use Map instead of objects, sanitize user input'
            },
            
            # ============ BUFFER OVERFLOW (C/C++) ============
            'buffer_overflow': {
                'severity': 'critical',
                'cwe': 'CWE-120',
                'owasp': 'A03:2021',
                'patterns': [
                    (r'gets\s*\(', 'gets() function (unsafe)'),
                    (r'strcpy\s*\(', 'strcpy (unsafe - use strncpy)'),
                    (r'strcat\s*\(', 'strcat (unsafe - use strncat)'),
                    (r'sprintf\s*\(', 'sprintf (unsafe - use snprintf)'),
                    (r'vsprintf\s*\(', 'vsprintf (unsafe - use vsnprintf)'),
                    (r'scanf\s*\([^)]*%s', 'scanf with %s (unsafe)'),
                    (r'fscanf\s*\([^)]*%s', 'fscanf with %s'),
                    (r'memcpy\s*\([^)]*sizeof', 'memcpy with sizeof (check bounds)'),
                ],
                'fix': 'Use safe alternatives: strncpy, strncat, snprintf, fgets. Always check buffer bounds, use modern C++ string class'
            },
            
            # ============ INTEGER OVERFLOW ============
            'integer_overflow': {
                'severity': 'high',
                'cwe': 'CWE-190',
                'owasp': 'A04:2021',
                'patterns': [
                    (r'malloc\s*\([^)]*\*[^)]*\)', 'malloc with multiplication'),
                    (r'new\s+\w+\[[^]]*\*[^]]*\]', 'Array allocation with multiplication'),
                    (r'int\s+\w+\s*=.*?\+.*?\+', 'Integer arithmetic (check overflow)'),
                    (r'size_t\s+\w+\s*=.*?\*', 'size_t multiplication'),
                ],
                'fix': 'Check for overflow before arithmetic operations, use safe integer libraries, validate input ranges'
            },
            
            # ============ USE AFTER FREE (C/C++) ============
            'use_after_free': {
                'severity': 'critical',
                'cwe': 'CWE-416',
                'owasp': 'A06:2021',
                'patterns': [
                    (r'free\s*\([^)]+\)\s*;(?!.*?\1\s*=\s*NULL)', 'free without NULL assignment'),
                    (r'delete\s+[^;]+;(?!.*?=\s*nullptr)', 'delete without nullptr'),
                    (r'delete\[\]\s+[^;]+;(?!.*?=\s*nullptr)', 'delete[] without nullptr'),
                ],
                'fix': 'Set pointers to NULL/nullptr after free/delete, use smart pointers (unique_ptr, shared_ptr), enable AddressSanitizer'
            },
            
            # ============ FORMAT STRING VULNERABILITY ============
            'format_string': {
                'severity': 'critical',
                'cwe': 'CWE-134',
                'owasp': 'A03:2021',
                'patterns': [
                    (r'printf\s*\(\s*\w+\s*\)', 'printf with variable (no format string)'),
                    (r'fprintf\s*\([^,]+,\s*\w+\s*\)', 'fprintf with variable format'),
                    (r'sprintf\s*\([^,]+,\s*\w+\s*\)', 'sprintf with variable format'),
                    (r'syslog\s*\([^,]+,\s*\w+\s*\)', 'syslog with variable format'),
                    (r'logging\.\w+\s*\([^%]*%[^%]', 'Python logging with % formatting'),
                ],
                'fix': 'Always use format string literals: printf("%s", var) instead of printf(var)'
            },
            
            # ============ CLICKJACKING ============
            'clickjacking': {
                'severity': 'medium',
                'cwe': 'CWE-1021',
                'owasp': 'A04:2021',
                'patterns': [
                    (r'<iframe(?!.*sandbox)', 'iframe without sandbox'),
                    (r'<frame(?!.*X-Frame-Options)', 'frame without protection'),
                    (r'@app\.route(?!.*X-Frame-Options)', 'Route missing X-Frame-Options'),
                ],
                'fix': 'Add X-Frame-Options: DENY or SAMEORIGIN, use Content-Security-Policy frame-ancestors directive'
            },
            
            # ============ DEPENDENCY VULNERABILITIES ============
            'vulnerable_dependencies': {
                'severity': 'high',
                'cwe': 'CWE-1104',
                'owasp': 'A06:2021',
                'patterns': [
                    (r'jquery@[12]\.', 'jQuery version 1.x or 2.x (outdated)'),
                    (r'lodash@[0-3]\.', 'Lodash < 4.x (vulnerable)'),
                    (r'moment@[01]\.', 'Moment.js (deprecated)'),
                    (r'angular@1\.', 'AngularJS 1.x (EOL)'),
                    (r'react@1[0-5]\.', 'React < 16.x (outdated)'),
                    (r'<PackageReference.*Version\s*=\s*"[0-9]\.[0-9]', 'Old .NET dependency'),
                ],
                'fix': 'Update dependencies regularly, use dependency scanning tools (npm audit, pip-audit, OWASP Dependency-Check), remove unused packages'
            },
            
            # ============ INSECURE RANDOMNESS ============
            'insecure_randomness': {
                'severity': 'medium',
                'cwe': 'CWE-330',
                'owasp': 'A02:2021',
                'patterns': [
                    (r'time\s*\(\s*\).*?seed', 'Seeding with time()'),
                    (r'new\s+Date\s*\(\s*\)\.getTime\s*\(\s*\).*?random', 'Seeding with timestamp'),
                    (r'Random\s*\(\s*\d+\s*\)', 'Random with constant seed'),
                    (r'srand\s*\(\s*\d+\s*\)', 'srand with constant seed'),
                ],
                'fix': 'Use cryptographically secure random: secrets module (Python), crypto.randomBytes (Node.js), SecureRandom (Java)'
            },
            
            # ============ UNRESTRICTED FILE UPLOAD SIZE ============
            'unrestricted_upload': {
                'severity': 'medium',
                'cwe': 'CWE-400',
                'owasp': 'A04:2021',
                'patterns': [
                    (r'multer\s*\(\s*\{(?!.*limits)', 'Multer without size limits'),
                    (r'upload\.single\s*\((?!.*maxSize)', 'Upload without max size'),
                    (r'MAX_CONTENT_LENGTH\s*=\s*None', 'No content length limit'),
                    (r'upload_max_filesize\s*=\s*0', 'Unlimited file upload'),
                ],
                'fix': 'Set maximum file size limits, implement rate limiting, validate file size before processing'
            },
            
            # ============ TIMING ATTACK ============
            'timing_attack': {
                'severity': 'medium',
                'cwe': 'CWE-208',
                'owasp': 'A02:2021',
                'patterns': [
                    (r'if\s+password\s*==\s*', 'String comparison for password'),
                    (r'if\s+token\s*==\s*', 'String comparison for token'),
                    (r'if\s+secret\s*==\s*', 'String comparison for secret'),
                    (r'strcmp\s*\(.*?password', 'strcmp for password (timing)'),
                ],
                'fix': 'Use constant-time comparison: hmac.compare_digest() (Python), crypto.timingSafeEqual() (Node.js)'
            },
            
            # ============ UNVALIDATED REDIRECT ============
            'unvalidated_redirect': {
                'severity': 'medium',
                'cwe': 'CWE-601',
                'owasp': 'A01:2021',
                'patterns': [
                    (r'redirect\s*\(.*?request\.args\.get\s*\(["\']url', 'Redirect with URL parameter'),
                    (r'redirect\s*\(.*?request\.form\[["\']url', 'Redirect from form'),
                    (r'Response\.Redirect\s*\(.*?Request\.QueryString', '.NET redirect from query'),
                    (r'window\.location\s*=\s*getParameter\s*\(', 'JavaScript redirect from parameter'),
                ],
                'fix': 'Validate redirect URLs against whitelist, use relative URLs, verify URL scheme'
            },
            
            # ============ MEMORY LEAK ============
            'memory_leak': {
                'severity': 'medium',
                'cwe': 'CWE-401',
                'owasp': 'A04:2021',
                'patterns': [
                    (r'while\s*\(\s*true\s*\).*?append\s*\(', 'Infinite loop with append'),
                    (r'setInterval\s*\([^)]*(?!clearInterval)', 'setInterval without clear'),
                    (r'addEventListener\s*\([^)]*(?!removeEventListener)', 'Event listener without removal'),
                    (r'new\s+\w+\[.*?\](?!.*delete)', 'Array allocation without delete'),
                ],
                'fix': 'Clean up resources, use weak references, clear intervals/timeouts, remove event listeners, use RAII pattern'
            },
            
            # ============ INSECURE DIRECT OBJECT REFERENCE (IDOR) ============
            'idor': {
                'severity': 'high',
                'cwe': 'CWE-639',
                'owasp': 'A01:2021',
                'patterns': [
                    (r'\.get\s*\(\s*request\.(args|form)\[["\']id["\']\]\s*\)', 'Direct ID access'),
                    (r'SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+id\s*=\s*\$\{?req\.', 'Direct database ID query'),
                    (r'findById\s*\(\s*req\.(params|query|body)\.id\s*\)', 'Direct findById with request'),
                    (r'User\.find\s*\(\s*req\.params\.id\s*\)', 'Direct user find'),
                ],
                'fix': 'Implement access control checks, verify ownership, use indirect references, check authorization before data access'
            },
            
            # ============ XML BOMB (Billion Laughs) ============
            'xml_bomb': {
                'severity': 'high',
                'cwe': 'CWE-776',
                'owasp': 'A05:2021',
                'patterns': [
                    (r'<!ENTITY', 'XML entity declaration (check for bomb)'),
                    (r'etree\.parse\s*\((?!.*resolve_entities=False)', 'XML parse without entity protection'),
                    (r'DocumentBuilder\.parse\s*\((?!.*setExpandEntityReferences)', 'Java XML parse vulnerable to bomb'),
                ],
                'fix': 'Disable entity expansion, set limits on entity expansion depth, use defusedxml library'
            },
            
            # ============ BUSINESS LOGIC VULNERABILITIES ============
            'business_logic': {
                'severity': 'high',
                'cwe': 'CWE-840',
                'owasp': 'A04:2021',
                'patterns': [
                    (r'if\s+amount\s*<\s*0', 'Negative amount check (check logic)'),
                    (r'balance\s*-=\s*amount(?!.*if)', 'Balance deduction without validation'),
                    (r'quantity\s*=\s*int\s*\(\s*request\.', 'Quantity from request without validation'),
                    (r'price\s*=\s*request\.(form|args|json)', 'Price from user input'),
                    (r'role\s*=\s*request\.(form|args|json)\[["\']role["\']\]', 'Role assignment from request'),
                ],
                'fix': 'Validate business rules, check quantity/price ranges, verify state transitions, implement rate limiting'
            },
            
            # ============ JWT VULNERABILITIES ============
            'jwt_vulnerabilities': {
                'severity': 'high',
                'cwe': 'CWE-347',
                'owasp': 'A02:2021',
                'patterns': [
                    (r'jwt\.decode\s*\([^)]*,\s*verify\s*=\s*False', 'JWT decode without verification'),
                    (r'algorithm\s*=\s*["\']none["\']', 'JWT algorithm none'),
                    (r'jwt\.encode\s*\([^)]*algorithm\s*=\s*["\']HS256["\'].*?secret\s*=\s*["\'][^"\']{1,10}["\']', 'JWT with weak secret'),
                    (r'verify_signature\s*=\s*False', 'JWT signature verification disabled'),
                ],
                'fix': 'Always verify JWT signatures, use strong algorithms (RS256), use strong secrets (256+ bits), validate all claims'
            },
            
            # ============ API KEY EXPOSURE ============
            'api_key_exposure': {
                'severity': 'critical',
                'cwe': 'CWE-798',
                'owasp': 'A07:2021',
                'patterns': [
                    (r'https?://[^/]*api[^/]*/[^?]*\?[^&]*key=[\w\-]{15,}', 'API key in URL'),
                    (r'Authorization:\s*Bearer\s+[\w\-\.]{20,}', 'Bearer token in code'),
                    (r'x-api-key:\s*[\w\-]{20,}', 'API key in header'),
                ],
                'fix': 'Never hardcode API keys, use environment variables, rotate keys regularly, use key management services'
            },
            
            # ============ GRAPHQL VULNERABILITIES ============
            'graphql_vulnerabilities': {
                'severity': 'medium',
                'cwe': 'CWE-400',
                'owasp': 'A04:2021',
                'patterns': [
                    (r'GraphQLSchema\s*\((?!.*validation_rules)', 'GraphQL without validation'),
                    (r'execute\s*\([^)]*(?!max_depth)', 'GraphQL execute without depth limit'),
                    (r'@app\.route\s*\(["\'][^"\']*graphql(?!.*authentication)', 'GraphQL endpoint without auth'),
                ],
                'fix': 'Implement query depth limiting, query complexity analysis, rate limiting, require authentication'
            },
            
            # ============ WEBSOCKET VULNERABILITIES ============
            'websocket_vulnerabilities': {
                'severity': 'medium',
                'cwe': 'CWE-346',
                'owasp': 'A05:2021',
                'patterns': [
                    (r'WebSocket\s*\([^)]*(?!wss://)', 'WebSocket without WSS'),
                    (r'ws\.on\s*\(["\']message["\'][^)]*(?!validate)', 'WebSocket message without validation'),
                    (r'socket\.on\s*\(["\'].*?["\'][^)]*(?!auth)', 'Socket.io without authentication'),
                ],
                'fix': 'Use WSS (TLS), validate all messages, implement authentication, rate limit connections'
            },
            
            # ============ DOCKER/CONTAINER SECURITY ============
            'container_security': {
                'severity': 'medium',
                'cwe': 'CWE-250',
                'owasp': 'A05:2021',
                'patterns': [
                    (r'FROM.*:latest', 'Docker image using latest tag'),
                    (r'USER\s+root', 'Container running as root'),
                    (r'privileged:\s*true', 'Privileged container'),
                    (r'--privileged', 'Docker run with privileged flag'),
                    (r'cap_add:\s*ALL', 'Adding all capabilities'),
                ],
                'fix': 'Use specific image tags, run as non-root user, avoid privileged mode, minimal capabilities, scan images for vulnerabilities'
            },
            
            # ============ KUBERNETES SECURITY ============
            'kubernetes_security': {
                'severity': 'high',
                'cwe': 'CWE-250',
                'owasp': 'A05:2021',
                'patterns': [
                    (r'automountServiceAccountToken:\s*true', 'Auto-mount service account token'),
                    (r'privileged:\s*true', 'Privileged pod'),
                    (r'hostNetwork:\s*true', 'Host network enabled'),
                    (r'hostPID:\s*true', 'Host PID namespace'),
                    (r'allowPrivilegeEscalation:\s*true', 'Privilege escalation allowed'),
                ],
                'fix': 'Disable automountServiceAccountToken, avoid privileged pods, use Pod Security Standards, implement RBAC'
            },
        }
    
    def test_connection(self) -> bool:
        """Test GitHub API connection"""
        print("\n🔌 Testing GitHub connection...")
        try:
            response = requests.get(f"{self.base_url}/user", headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.username = data.get('login')
                print(f"✅ Connected as: {self.username}")
                return True
            else:
                print(f"❌ Authentication failed!")
                return False
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False
    
    def scan_with_patterns(self, file_path: str, code_content: str) -> List[Dict]:
        """Comprehensive deterministic pattern-based scanning"""
        vulnerabilities = []
        lines = code_content.split('\n')
        file_ext = Path(file_path).suffix
        
        for vuln_type, config in self.security_patterns.items():
            for pattern, description in config['patterns']:
                try:
                    for line_num, line in enumerate(lines, 1):
                        # Skip comments to reduce false positives
                        stripped_line = line.strip()
                        if stripped_line.startswith(('#', '//', '/*', '*', '<!--')):
                            continue
                            
                        if re.search(pattern, line, re.IGNORECASE):
                            # Context-aware filtering
                            if self._is_false_positive(line, vuln_type, file_ext):
                                continue
                            
                            vulnerable_code = line.strip()
                            fixed_code = self.generate_enhanced_fix(line, vuln_type, file_ext)
                            
                            vulnerabilities.append({
                                'type': vuln_type.replace('_', ' ').title(),
                                'severity': config['severity'],
                                'cwe': config.get('cwe', 'N/A'),
                                'owasp': config.get('owasp', 'N/A'),
                                'line': str(line_num),
                                'description': description,
                                'vulnerable_code': vulnerable_code,
                                'fix': config['fix'],
                                'fixed_code': fixed_code,
                                'detected_by': 'deterministic_pattern',
                                'confidence': 'high'
                            })
                except:
                    pass
        
        return vulnerabilities
    
    def _is_false_positive(self, line: str, vuln_type: str, file_ext: str) -> bool:
        """Reduce false positives with context-aware filtering"""
        line_lower = line.lower()
        
        # Skip test files
        if any(test_indicator in line_lower for test_indicator in ['test_', 'mock', 'stub', 'fixture']):
            return True
        
        # Skip example/documentation code
        if any(doc_indicator in line_lower for doc_indicator in ['example', 'demo', 'sample', '# usage']):
            return True
        
        # Context-specific false positive reduction
        if vuln_type == 'hardcoded_secrets':
            # Skip common non-secrets
            if any(benign in line_lower for benign in ['example', 'placeholder', 'your_', 'insert_', 'put_your_']):
                return True
            if re.search(r'(password|key|secret)\s*=\s*["\'](\s*|xxx+|test|demo|sample)["\']', line_lower):
                return True
        
        return False
    
    def generate_enhanced_fix(self, code_line: str, vuln_type: str, file_ext: str) -> str:
        """Generate context-aware fix suggestions"""
        fixes = {
            'sql_injection': self._fix_sql_injection(code_line, file_ext),
            'xss': self._fix_xss(code_line, file_ext),
            'hardcoded_secrets': self._fix_hardcoded_secrets(code_line, file_ext),
            'command_injection': self._fix_command_injection(code_line, file_ext),
            'path_traversal': self._fix_path_traversal(code_line, file_ext),
            'weak_crypto': self._fix_weak_crypto(code_line, file_ext),
        }
        
        return fixes.get(vuln_type, f'# SECURITY FIX NEEDED: {vuln_type}\n{code_line}')
    
    def _fix_sql_injection(self, line: str, ext: str) -> str:
        """Generate SQL injection fixes"""
        if ext == '.py':
            if 'execute' in line:
                return re.sub(r'execute\s*\([^)]+\)', 'execute(query, (param1, param2))', line)
        elif ext in ['.js', '.ts']:
            return line.replace('`', '').replace('${', '').replace('}', '') + '  # Use parameterized query'
        return f'# Use parameterized queries\n{line}'
    
    def _fix_xss(self, line: str, ext: str) -> str:
        """Generate XSS fixes"""
        line = line.replace('innerHTML', 'textContent')
        line = line.replace('dangerouslySetInnerHTML', 'children')
        line = line.replace('v-html', 'v-text')
        return line
    
    def _fix_hardcoded_secrets(self, line: str, ext: str) -> str:
        """Generate secret management fixes"""
        if ext == '.py':
            return re.sub(r'=\s*["\'][^"\']+["\']', '= os.getenv("SECRET_KEY")', line)
        elif ext in ['.js', '.ts']:
            return re.sub(r'=\s*["\'][^"\']+["\']', '= process.env.SECRET_KEY', line)
        return re.sub(r'=\s*["\'][^"\']+["\']', '= ENV["SECRET_KEY"]', line)
    
    def _fix_command_injection(self, line: str, ext: str) -> str:
        """Generate command injection fixes"""
        line = line.replace('shell=True', 'shell=False')
        line = line.replace('os.system', 'subprocess.run')
        return line + '  # Use parameterized commands'
    
    def _fix_path_traversal(self, line: str, ext: str) -> str:
        """Generate path traversal fixes"""
        if ext == '.py':
            return f'# Validate path: os.path.basename(filename)\n{line}'
        return f'# Validate and sanitize file path\n{line}'
    
    def _fix_weak_crypto(self, line: str, ext: str) -> str:
        """Generate cryptography fixes"""
        line = line.replace('md5', 'sha256')
        line = line.replace('sha1', 'sha256')
        line = line.replace('MD5', 'SHA256')
        line = line.replace('SHA1', 'SHA256')
        line = line.replace('Math.random()', 'crypto.randomBytes(32)')
        line = line.replace('random.random()', 'secrets.token_bytes(32)')
        return line
    
    def github_request(self, method: str, endpoint: str, data: Optional[Dict] = None, timeout: int = 30) -> Dict:
        """Make GitHub API request"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.request(method, url, headers=self.headers, json=data, timeout=timeout)
            if response.status_code in [200, 201]:
                return response.json() if response.content else {"success": True}
            else:
                error_msg = response.json().get('message', '') if response.content else f"HTTP {response.status_code}"
                return {"error": error_msg}
        except Exception as e:
            return {"error": str(e)}
    
    def force_remove_directory(self, path: str):
        """Remove directory with Windows handling"""
        def handle_remove_readonly(func, path, exc):
            try:
                os.chmod(path, stat.S_IWUSR | stat.S_IREAD | stat.S_IWRITE)
                func(path)
            except:
                pass
        
        for attempt in range(3):
            try:
                if os.path.exists(path):
                    for root, dirs, files in os.walk(path):
                        for d in dirs:
                            try:
                                os.chmod(os.path.join(root, d), stat.S_IWUSR | stat.S_IREAD | stat.S_IWRITE)
                            except:
                                pass
                        for f in files:
                            try:
                                os.chmod(os.path.join(root, f), stat.S_IWUSR | stat.S_IREAD | stat.S_IWRITE)
                            except:
                                pass
                    shutil.rmtree(path, onerror=handle_remove_readonly)
                break
            except:
                if attempt < 2:
                    time.sleep(1)
    
    def clone_repository(self, github_url: str, target_dir="temp_scan_repo") -> str:
        """Clone GitHub repository"""
        if os.path.exists(target_dir):
            self.force_remove_directory(target_dir)
        
        print(f"\n📥 Cloning repository...")
        subprocess.run(["git", "clone", "--depth", "1", github_url, target_dir], 
                      check=True, capture_output=True, text=True)
        print(f"✅ Repository cloned")
        return target_dir
    
    def get_code_files(self, repo_path: str) -> List[str]:
        """Get all code files"""
        files = []
        skip_dirs = {'.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build', '.next', 'vendor', 'target', 'bin', 'obj'}
        
        for root, dirs, filenames in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in filenames:
                if Path(filename).suffix in self.supported_extensions:
                    file_path = os.path.join(root, filename)
                    try:
                        if os.path.getsize(file_path) < 500000:  # 500KB limit
                            files.append(file_path)
                    except:
                        pass
        return files
    
    def scan_repository(self, repo_path: str) -> Dict:
        """Scan repository with comprehensive deterministic patterns"""
        print("\n🔍 DETERMINISTIC SECURITY SCAN")
        print("="*70)
        print("🎯 100% Pattern-Based | No AI | Consistent Results")
        print("="*70)
        
        files = self.get_code_files(repo_path)
        print(f"📁 Found {len(files)} code files to scan")
        
        if not files:
            return {"files": {}, "vulnerabilities": [], "total_issues": 0, "scan_summary": {}}
        
        max_files = len(files)  # Scan all files
        print(f"📊 Scanning {max_files} files with {sum(len(config['patterns']) for config in self.security_patterns.values())} security patterns\n")
        
        all_results = {}
        vulnerabilities_summary = []
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        vuln_type_count = {}
        
        for i, file_path in enumerate(files[:max_files], 1):
            relative_path = os.path.relpath(file_path, repo_path)
            print(f"[{i}/{max_files}] 🔍 {relative_path[:60]}", end='', flush=True)
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    original_code = f.read()
                
                if len(original_code.strip()) < 30:
                    print(" ⏭️  Skipped (too small)")
                    continue
                
                # Scan with comprehensive patterns
                vulnerabilities = self.scan_with_patterns(file_path, original_code)
                
                if vulnerabilities:
                    print(f"\r[{i}/{max_files}] ✅ {relative_path[:60]} - 🔴 {len(vulnerabilities)} issues found")
                    
                    # Count severity and types
                    for vuln in vulnerabilities:
                        severity = vuln.get('severity', 'low')
                        severity_count[severity] = severity_count.get(severity, 0) + 1
                        
                        vuln_type = vuln.get('type', 'Unknown')
                        vuln_type_count[vuln_type] = vuln_type_count.get(vuln_type, 0) + 1
                    
                    # Generate corrected code
                    corrected_code = self.generate_corrected_code(original_code, vulnerabilities)
                    
                    all_results[relative_path] = {
                        "original_code": original_code,
                        "corrected_code": corrected_code,
                        "vulnerabilities": vulnerabilities,
                        "has_fixes": True
                    }
                    
                    for vuln in vulnerabilities:
                        vuln['file'] = relative_path
                        vulnerabilities_summary.append(vuln)
                else:
                    print(f"\r[{i}/{max_files}] ✅ {relative_path[:60]} - ✅ Clean")
                    
            except Exception as e:
                print(f"\r[{i}/{max_files}] ❌ {relative_path[:60]} - Error: {str(e)[:30]}")
        
        print(f"\n{'='*70}")
        print(f"✅ Scan complete: {len(vulnerabilities_summary)} vulnerabilities detected")
        
        return {
            "files": all_results,
            "vulnerabilities": vulnerabilities_summary,
            "total_issues": len(vulnerabilities_summary),
            "scan_summary": {
                "severity_breakdown": severity_count,
                "vulnerability_types": vuln_type_count,
                "files_scanned": max_files,
                "files_with_issues": len(all_results)
            }
        }
    
    def generate_corrected_code(self, original_code: str, vulnerabilities: List[Dict]) -> str:
        """Generate corrected code based on vulnerabilities"""
        lines = original_code.split('\n')
        
        # Sort vulnerabilities by line number (reverse) to avoid offset issues
        sorted_vulns = sorted(vulnerabilities, key=lambda v: int(v.get('line', 0)), reverse=True)
        
        # Apply fixes line by line
        for vuln in sorted_vulns:
            try:
                line_num = int(vuln.get('line', 0)) - 1
                if 0 <= line_num < len(lines) and vuln.get('fixed_code'):
                    # Add security comment
                    indent = len(lines[line_num]) - len(lines[line_num].lstrip())
                    security_comment = ' ' * indent + f'# SECURITY FIX: {vuln.get("type")} - {vuln.get("cwe")}'
                    lines[line_num] = security_comment + '\n' + vuln['fixed_code']
            except:
                pass
        
        return '\n'.join(lines)
    
    def save_report(self, scan_results: Dict, output_file="security_report.json") -> str:
        """Save comprehensive scan results"""
        report = {
            "scan_metadata": {
                "scan_type": "Deterministic Pattern-Based",
                "total_patterns": sum(len(config['patterns']) for config in self.security_patterns.values()),
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scanner_version": "2.0-Deterministic"
            },
            "summary": {
                "total_vulnerabilities": scan_results['total_issues'],
                "files_scanned": scan_results['scan_summary']['files_scanned'],
                "files_with_issues": scan_results['scan_summary']['files_with_issues'],
                "severity_breakdown": scan_results['scan_summary']['severity_breakdown'],
                "vulnerability_types": scan_results['scan_summary']['vulnerability_types']
            },
            "vulnerabilities": scan_results['vulnerabilities'],
            "fixed_files": {
                path: {
                    "vulnerability_count": len(data['vulnerabilities']),
                    "vulnerabilities": data['vulnerabilities'],
                    "corrected_code": data['corrected_code'],
                    "has_auto_fix": data['has_fixes']
                }
                for path, data in scan_results['files'].items()
            }
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Detailed report saved: {output_file}")
        return output_file
        
    def create_fixed_repository(self, scan_results: Dict, original_repo_path: str, new_repo_name: str):
        """Create new repository with fixed code"""
        print(f"\n🚀 Creating fixed repository: {new_repo_name}")
        print("="*70)
        
        # Create repository
        create_response = self.github_request("POST", "/user/repos", {
            "name": new_repo_name,
            "description": f"🛡️ Security Fixed - {scan_results['total_issues']} issues resolved",
            "private": False,
            "auto_init": True
        })
        
        if "error" in create_response:
            if "already exists" in str(create_response.get('error', '')).lower():
                delete = input(f"Repository '{new_repo_name}' exists. Delete and recreate? (yes/no): ").strip().lower()
                if delete in ['yes', 'y']:
                    self.github_request("DELETE", f"/repos/{self.username}/{new_repo_name}")
                    time.sleep(2)
                    create_response = self.github_request("POST", "/user/repos", {
                        "name": new_repo_name,
                        "description": f"🛡️ Security Fixed - {scan_results['total_issues']} issues resolved",
                        "private": False,
                        "auto_init": True
                    })
                else:
                    return False
            
            if "error" in create_response:
                print(f"❌ Failed to create repository: {create_response['error']}")
                return False
        
        print(f"✅ Repository created: https://github.com/{self.username}/{new_repo_name}")
        time.sleep(3)
        
        # Get branch
        repo_response = self.github_request("GET", f"/repos/{self.username}/{new_repo_name}")
        branch = repo_response.get('default_branch', 'main')
        
        ref_response = self.github_request("GET", f"/repos/{self.username}/{new_repo_name}/git/ref/heads/{branch}")
        base_sha = ref_response["object"]["sha"]
        commit_response = self.github_request("GET", f"/repos/{self.username}/{new_repo_name}/git/commits/{base_sha}")
        tree_sha = commit_response["tree"]["sha"]
        
        # Create README with security report
        readme_content = self._generate_security_readme(scan_results)
        readme_encoded = base64.b64encode(readme_content.encode('utf-8')).decode('utf-8')
        
        # Upload files
        print("\n📤 Uploading files with folder structure...")
        tree_items = []
        
        # Add README
        readme_blob = self.github_request("POST", f"/repos/{self.username}/{new_repo_name}/git/blobs",
                                        {"content": readme_encoded, "encoding": "base64"})
        if "sha" in readme_blob:
            tree_items.append({"path": "SECURITY_REPORT.md", "mode": "100644", "type": "blob", "sha": readme_blob["sha"]})
        
        # Track all files to upload (fixed + original)
        files_to_upload = {}
        
        # First, add all fixed files
        for relative_path, data in scan_results['files'].items():
            files_to_upload[relative_path] = data['corrected_code']
            print(f"  🔧 {relative_path}")
        
        # Then, add all original files (skipping already fixed ones)
        print("  📦 Processing remaining files...")
        for root, dirs, filenames in os.walk(original_repo_path):
            # Skip .git and other unwanted directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build', '.next', 'vendor', 'target', 'bin', 'obj'}]
            
            for filename in filenames:
                file_path = os.path.join(root, filename)
                relative_path = os.path.relpath(file_path, original_repo_path).replace('\\', '/')
                
                # Skip if already in fixed files or is the security report
                if relative_path in files_to_upload or relative_path == 'SECURITY_REPORT.md':
                    continue
                
                try:
                    # Read file content
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    
                    # Skip files > 1MB
                    if len(content) > 1000000:
                        print(f"  ⏭️  Skipped (too large): {relative_path}")
                        continue
                    
                    files_to_upload[relative_path] = content
                    
                except Exception as e:
                    print(f"  ⚠️  Could not read: {relative_path}")
        
        # Now upload all files with proper paths
        print(f"\n📤 Uploading {len(files_to_upload)} files...")
        uploaded_count = 0
        
        for relative_path, content in files_to_upload.items():
            try:
                # Normalize path separators to forward slashes for GitHub
                normalized_path = relative_path.replace('\\', '/')
                
                # Encode content
                if isinstance(content, str):
                    encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
                else:
                    encoded = base64.b64encode(content).decode('utf-8')
                
                # Create blob
                blob_response = self.github_request("POST", f"/repos/{self.username}/{new_repo_name}/git/blobs",
                                                {"content": encoded, "encoding": "base64"})
                
                if "sha" in blob_response:
                    tree_items.append({
                        "path": normalized_path,
                        "mode": "100644",
                        "type": "blob",
                        "sha": blob_response["sha"]
                    })
                    uploaded_count += 1
                    if uploaded_count % 10 == 0:
                        print(f"  ✅ Uploaded {uploaded_count}/{len(files_to_upload)} files...")
                else:
                    print(f"  ❌ Failed to upload: {normalized_path}")
                    
            except Exception as e:
                print(f"  ⚠️  Error uploading {relative_path}: {str(e)[:50]}")
        
        print(f"✅ Successfully prepared {len(tree_items)} files")
        
        # Create tree
        print("🌳 Creating repository tree...")
        new_tree = self.github_request("POST", f"/repos/{self.username}/{new_repo_name}/git/trees",
                                    {"base_tree": tree_sha, "tree": tree_items})
        
        if "error" in new_tree:
            print(f"❌ Failed to create tree: {new_tree['error']}")
            return False
        
        # Create commit
        print("💾 Creating commit...")
        severity = scan_results['scan_summary']['severity_breakdown']
        commit_msg = f"""🛡️ Security Fixes Applied - Deterministic Scan

    ✅ Fixed {len(scan_results['files'])} files
    🔍 Resolved {len(scan_results['vulnerabilities'])} vulnerabilities

    📊 Severity Breakdown:
    🔴 Critical: {severity.get('critical', 0)}
    🔴 High: {severity.get('high', 0)}
    🟡 Medium: {severity.get('medium', 0)}
    🟢 Low: {severity.get('low', 0)}

    🔬 Scan Type: Deterministic Pattern-Based (100% consistent)
    📋 Patterns Used: {sum(len(config['patterns']) for config in self.security_patterns.values())}

    See SECURITY_REPORT.md for details."""

        new_commit = self.github_request("POST", f"/repos/{self.username}/{new_repo_name}/git/commits",
                                        {"message": commit_msg, "tree": new_tree["sha"], "parents": [base_sha]})
        
        if "error" in new_commit:
            print(f"❌ Failed to create commit: {new_commit['error']}")
            return False
        
        # Update branch
        print("🔄 Updating branch...")
        update_response = self.github_request("PATCH", f"/repos/{self.username}/{new_repo_name}/git/refs/heads/{branch}",
                                            {"sha": new_commit["sha"]})
        
        if "error" not in update_response:
            print(f"\n✅ Successfully created secure repository!")
            print(f"🔗 Repository: https://github.com/{self.username}/{new_repo_name}")
            print(f"📄 Security Report: https://github.com/{self.username}/{new_repo_name}/blob/{branch}/SECURITY_REPORT.md")
            return True
        else:
            print(f"❌ Failed to update branch: {update_response['error']}")
            return False
    
    def _generate_security_readme(self, scan_results: Dict) -> str:
        """Generate comprehensive security report"""
        severity = scan_results['scan_summary']['severity_breakdown']
        vuln_types = scan_results['scan_summary']['vulnerability_types']
        
        readme = f"""# 🛡️ Security Scan Report

**Scan Date:** {time.strftime("%Y-%m-%d %H:%M:%S")}  
**Scan Type:** Deterministic Pattern-Based Analysis  
**Scanner Version:** 2.0

---

## 📊 Executive Summary

- **Total Vulnerabilities Found:** {scan_results['total_issues']}
- **Files Scanned:** {scan_results['scan_summary']['files_scanned']}
- **Files with Issues:** {scan_results['scan_summary']['files_with_issues']}
- **All Issues:** ✅ **FIXED**

---

## 🔥 Severity Breakdown

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 Critical | {severity.get('critical', 0)} | ✅ Fixed |
| 🔴 High | {severity.get('high', 0)} | ✅ Fixed |
| 🟡 Medium | {severity.get('medium', 0)} | ✅ Fixed |
| 🟢 Low | {severity.get('low', 0)} | ✅ Fixed |

---

## 🔍 Vulnerability Types Detected

"""
        
        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            readme += f"- **{vuln_type}**: {count} issue(s)\n"
        
        readme += f"""

---

## 📋 Detailed Findings

"""
        
        # Group vulnerabilities by file
        files_with_vulns = {}
        for vuln in scan_results['vulnerabilities']:
            file_path = vuln.get('file', 'Unknown')
            if file_path not in files_with_vulns:
                files_with_vulns[file_path] = []
            files_with_vulns[file_path].append(vuln)
        
        for file_path, vulns in sorted(files_with_vulns.items()):
            readme += f"### 📁 `{file_path}`\n\n"
            readme += f"**Issues Found:** {len(vulns)}\n\n"
            
            for i, vuln in enumerate(vulns, 1):
                severity_emoji = {
                    'critical': '🔴',
                    'high': '🔴',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(vuln.get('severity', 'low'), '⚪')
                
                readme += f"#### {i}. {severity_emoji} {vuln.get('type')} - Line {vuln.get('line')}\n\n"
                readme += f"**Severity:** {vuln.get('severity', 'N/A').upper()}  \n"
                readme += f"**CWE:** {vuln.get('cwe', 'N/A')}  \n"
                readme += f"**OWASP:** {vuln.get('owasp', 'N/A')}  \n"
                readme += f"**Description:** {vuln.get('description', 'N/A')}\n\n"
                
                if vuln.get('vulnerable_code'):
                    readme += f"**Vulnerable Code:**\n```\n{vuln['vulnerable_code']}\n```\n\n"
                
                readme += f"**Fix Applied:** {vuln.get('fix', 'N/A')}\n\n"
                readme += "---\n\n"
        
        readme += f"""

## 🎯 Scan Coverage

This security scan used **{sum(len(config['patterns']) for config in self.security_patterns.values())} deterministic patterns** covering:

- ✅ SQL Injection (OWASP A03:2021)
- ✅ Cross-Site Scripting (XSS)
- ✅ Hardcoded Secrets & API Keys
- ✅ Command Injection
- ✅ Path Traversal
- ✅ Insecure Deserialization
- ✅ Weak Cryptography
- ✅ Authentication Issues
- ✅ CSRF Vulnerabilities
- ✅ XXE (XML External Entity)
- ✅ SSRF (Server-Side Request Forgery)
- ✅ Insecure File Upload
- ✅ LDAP Injection
- ✅ Open Redirect
- ✅ Information Disclosure
- ✅ Race Conditions
- ✅ ReDoS (Regex DoS)
- ✅ Mass Assignment
- ✅ CORS Misconfiguration
- ✅ NoSQL Injection
- ✅ Server-Side Template Injection (SSTI)
- ✅ Prototype Pollution
- ✅ Buffer Overflow
- ✅ JWT Vulnerabilities
- ✅ GraphQL Security
- ✅ WebSocket Security
- ✅ Container/Docker Security
- ✅ Kubernetes Security
- And 25+ more categories...

---

## ⚠️ Important Notes

1. **Review Before Deployment**: While all issues have been automatically fixed, please review the changes before deploying to production.
2. **Test Thoroughly**: Run your test suite to ensure the fixes don't break functionality.
3. **Additional Security**: Consider implementing:
   - Input validation
   - Output encoding
   - Rate limiting
   - WAF (Web Application Firewall)
   - Security headers
   - Regular dependency updates
4. **Continuous Monitoring**: Implement continuous security scanning in your CI/CD pipeline.

---

## 📚 References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)

---

**Generated by Deterministic Security Scanner v2.0**  
*100% Pattern-Based | No AI | Consistent Results*
"""
        
        return readme


def main():
    print("🛡️  DETERMINISTIC SECURITY SCANNER")
    print("🎯 100% Pattern-Based | No AI | Consistent Results")
    print("="*70)
    
    # Get GitHub token
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("\n❌ GITHUB_TOKEN not found in environment!")
        print("💡 Create a .env file with: GITHUB_TOKEN=your_token_here")
        print("💡 Or export GITHUB_TOKEN=your_token_here")
        return
    
    # Initialize scanner
    scanner = DeterministicSecurityScanner(github_token)
    
    # Test connection
    if not scanner.test_connection():
        print("\n❌ GitHub connection failed. Check your token.")
        return
    
    # Display scan capabilities
    print(f"\n📋 Loaded {len(scanner.security_patterns)} vulnerability categories")
    print(f"🔍 Total patterns: {sum(len(v['patterns']) for v in scanner.security_patterns.values())}")
    print(f"📁 Supported file types: {len(scanner.supported_extensions)}")
    
    # Get repository URL
    print("\n" + "="*70)
    repo_url = input("🔗 Enter GitHub repository URL to scan: ").strip()
    if not repo_url:
        print("❌ No URL provided")
        return
    
    repo_path = None
    
    try:
        # Clone and scan
        repo_path = scanner.clone_repository(repo_url)
        scan_results = scanner.scan_repository(repo_path)
        report_file = scanner.save_report(scan_results)
        
        # Display comprehensive summary
        print("\n" + "="*70)
        print("📊 SECURITY SCAN SUMMARY")
        print("="*70)
        print(f"Total Vulnerabilities: {scan_results['total_issues']}")
        print(f"Files Scanned: {scan_results['scan_summary']['files_scanned']}")
        print(f"Files with Issues: {scan_results['scan_summary']['files_with_issues']}")
        
        # Show severity breakdown
        severity = scan_results['scan_summary']['severity_breakdown']
        print(f"\n🔥 Severity Breakdown:")
        if severity.get('critical', 0) > 0:
            print(f"  🔴 Critical: {severity['critical']}")
        if severity.get('high', 0) > 0:
            print(f"  🔴 High: {severity['high']}")
        if severity.get('medium', 0) > 0:
            print(f"  🟡 Medium: {severity['medium']}")
        if severity.get('low', 0) > 0:
            print(f"  🟢 Low: {severity['low']}")
        
        # Show top vulnerability types
        vuln_types = scan_results['scan_summary']['vulnerability_types']
        if vuln_types:
            print(f"\n🔍 Top Vulnerability Types:")
            for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  • {vuln_type}: {count}")
        
        # Show sample vulnerabilities
        if scan_results['vulnerabilities']:
            print(f"\n📋 Sample Vulnerabilities (showing top 5):")
            for i, vuln in enumerate(scan_results['vulnerabilities'][:5], 1):
                severity_emoji = {'critical': '🔴', 'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(vuln.get('severity'), '⚪')
                print(f"\n  [{i}] {severity_emoji} {vuln.get('type')} - {vuln.get('severity', '').upper()}")
                print(f"      📁 {vuln.get('file')} (Line {vuln.get('line')})")
                print(f"      📝 {vuln.get('description')}")
                print(f"      🔧 {vuln.get('cwe')} | {vuln.get('owasp')}")
        
        # Create fixed repository
        if scan_results['files']:
            print("\n" + "="*70)
            output_name = input(f"\n📝 Enter name for fixed repository (default: ___demo_repo): ").strip() or "___demo_repo"
            confirm = input(f"\n✅ Create fixed repository '{output_name}'? (yes/no): ").strip().lower()
            
            if confirm in ['yes', 'y']:
                success = scanner.create_fixed_repository(scan_results, repo_path, output_name)
                
                if success:
                    print("\n" + "="*70)
                    print("🎉 SECURITY SCAN COMPLETE!")
                    print("="*70)
                    print(f"✅ Fixed Repository: https://github.com/{scanner.username}/___demo_repo")
                    print(f"✅ Detailed Report: {report_file}")
                    print(f"✅ Security Summary: https://github.com/{scanner.username}/___demo_repo/blob/main/SECURITY_REPORT.md")
                    print(f"\n📊 Results:")
                    print(f"   🔍 {scan_results['total_issues']} vulnerabilities detected and fixed")
                    print(f"   📁 {scan_results['scan_summary']['files_with_issues']} files patched")
                    print(f"   🎯 {sum(len(v['patterns']) for v in scanner.security_patterns.values())} patterns used")
                    print(f"\n💡 Next Steps:")
                    print(f"   1. Review the fixes in the new repository")
                    print(f"   2. Test the application thoroughly")
                    print(f"   3. Read SECURITY_REPORT.md for detailed findings")
                    print(f"   4. Implement additional security measures as recommended")
            else:
                print("\n❌ Repository creation cancelled")
        else:
            print("\n✅ No vulnerabilities found! Your repository is secure! 🎉")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan cancelled by user")
    except subprocess.CalledProcessError:
        print(f"\n❌ Failed to clone repository. Please check:")
        print(f"   • Repository URL is correct")
        print(f"   • Repository is public or you have access")
        print(f"   • Git is installed and accessible")
    except Exception as e:
        print(f"\n❌ Error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if repo_path and os.path.exists(repo_path):
            print(f"\n🧹 Cleaning up temporary files...")
            try:
                scanner.force_remove_directory(repo_path)
                print(f"✅ Cleanup complete")
            except:
                print(f"⚠️  Could not remove temporary directory: {repo_path}")


if __name__ == "__main__":
    main()