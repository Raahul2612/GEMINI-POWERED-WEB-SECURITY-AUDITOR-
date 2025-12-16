"""
Enhanced fuzzing engine for security testing.
"""
import requests
import logging
import time
from typing import List, Dict, Optional
from threading import Thread, Lock
from contextlib import contextmanager
from flask import Flask, request, jsonify
from config import FLASK_HOST, FLASK_PORT, REQUEST_TIMEOUT
from payloads import PayloadGenerator

logger = logging.getLogger(__name__)

# Global flag and lock for Flask server
flask_running = False
flask_lock = Lock()

# Create Flask app for vulnerable endpoints
app = Flask(__name__)

@app.route('/checkout', methods=['POST'])
def checkout():
    """Mock API endpoint with simulated vulnerabilities."""
    try:
        data = request.json or {}
        user_input = data.get('input', '')
        
        # SQL injection check
        sql_patterns = ["' OR '", "1=1", "UNION SELECT", "DROP TABLE", "SLEEP("]
        if any(pattern.lower() in str(user_input).lower() for pattern in sql_patterns):
            return jsonify({"error": "SQL injection detected", "type": "SQLi"}), 400
        
        # XSS check
        xss_patterns = ["<script>", "<img", "<svg", "onerror=", "onload=", "javascript:", "<iframe"]
        if any(pattern.lower() in str(user_input).lower() for pattern in xss_patterns):
            return jsonify({"error": "XSS detected", "type": "XSS"}), 400
        
        # Command injection check
        cmd_patterns = [";", "|", "&&", "||", "`"]
        if any(pattern in str(user_input) for pattern in cmd_patterns):
            return jsonify({"error": "Command injection detected", "type": "Command Injection"}), 400
        
        # Path traversal check
        path_patterns = ["../", "..\\", "%2e%2e", "....//"]
        if any(pattern in str(user_input) for pattern in path_patterns):
            return jsonify({"error": "Path traversal detected", "type": "Path Traversal"}), 400
        
        # Buffer overflow simulation
        if len(str(user_input)) > 1000:
            return jsonify({"error": "Buffer overflow detected", "type": "Buffer Overflow"}), 400
        
        # CSRF check
        if 'csrf_token' not in data or not data.get('csrf_token'):
            return jsonify({"error": "CSRF token missing or invalid", "type": "CSRF"}), 403
        
        # IDOR check
        user_id = data.get('user_id', '')
        if not str(user_id).isdigit() or int(user_id) < 1 or int(user_id) > 1000:
            return jsonify({"error": "Invalid user reference (IDOR)", "type": "IDOR"}), 403
        
        # Session fixation check
        session_id = data.get('session_id', '')
        if len(str(session_id)) < 10 or not session_id.isalnum():
            return jsonify({"error": "Weak or invalid session detected", "type": "Session Fixation"}), 400
        
        # LDAP injection check
        ldap_patterns = ["*)(&", "*))%00", "*()|&"]
        if any(pattern in str(user_input) for pattern in ldap_patterns):
            return jsonify({"error": "LDAP injection detected", "type": "LDAP Injection"}), 400
        
        return jsonify({"status": "success", "message": "Checkout processed"}), 200
    except Exception as e:
        logger.error(f"Checkout endpoint error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@contextmanager
def flask_server_context():
    """Context manager to safely start and stop Flask server."""
    global flask_running
    with flask_lock:
        if flask_running:
            yield
            return
        flask_running = True

    flask_thread = Thread(target=lambda: app.run(
        host=FLASK_HOST, 
        port=FLASK_PORT, 
        debug=False, 
        use_reloader=False
    ))
    flask_thread.daemon = True
    flask_thread.start()
    time.sleep(2)  # Give server time to start
    logger.info(f"Flask server started on {FLASK_HOST}:{FLASK_PORT}")
    
    try:
        yield
    finally:
        logger.info("Flask server context finished.")
        with flask_lock:
            flask_running = False


class Fuzzer:
    """Enhanced fuzzing engine for security testing."""
    
    def __init__(self, target_url: str = None):
        self.target_url = target_url or f"http://{FLASK_HOST}:{FLASK_PORT}/checkout"
        self.payload_generator = PayloadGenerator()
    
    def fuzz_input(self, num_tests: int = 20, custom_inputs: Optional[List[str]] = None, 
                   test_types: Optional[List[str]] = None) -> List[Dict]:
        """
        Generate and send fuzzing payloads to find vulnerabilities.
        
        Args:
            num_tests: Number of tests to run
            custom_inputs: Custom input strings to test
            test_types: List of vulnerability types to test (None = all)
        
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        base_payloads = self._generate_base_payloads(custom_inputs, test_types)
        
        with flask_server_context():
            for i, test_case in enumerate(base_payloads[:num_tests]):
                try:
                    payload = test_case["input"]
                    response = requests.post(
                        self.target_url, 
                        json=payload, 
                        timeout=REQUEST_TIMEOUT
                    )

                    if response.status_code != 200:
                        error_data = response.json() if response.content else {}
                        error_msg = error_data.get("error", "Unknown error")
                        vuln_type = error_data.get("type", "Unknown")
                        
                        if not vuln_type or vuln_type == "Unknown":
                            vuln_type = self._classify_vulnerability(error_msg)
                        
                        input_str = str(payload.get("input", ""))[:100]
                        vulnerabilities.append({
                            "id": f"VULN-{i+1:03d}",
                            "input": input_str,
                            "type": vuln_type,
                            "description": f"Detected {vuln_type}: {error_msg}",
                            "status_code": response.status_code
                        })
                    
                    logger.info(f"Fuzzing test {i+1}/{num_tests}: Status {response.status_code}")
                    
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Fuzzing request {i+1} failed: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error in fuzzing test {i+1}: {e}")

        return vulnerabilities
    
    def _generate_base_payloads(self, custom_inputs: Optional[List[str]] = None,
                                test_types: Optional[List[str]] = None) -> List[Dict]:
        """Generate base payloads for testing."""
        payloads = []
        all_payloads = self.payload_generator.get_all_payloads()
        
        # Default valid payload
        base_valid = {
            "input": "normal_test_input",
            "user_id": "5",
            "session_id": "long_valid_session_id_12345",
            "csrf_token": "valid_csrf_token_abc123"
        }
        
        # SQL Injection tests
        if not test_types or "sql_injection" in test_types:
            for payload in self.payload_generator.SQL_INJECTION[:5]:
                test_payload = base_valid.copy()
                test_payload["input"] = payload
                payloads.append({"input": test_payload, "expected": "sql_injection"})
        
        # XSS tests
        if not test_types or "xss" in test_types:
            for payload in self.payload_generator.XSS_PAYLOADS[:5]:
                test_payload = base_valid.copy()
                test_payload["input"] = payload
                payloads.append({"input": test_payload, "expected": "xss"})
        
        # Buffer overflow tests
        if not test_types or "buffer_overflow" in test_types:
            for payload in self.payload_generator.BUFFER_OVERFLOW[:3]:
                test_payload = base_valid.copy()
                test_payload["input"] = "".join(payload) if isinstance(payload, list) else payload
                payloads.append({"input": test_payload, "expected": "buffer_overflow"})
        
        # CSRF tests
        if not test_types or "csrf" in test_types:
            for payload_config in self.payload_generator.CSRF_PAYLOADS:
                test_payload = base_valid.copy()
                test_payload.update(payload_config)
                payloads.append({"input": test_payload, "expected": "csrf"})
        
        # IDOR tests
        if not test_types or "idor" in test_types:
            for payload_config in self.payload_generator.IDOR_PAYLOADS:
                test_payload = base_valid.copy()
                test_payload.update(payload_config)
                payloads.append({"input": test_payload, "expected": "idor"})
        
        # Session fixation tests
        if not test_types or "session_fixation" in test_types:
            for payload_config in self.payload_generator.SESSION_PAYLOADS:
                test_payload = base_valid.copy()
                test_payload.update(payload_config)
                payloads.append({"input": test_payload, "expected": "session_fixation"})
        
        # Command injection tests
        if not test_types or "command_injection" in test_types:
            for payload in self.payload_generator.COMMAND_INJECTION[:3]:
                test_payload = base_valid.copy()
                test_payload["input"] = payload
                payloads.append({"input": test_payload, "expected": "command_injection"})
        
        # Add custom inputs
        if custom_inputs:
            for custom_input in custom_inputs:
                test_payload = base_valid.copy()
                test_payload["input"] = custom_input
                payloads.append({"input": test_payload, "expected": "custom"})
        
        return payloads
    
    def _classify_vulnerability(self, error_msg: str) -> str:
        """Classify vulnerability type from error message."""
        error_lower = error_msg.lower()
        if "sql" in error_lower:
            return "SQL Injection"
        elif "xss" in error_lower:
            return "XSS"
        elif "buffer" in error_lower or "overflow" in error_lower:
            return "Buffer Overflow"
        elif "csrf" in error_lower:
            return "CSRF"
        elif "idor" in error_lower:
            return "IDOR"
        elif "session" in error_lower:
            return "Session Fixation"
        elif "command" in error_lower:
            return "Command Injection"
        elif "path" in error_lower or "traversal" in error_lower:
            return "Path Traversal"
        elif "ldap" in error_lower:
            return "LDAP Injection"
        else:
            return "Unknown"

