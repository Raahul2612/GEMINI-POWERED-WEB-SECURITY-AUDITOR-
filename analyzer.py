"""
Vulnerability analysis using Gemini AI and fallback ML models.
"""
import logging
import json
import google.generativeai as genai
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from config import GEMINI_API_KEY, GEMINI_MODEL
import streamlit as st

logger = logging.getLogger(__name__)


@st.cache_resource
def _train_fallback_classifier():
    """Train fallback ML classifier for severity rating."""
    descriptions = [
        "SQL injection", "XSS cross-site scripting", "Buffer overflow",
        "CSRF cross-site request forgery", "IDOR insecure direct object reference",
        "Weak session management", "Command injection", "Path traversal",
        "LDAP injection", "XXE XML external entity", "Template injection"
    ]
    severities = ["High", "Medium", "Critical", "Medium", "High", "Low", "High", "Medium", "Medium", "High", "Medium"]
    
    vectorizer = TfidfVectorizer(max_features=100)
    X = vectorizer.fit_transform(descriptions)
    y = [severities.index(s) for s in severities]
    
    clf = MultinomialNB()
    clf.fit(X, y)
    
    return clf, vectorizer, severities


class VulnerabilityAnalyzer:
    """Analyzes vulnerabilities using AI and ML models."""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or GEMINI_API_KEY
        if self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel(GEMINI_MODEL)
                self.gemini_available = True
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini: {e}")
                self.gemini_available = False
        else:
            self.gemini_available = False
    
    def analyze_vulnerability_with_gemini(self, description: str) -> dict:
        """
        Analyze vulnerability using Gemini API.
        
        Args:
            description: Vulnerability description
        
        Returns:
            Dictionary with analysis results or None if failed
        """
        if not self.gemini_available:
            return None
        
        try:
            prompt = f"""
You are a cybersecurity expert analyzing web application vulnerabilities. Analyze the following vulnerability finding and provide a detailed assessment.

Vulnerability Description: "{description}"

Provide a comprehensive analysis in JSON format with the following structure:
{{
  "severity": "...",
  "cvss_score": <number>,
  "justification": "...",
  "remediation": "...",
  "impact": "...",
  "likelihood": "..."
}}

Requirements:
- "severity" must be one of: "Low", "Medium", "High", "Critical"
- "cvss_score" must be a number between 0.0 and 10.0 (use CVSS v3.1 scoring guidelines)
- "justification": A concise 2-3 sentence explanation of the risk and why it's rated this way
- "remediation": Clear, actionable recommendations for fixing the vulnerability (2-3 sentences)
- "impact": Describe the potential business/technical impact
- "likelihood": "Low", "Medium", or "High" - likelihood of exploitation

Respond ONLY with valid JSON, no additional text or markdown formatting.
"""

            response = self.model.generate_content(prompt)
            
            # Clean up response text
            response_text = response.text.strip()
            response_text = response_text.replace("```json", "").replace("```", "").strip()
            
            # Try to extract JSON from response
            try:
                result = json.loads(response_text)
                return result
            except json.JSONDecodeError:
                # Try to find JSON object in the response
                start = response_text.find('{')
                end = response_text.rfind('}') + 1
                if start >= 0 and end > start:
                    result = json.loads(response_text[start:end])
                    return result
                raise
            
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            return None
    
    
    def rate_vulnerability(self, description: str) -> tuple:
        """
        Rate vulnerability severity using Gemini or fallback classifier.
        
        Args:
            description: Vulnerability description
        
        Returns:
            Tuple of (severity, cvss_score, justification, remediation, vuln_type, impact, likelihood)
        """
        # Try Gemini first
        gemini_analysis = self.analyze_vulnerability_with_gemini(description)
        
        if gemini_analysis:
            try:
                severity = gemini_analysis.get("severity", "Unknown")
                cvss_score = float(gemini_analysis.get("cvss_score", 0.0))
                justification = gemini_analysis.get("justification", "No justification provided.")
                remediation = gemini_analysis.get("remediation", "No remediation provided.")
                impact = gemini_analysis.get("impact", "Potential security risk.")
                likelihood = gemini_analysis.get("likelihood", "Medium")
                
                # Validate severity
                if severity not in ["Low", "Medium", "High", "Critical"]:
                    severity = "Unknown"
                
                # Validate CVSS score
                if not 0.0 <= cvss_score <= 10.0:
                    cvss_score = 0.0
                    
            except (ValueError, TypeError) as e:
                logger.error(f"Error parsing Gemini response: {e}")
                gemini_analysis = None
        
        # Fallback to ML model if Gemini failed
        if not gemini_analysis:
            clf, vectorizer, severity_map = _train_fallback_classifier()
            X_test = vectorizer.transform([description])
            pred_index = clf.predict(X_test)[0]
            score = clf.predict_proba(X_test).max()
            
            severity = severity_map[pred_index]
            cvss_score = round(2.0 + 2.0 * pred_index + 1.0 * score, 1)
            justification = f"Fallback ML model prediction with {score:.2f} confidence. Review manually for accuracy."
            remediation = "Follow security best practices for this vulnerability type. Consult OWASP guidelines for specific remediation steps."
            impact = "Potential security risk requiring review."
            likelihood = "Medium"
        
        # Determine vulnerability type
        vuln_type = self._classify_vulnerability_type(description)
        
        return severity, cvss_score, justification, remediation, vuln_type, impact, likelihood
    
    def _classify_vulnerability_type(self, description: str) -> str:
        """Classify the type of vulnerability from description."""
        description_lower = description.lower()
        
        type_keywords = {
            "SQL Injection": ["sql", "sql injection", "sqli"],
            "XSS": ["xss", "cross-site scripting", "script injection"],
            "Buffer Overflow": ["buffer overflow", "buffer", "overflow"],
            "CSRF": ["csrf", "cross-site request forgery"],
            "IDOR": ["idor", "insecure direct object reference", "direct object"],
            "Session Fixation": ["session", "session fixation", "weak session"],
            "Command Injection": ["command injection", "command", "cmd"],
            "Path Traversal": ["path traversal", "directory traversal", "../"],
            "LDAP Injection": ["ldap", "ldap injection"],
            "XXE": ["xxe", "xml external entity", "xml injection"],
            "Template Injection": ["template injection", "ssti", "server-side template"]
        }
        
        for vtype, keywords in type_keywords.items():
            if any(keyword in description_lower for keyword in keywords):
                return vtype
        
        return "Unknown"

