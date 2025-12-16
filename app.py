"""
Main Streamlit application for Gemini-Powered Web Security Auditor.
"""
import streamlit as st
import pandas as pd
import logging
import uuid
from datetime import datetime
from typing import List, Dict
import plotly.express as px
import plotly.graph_objects as go

from config import CVE_DATA_FILE, GEMINI_API_KEY, DEFAULT_FUZZ_TESTS, MAX_FUZZ_TESTS
from fuzzer import Fuzzer
from analyzer import VulnerabilityAnalyzer
from reporter import ReportGenerator
from database import db_manager
import json
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def init_session_state():
    """Initialize Streamlit session state variables."""
    if "vulnerabilities" not in st.session_state:
        st.session_state.vulnerabilities = []
    if "analyzed_data" not in st.session_state:
        st.session_state.analyzed_data = []
    if "audit_id" not in st.session_state:
        st.session_state.audit_id = None
    if "fuzzer" not in st.session_state:
        st.session_state.fuzzer = Fuzzer()
    if "analyzer" not in st.session_state:
        st.session_state.analyzer = VulnerabilityAnalyzer()


def save_cve_dataset():
    """Save initial CVE dataset if it doesn't exist."""
    if not os.path.exists(CVE_DATA_FILE):
        cve_data = [
            {"id": "CVE-2025-001", "description": "SQL injection in checkout endpoint", 
             "type": "SQLi", "severity": "High", "cvss_score": 7.5},
            {"id": "CVE-2025-002", "description": "XSS in user input field", 
             "type": "XSS", "severity": "Medium", "cvss_score": 5.4},
            {"id": "CVE-2025-003", "description": "Buffer overflow in payment processing", 
             "type": "Buffer Overflow", "severity": "Critical", "cvss_score": 9.8},
            {"id": "CVE-2025-004", "description": "CSRF in authentication flow", 
             "type": "CSRF", "severity": "Medium", "cvss_score": 6.5},
            {"id": "CVE-2025-005", "description": "Insecure direct object reference in user profile", 
             "type": "IDOR", "severity": "High", "cvss_score": 8.1},
            {"id": "CVE-2025-006", "description": "Weak session management", 
             "type": "Session Fixation", "severity": "Low", "cvss_score": 3.7}
        ]
        try:
            os.makedirs(os.path.dirname(CVE_DATA_FILE), exist_ok=True)
            with open(CVE_DATA_FILE, "w") as f:
                json.dump(cve_data, f, indent=4)
            logger.info("CVE dataset saved")
        except Exception as e:
            logger.error(f"Error saving CVE dataset: {e}")


def main():
    """Main application function."""
    st.set_page_config(
        page_title="Gemini Security Auditor",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    .stButton>button {
        width: 100%;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown('<p class="main-header">🔒 Gemini-Powered Web Security Audit Tool</p>', 
                unsafe_allow_html=True)
    st.markdown("""
    <div style='text-align: center; color: #666; margin-bottom: 2rem;'>
    Advanced security testing using AI-powered vulnerability analysis and dynamic fuzzing
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize session state
    init_session_state()
    save_cve_dataset()
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # API Key input
        api_key = st.text_input(
            "Google AI API Key",
            value=GEMINI_API_KEY,
            type="password",
            help="Get your API key from https://makersuite.google.com/app/apikey"
        )
        
        if api_key and api_key != GEMINI_API_KEY:
            st.session_state.analyzer = VulnerabilityAnalyzer(api_key=api_key)
        
        st.divider()
        
        # Fuzzing configuration
        st.subheader("🧪 Fuzzing Settings")
        num_tests = st.slider(
            "Number of Tests",
            min_value=5,
            max_value=MAX_FUZZ_TESTS,
            value=DEFAULT_FUZZ_TESTS,
            help=f"Maximum {MAX_FUZZ_TESTS} tests allowed"
        )
        
        # Vulnerability type selection
        test_types = st.multiselect(
            "Vulnerability Types to Test",
            options=["sql_injection", "xss", "buffer_overflow", "csrf", "idor", 
                    "session_fixation", "command_injection", "path_traversal"],
            default=["sql_injection", "xss", "csrf", "idor"],
            help="Select which vulnerability types to test for"
        )
        
        # Custom inputs
        custom_input = st.text_area(
            "Custom Test Inputs",
            height=100,
            placeholder="Enter custom payloads (one per line):\n<svg onload=alert(1)>\n' or 1=1--",
            help="Add custom payloads to test against the target"
        )
        
        st.divider()
        
        # Action buttons
        if st.button("🚀 Run Security Audit", type="primary", use_container_width=True):
            if not api_key:
                st.warning("⚠️ Please enter your Google AI API key to use AI-powered analysis")
            
            custom_inputs = [line.strip() for line in custom_input.split('\n') if line.strip()] if custom_input else None
            
            # Generate audit ID
            audit_id = str(uuid.uuid4())[:8]
            st.session_state.audit_id = audit_id
            
            # Run fuzzing
            with st.spinner(f"🔍 Running {num_tests} security tests..."):
                vulns = st.session_state.fuzzer.fuzz_input(
                    num_tests=num_tests,
                    custom_inputs=custom_inputs,
                    test_types=test_types if test_types else None
                )
                st.session_state.vulnerabilities = vulns
            
            # Analyze vulnerabilities
            if vulns:
                analyzed_results = []
                with st.spinner("🤖 AI is analyzing findings..."):
                    progress_bar = st.progress(0)
                    for i, vuln in enumerate(st.session_state.vulnerabilities):
                        severity, cvss, justif, remed, vtype, impact, likelihood = \
                            st.session_state.analyzer.rate_vulnerability(vuln["description"])
                        
                        analyzed_results.append({
                            "id": vuln["id"],
                            "type": vtype,
                            "severity": severity,
                            "cvss": cvss,
                            "input": vuln["input"],
                            "description": vuln["description"],
                            "justification": justif,
                            "remediation": remed,
                            "impact": impact,
                            "likelihood": likelihood
                        })
                        progress_bar.progress((i + 1) / len(vulns))
                    
                    progress_bar.empty()
                
                st.session_state.analyzed_data = analyzed_results
                
                # Save to database
                try:
                    db_manager.save_audit_results(audit_id, analyzed_results)
                    st.success(f"✅ Audit complete! Found {len(vulns)} vulnerabilities. Results saved.")
                except Exception as e:
                    logger.error(f"Error saving to database: {e}")
                    st.success(f"✅ Audit complete! Found {len(vulns)} vulnerabilities.")
            else:
                st.info("ℹ️ No vulnerabilities detected in this audit.")
            
            st.rerun()
        
        st.divider()
        
        # Report download
        if st.session_state.analyzed_data:
            report_generator = ReportGenerator()
            pdf_data = report_generator.create_pdf_report(
                st.session_state.vulnerabilities,
                st.session_state.analyzed_data,
                st.session_state.audit_id
            )
            
            st.download_button(
                label="📥 Download PDF Report",
                data=pdf_data,
                file_name=f"security_audit_{st.session_state.audit_id or datetime.now().strftime('%Y%m%d')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        
        # Clear results
        if st.button("🗑️ Clear Results", use_container_width=True):
            st.session_state.vulnerabilities = []
            st.session_state.analyzed_data = []
            st.session_state.audit_id = None
            st.rerun()
    
    # Main content area
    if st.session_state.analyzed_data:
        # Metrics dashboard
        st.header("📊 Audit Overview")
        
        df = pd.DataFrame(st.session_state.analyzed_data)
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Vulnerabilities", len(df))
        with col2:
            critical_count = len(df[df['severity'] == 'Critical'])
            st.metric("Critical", critical_count, delta=None if critical_count == 0 else f"+{critical_count}")
        with col3:
            high_count = len(df[df['severity'] == 'High'])
            st.metric("High", high_count)
        with col4:
            avg_cvss = df['cvss'].mean()
            st.metric("Avg CVSS Score", f"{avg_cvss:.2f}")
        
        st.divider()
        
        # Data table
        st.header("📋 Vulnerability Findings")
        st.dataframe(
            df[['id', 'type', 'severity', 'cvss', 'input', 'description']],
            use_container_width=True,
            hide_index=True
        )
        
        st.divider()
        
        # Analytics charts
        st.header("📈 Analytics Dashboard")
        
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            st.subheader("Severity Distribution")
            severity_counts = df['severity'].value_counts()
            fig_severity = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                color_discrete_map={
                    'Critical': '#DC143C',
                    'High': '#FF8C00',
                    'Medium': '#FFD700',
                    'Low': '#32CD32'
                }
            )
            fig_severity.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig_severity, use_container_width=True)
        
        with col_chart2:
            st.subheader("Vulnerability Type Breakdown")
            type_counts = df['type'].value_counts()
            fig_type = px.bar(
                x=type_counts.index,
                y=type_counts.values,
                labels={'x': 'Vulnerability Type', 'y': 'Count'},
                color=type_counts.values,
                color_continuous_scale='Reds'
            )
            st.plotly_chart(fig_type, use_container_width=True)
        
        # CVSS Score distribution
        st.subheader("CVSS Score Distribution")
        fig_cvss = px.histogram(
            df,
            x='cvss',
            nbins=20,
            labels={'cvss': 'CVSS Score', 'count': 'Number of Vulnerabilities'},
            color='severity',
            color_discrete_map={
                'Critical': '#DC143C',
                'High': '#FF8C00',
                'Medium': '#FFD700',
                'Low': '#32CD32'
            }
        )
        st.plotly_chart(fig_cvss, use_container_width=True)
        
        st.divider()
        
        # Detailed findings
        st.header("🔍 Detailed Findings & Remediation")
        
        for item in st.session_state.analyzed_data:
            severity_color = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            }.get(item['severity'], '⚪')
            
            with st.expander(
                f"{severity_color} **{item['id']}: {item['type']}** "
                f"(Severity: {item['severity']}, CVSS: {item['cvss']})"
            ):
                col_left, col_right = st.columns(2)
                
                with col_left:
                    st.markdown(f"**Input Snippet:**")
                    st.code(item['input'], language='text')
                    
                    st.markdown(f"**Description:**")
                    st.info(item['description'])
                    
                    if item.get('impact'):
                        st.markdown(f"**Impact:**")
                        st.warning(item['impact'])
                    
                    if item.get('likelihood'):
                        st.markdown(f"**Likelihood of Exploitation:** {item['likelihood']}")
                
                with col_right:
                    st.markdown(f"**Justification:**")
                    st.info(item['justification'])
                    
                    st.markdown(f"**Remediation Advice:**")
                    st.success(item['remediation'])
    else:
        # Welcome screen
        st.info("👈 Configure your settings and run a security audit from the sidebar to begin.")
        
        # Show example features
        with st.expander("📖 How to Use"):
            st.markdown("""
            1. **Enter API Key**: Get your Google AI API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
            2. **Configure Tests**: Select the number of tests and vulnerability types
            3. **Add Custom Payloads** (optional): Add your own test payloads
            4. **Run Audit**: Click "Run Security Audit" to start testing
            5. **Review Results**: Analyze findings with AI-powered insights
            6. **Download Report**: Generate a comprehensive PDF report
            """)
        
        with st.expander("🛡️ Vulnerability Types Detected"):
            st.markdown("""
            - **SQL Injection**: Database query manipulation attacks
            - **XSS**: Cross-site scripting attacks
            - **CSRF**: Cross-site request forgery
            - **IDOR**: Insecure direct object references
            - **Buffer Overflow**: Memory corruption attacks
            - **Command Injection**: OS command execution
            - **Path Traversal**: Directory traversal attacks
            - **Session Fixation**: Weak session management
            """)
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666;'>"
        "**© 2025 Gemini-Powered Web Security Auditor** | Built with Streamlit & Google Gemini AI"
        "</div>",
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()

