"""
PDF and report generation utilities.
"""
from fpdf import FPDF
from datetime import datetime
from typing import List, Dict
from config import REPORTS_DIR
import logging

logger = logging.getLogger(__name__)


class SecurityReportPDF(FPDF):
    """Enhanced PDF report generator for security audits."""
    
    def header(self):
        """Add header to each page."""
        self.set_font('Helvetica', 'B', 16)
        self.set_text_color(30, 144, 255)  # Blue color
        self.cell(0, 10, 'Gemini-Powered Web Security Audit Report', 0, 1, 'C')
        self.set_text_color(0, 0, 0)  # Black
        self.set_font('Helvetica', '', 10)
        self.cell(0, 5, f'Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        """Add footer to each page."""
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title, size=12):
        """Add a chapter title."""
        self.set_font('Helvetica', 'B', size)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 10, title, 0, 1, 'L', True)
        self.ln(2)

    def chapter_body(self, body):
        """Add body text, handling encoding."""
        self.set_font('Helvetica', '', 10)
        try:
            # Try to encode to latin-1, replace unencodable characters
            encoded_body = body.encode('latin-1', 'replace').decode('latin-1')
            self.multi_cell(0, 5, encoded_body)
        except Exception as e:
            logger.warning(f"Encoding error in PDF: {e}")
            # Fallback: remove problematic characters
            safe_body = ''.join(char if ord(char) < 256 else '?' for char in body)
            self.multi_cell(0, 5, safe_body)
        self.ln()

    def add_vulnerability_entry(self, vuln: Dict, analysis_data: Dict):
        """Add a vulnerability entry to the report."""
        # Vulnerability header
        self.set_font('Helvetica', 'B', 11)
        severity_color = self._get_severity_color(analysis_data.get('severity', 'Unknown'))
        self.set_text_color(*severity_color)
        
        vuln_header = f"{analysis_data.get('id', 'N/A')} - {analysis_data.get('type', 'Unknown')}"
        severity_text = f"Severity: {analysis_data.get('severity', 'Unknown')} | CVSS: {analysis_data.get('cvss', 0.0)}"
        self.cell(0, 8, vuln_header, ln=1)
        self.cell(0, 8, severity_text, ln=1)
        self.set_text_color(0, 0, 0)  # Reset to black
        
        # Vulnerability details
        self.set_font('Helvetica', 'I', 9)
        input_text = f"Input Snippet: {vuln.get('input', 'N/A')[:80]}"
        self.multi_cell(0, 5, self._safe_encode(input_text))
        
        desc_text = f"Description: {vuln.get('description', 'N/A')}"
        self.multi_cell(0, 5, self._safe_encode(desc_text))
        self.ln(2)
        
        # Justification
        self.set_font('Helvetica', 'B', 10)
        self.cell(0, 8, "Justification:", ln=1)
        self.set_font('Helvetica', '', 10)
        self.chapter_body(analysis_data.get('justification', 'N/A'))
        
        # Impact (if available)
        if analysis_data.get('impact'):
            self.set_font('Helvetica', 'B', 10)
            self.cell(0, 8, "Impact:", ln=1)
            self.set_font('Helvetica', '', 10)
            self.chapter_body(analysis_data.get('impact'))
        
        # Remediation
        self.set_font('Helvetica', 'B', 10)
        self.cell(0, 8, "Remediation:", ln=1)
        self.set_font('Helvetica', '', 10)
        self.chapter_body(analysis_data.get('remediation', 'N/A'))
        
        self.ln(5)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)
    
    def _get_severity_color(self, severity: str) -> tuple:
        """Get color tuple based on severity level."""
        colors = {
            "Critical": (220, 20, 60),    # Crimson
            "High": (255, 140, 0),        # Dark Orange
            "Medium": (255, 215, 0),      # Gold
            "Low": (50, 205, 50),         # Lime Green
            "Unknown": (128, 128, 128)    # Gray
        }
        return colors.get(severity, (128, 128, 128))
    
    def _safe_encode(self, text: str) -> str:
        """Safely encode text for PDF."""
        try:
            return text.encode('latin-1', 'replace').decode('latin-1')
        except:
            return ''.join(char if ord(char) < 256 else '?' for char in text)


class ReportGenerator:
    """Generates security audit reports."""
    
    def __init__(self):
        self.reports_dir = REPORTS_DIR
    
    def create_pdf_report(self, vulnerabilities: List[Dict], analyzed_data: List[Dict], 
                         audit_id: str = None) -> bytes:
        """
        Generate a PDF report from vulnerabilities and analysis.
        
        Args:
            vulnerabilities: List of vulnerability findings
            analyzed_data: List of analyzed vulnerability data
            audit_id: Optional audit identifier
        
        Returns:
            PDF file as bytes
        """
        pdf = SecurityReportPDF()
        pdf.add_page()

        # Executive Summary
        pdf.chapter_title('1. Executive Summary', size=14)
        total_vulns = len(vulnerabilities)
        critical_count = sum(1 for a in analyzed_data if a.get('severity') == 'Critical')
        high_count = sum(1 for a in analyzed_data if a.get('severity') == 'High')
        medium_count = sum(1 for a in analyzed_data if a.get('severity') == 'Medium')
        low_count = sum(1 for a in analyzed_data if a.get('severity') == 'Low')
        
        summary_text = (
            f"This security audit report details {total_vulns} vulnerabilities discovered through "
            f"dynamic security testing and fuzzing. Each finding has been analyzed using Google's "
            f"Gemini AI to provide detailed assessments, risk ratings, and actionable remediation advice.\n\n"
            f"Severity Breakdown:\n"
            f"• Critical: {critical_count}\n"
            f"• High: {high_count}\n"
            f"• Medium: {medium_count}\n"
            f"• Low: {low_count}\n\n"
            f"Organizations should prioritize remediation based on the assigned severity levels and "
            f"CVSS scores. Critical and High severity vulnerabilities should be addressed immediately."
        )
        
        if audit_id:
            summary_text += f"\n\nAudit ID: {audit_id}"
        
        pdf.chapter_body(summary_text)
        pdf.ln(5)

        # Vulnerability Statistics
        pdf.chapter_title('2. Vulnerability Statistics', size=14)
        stats_text = (
            f"Total Vulnerabilities Found: {total_vulns}\n"
            f"Average CVSS Score: {sum(a.get('cvss', 0) for a in analyzed_data) / max(total_vulns, 1):.2f}\n"
            f"Highest CVSS Score: {max((a.get('cvss', 0) for a in analyzed_data), default=0):.2f}\n"
            f"Lowest CVSS Score: {min((a.get('cvss', 0) for a in analyzed_data), default=0):.2f}"
        )
        pdf.chapter_body(stats_text)
        pdf.ln(5)

        # Detailed Findings
        pdf.chapter_title('3. Detailed Vulnerability Findings', size=14)
        for vuln, analysis in zip(vulnerabilities, analyzed_data):
            pdf.add_vulnerability_entry(vuln, analysis)
            # Add new page if near the end
            if pdf.get_y() > 250:
                pdf.add_page()

        # Recommendations
        pdf.chapter_title('4. Recommendations', size=14)
        recommendations = (
            "1. Immediately address all Critical and High severity vulnerabilities.\n\n"
            "2. Implement secure coding practices and security training for development teams.\n\n"
            "3. Establish regular security audits and penetration testing schedules.\n\n"
            "4. Implement automated security testing in CI/CD pipelines.\n\n"
            "5. Review and update security policies and procedures.\n\n"
            "6. Consider implementing a Web Application Firewall (WAF) for additional protection.\n\n"
            "7. Ensure all dependencies and libraries are kept up to date with security patches."
        )
        pdf.chapter_body(recommendations)

        return pdf.output(dest='S').encode('latin-1')
    
    def save_pdf_report(self, vulnerabilities: List[Dict], analyzed_data: List[Dict], 
                       audit_id: str = None) -> str:
        """Save PDF report to file and return file path."""
        pdf_bytes = self.create_pdf_report(vulnerabilities, analyzed_data, audit_id)
        filename = f"security_audit_{audit_id or datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = self.reports_dir / filename
        
        with open(filepath, 'wb') as f:
            f.write(pdf_bytes)
        
        logger.info(f"PDF report saved to {filepath}")
        return str(filepath)

