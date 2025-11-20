"""
OpenAI Integration for CyberShield AI
This module provides AI-powered analysis and report generation using OpenAI
"""

import json
import logging
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("OpenAI library not installed. AI analysis will be disabled.")


class OpenAIAnalyzer:
    """OpenAI-powered security analysis and report generation"""
    
    def __init__(self, api_key: str = None, model: str = "gpt-4", temperature: float = 0.7):
        """
        Initialize OpenAI Analyzer
        
        Args:
            api_key: OpenAI API key
            model: OpenAI model to use (default: gpt-4)
            temperature: Temperature for generation (default: 0.7)
        """
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.client = None
        self.is_available = False
        
        if OPENAI_AVAILABLE and api_key:
            try:
                self.client = OpenAI(api_key=api_key)
                # Test connection with a simple request
                self.is_available = True
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {str(e)}")
                self.is_available = False
        else:
            self.is_available = False
    
    def analyze_scan_results(self, scan_data: Dict, headers: Dict, zap_results: Optional[Dict] = None) -> Dict:
        """
        Analyze scan results using OpenAI and generate professional insights
        
        Args:
            scan_data: Basic scan data (URL, status_code, etc.)
            headers: HTTP headers dictionary
            zap_results: ZAP scan results (optional)
            
        Returns:
            Dictionary containing AI analysis and recommendations
        """
        if not self.is_available or not self.client:
            return {"error": "OpenAI is not configured or available"}
        
        try:
            # Prepare context for OpenAI
            context = self._prepare_context(scan_data, headers, zap_results)
            
            # Create prompt for analysis
            prompt = self._create_analysis_prompt(context)
            
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a professional cybersecurity analyst with expertise in web application security, vulnerability assessment, and security best practices. Provide detailed, actionable security analysis and recommendations."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.temperature,
                max_tokens=2000
            )
            
            # Parse response
            ai_analysis = response.choices[0].message.content
            
            # Generate structured report
            structured_report = self._generate_structured_report(scan_data, headers, zap_results, ai_analysis)
            
            return {
                "success": True,
                "ai_analysis": ai_analysis,
                "structured_report": structured_report,
                "model_used": self.model
            }
            
        except Exception as e:
            logger.error(f"OpenAI analysis error: {str(e)}")
            return {"error": f"Failed to analyze with OpenAI: {str(e)}"}
    
    def _prepare_context(self, scan_data: Dict, headers: Dict, zap_results: Optional[Dict] = None) -> str:
        """Prepare context string from scan data"""
        context_parts = []
        
        # Basic scan information
        context_parts.append(f"Target URL: {scan_data.get('url', 'N/A')}")
        context_parts.append(f"HTTP Status Code: {scan_data.get('status_code', 'N/A')}")
        context_parts.append(f"Scan Date: {scan_data.get('scan_date', 'N/A')}")
        
        # HTTP Headers
        context_parts.append("\nHTTP Headers:")
        security_headers = ['content-security-policy', 'x-frame-options', 'x-content-type-options', 
                           'strict-transport-security', 'x-xss-protection', 'referrer-policy', 
                           'permissions-policy', 'server', 'x-powered-by']
        
        for header_name, header_value in headers.items():
            if header_name.lower() in security_headers:
                context_parts.append(f"  [SECURITY] {header_name}: {header_value}")
            else:
                context_parts.append(f"  {header_name}: {header_value}")
        
        # ZAP Results
        if zap_results and 'summary' in zap_results:
            zap_summary = zap_results['summary']
            context_parts.append(f"\nOWASP ZAP Scan Results:")
            context_parts.append(f"  Total Alerts: {zap_summary.get('total_alerts', 0)}")
            context_parts.append(f"  High Risk: {zap_summary.get('high_risk', 0)}")
            context_parts.append(f"  Medium Risk: {zap_summary.get('medium_risk', 0)}")
            context_parts.append(f"  Low Risk: {zap_summary.get('low_risk', 0)}")
            
            # Include key alerts
            if zap_summary.get('alerts'):
                context_parts.append("\nKey Security Alerts:")
                for alert in zap_summary['alerts'][:20]:  # First 20 alerts
                    context_parts.append(f"  [{alert.get('risk', 'Unknown')}] {alert.get('name', 'Unknown')}: {alert.get('description', '')[:200]}")
        
        return "\n".join(context_parts)
    
    def _create_analysis_prompt(self, context: str) -> str:
        """Create analysis prompt for OpenAI"""
        return f"""Analyze the following web security scan results and provide a comprehensive professional security assessment report.

{context}

Please provide:
1. Executive Summary: A brief overview of the security posture
2. Critical Findings: List the most critical security issues found
3. Security Headers Analysis: Detailed analysis of HTTP security headers
4. Vulnerability Assessment: If ZAP results are available, analyze the vulnerabilities
5. Risk Assessment: Overall risk level and justification
6. Recommendations: Prioritized, actionable recommendations for remediation
7. Best Practices: Additional security best practices to implement

Format the response in a clear, professional manner suitable for a security audit report."""
    
    def _generate_structured_report(self, scan_data: Dict, headers: Dict, zap_results: Optional[Dict], ai_analysis: str) -> Dict:
        """Generate structured report from AI analysis"""
        return {
            "executive_summary": self._extract_section(ai_analysis, "Executive Summary"),
            "critical_findings": self._extract_section(ai_analysis, "Critical Findings"),
            "security_headers_analysis": self._extract_section(ai_analysis, "Security Headers Analysis"),
            "vulnerability_assessment": self._extract_section(ai_analysis, "Vulnerability Assessment"),
            "risk_assessment": self._extract_section(ai_analysis, "Risk Assessment"),
            "recommendations": self._extract_section(ai_analysis, "Recommendations"),
            "best_practices": self._extract_section(ai_analysis, "Best Practices"),
            "full_analysis": ai_analysis
        }
    
    def _extract_section(self, text: str, section_name: str) -> str:
        """Extract a specific section from the AI analysis"""
        try:
            lines = text.split('\n')
            in_section = False
            section_lines = []
            
            for line in lines:
                if section_name.lower() in line.lower() and (':' in line or line.strip().startswith('#')):
                    in_section = True
                    continue
                
                if in_section:
                    # Check if we've reached the next section
                    if any(keyword in line.lower() for keyword in ['executive', 'critical', 'security headers', 'vulnerability', 'risk assessment', 'recommendations', 'best practices']) and (':' in line or line.strip().startswith('#')):
                        if section_name.lower() not in line.lower():
                            break
                    
                    section_lines.append(line)
            
            return '\n'.join(section_lines).strip() if section_lines else "Not available in analysis"
        except:
            return "Error extracting section"


def create_openai_analyzer(api_key: str = None, model: str = "gpt-4", temperature: float = 0.7) -> Optional[OpenAIAnalyzer]:
    """Factory function to create OpenAI Analyzer instance"""
    if not OPENAI_AVAILABLE:
        return None
    
    if not api_key:
        return None
    
    return OpenAIAnalyzer(api_key=api_key, model=model, temperature=temperature)


if __name__ == "__main__":
    # Example usage
    analyzer = create_openai_analyzer(api_key="your-api-key-here")
    if analyzer and analyzer.is_available:
        print("OpenAI Analyzer is ready!")
    else:
        print("OpenAI Analyzer is not available. Please check API key and configuration.")



