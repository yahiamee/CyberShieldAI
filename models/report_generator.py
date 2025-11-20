from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
import sqlite3
import json
from datetime import datetime
import os
import ast
from database import get_setting
from openai_analyzer import create_openai_analyzer

def generate_pdf_report(scan_id, filename=None):
    """Generate a PDF report for a scan result with enhanced error handling"""
    
    # Validate scan_id
    if not isinstance(scan_id, int) or scan_id <= 0:
        raise ValueError("Invalid scan ID")
    
    conn = None
    try:
        conn = sqlite3.connect('cybershield.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, url, status_code, headers, scan_date, zap_results 
            FROM scans 
            WHERE id = ?
        ''', (scan_id,))
        
        scan_data = cursor.fetchone()
        
        if not scan_data:
            raise ValueError("Scan not found")
        
        # Parse zap_results safely
        zap_results = None
        if scan_data[5] and len(scan_data[5]) > 0:
            try:
                zap_results = json.loads(scan_data[5])
            except (json.JSONDecodeError, TypeError) as e:
                # If JSON parsing fails, continue without ZAP results
                zap_results = None
        
        # Parse headers safely
        headers_dict = {}
        if scan_data[3]:
            try:
                # Try to parse as dictionary string
                if isinstance(scan_data[3], str):
                    headers_dict = ast.literal_eval(scan_data[3])
                elif isinstance(scan_data[3], dict):
                    headers_dict = scan_data[3]
            except:
                try:
                    headers_dict = json.loads(scan_data[3])
                except:
                    headers_dict = {}
        
        if filename is None:
            filename = f"reports/scan_report_{scan_id}.pdf"
        
        # Ensure reports directory exists
        reports_dir = os.path.dirname(filename) if os.path.dirname(filename) else 'reports'
        try:
            os.makedirs(reports_dir, exist_ok=True)
        except OSError as e:
            # If directory creation fails, try current directory
            filename = f"scan_report_{scan_id}.pdf"
        
    except sqlite3.Error as e:
        raise Exception(f"Database error: {str(e)}")
    except Exception as e:
        raise
    finally:
        if conn:
            conn.close()
    
    # Generate PDF with error handling
    try:
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1,
            textColor=colors.darkblue
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.darkgreen
        )
        
        heading3_style = ParagraphStyle(
            'Heading3',
            parent=styles['Heading3'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.darkblue,
            fontName='Helvetica-Bold'
        )
        
        normal_style = ParagraphStyle(
            'Normal',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            alignment=TA_JUSTIFY
        )
        
        code_style = ParagraphStyle(
            'Code',
            parent=styles['Code'],
            fontSize=8,
            fontName='Courier',
            leftIndent=0.2*inch,
            rightIndent=0.2*inch,
            backColor=colors.lightgrey
        )
        
        story.append(Paragraph("CyberShield Professional Security Analysis", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        risk_level = determine_risk_level(scan_data, zap_results)
        risk_color = colors.red if risk_level == "High" else colors.orange if risk_level == "Medium" else colors.green
        
        risk_data = [
            ['Overall Risk Assessment:', Paragraph(f"<font color='{risk_color.hexval()}'>{risk_level}</font>", styles['Normal'])],
            ['Assessment Date:', scan_data[4]]
        ]
        
        risk_table = Table(risk_data, colWidths=[2*inch, 4*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(risk_table)
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph("Technical Assessment Details", subtitle_style))
        
        scan_details = [
            ['Scan ID:', str(scan_data[0])],
            ['URL Analyzed:', scan_data[1]],
            ['HTTP Response Code:', str(scan_data[2])],
            ['Scan Completion Time:', scan_data[4]]
        ]
        
        details_table = Table(scan_details, colWidths=[2*inch, 4*inch])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(details_table)
        story.append(Spacer(1, 0.3*inch))
        
        # HTTP Headers Section
        story.append(Paragraph("HTTP Response Headers Analysis", subtitle_style))
        story.append(Paragraph(
            "The following HTTP headers were detected in the server response. Security headers are highlighted.",
            normal_style
        ))
        story.append(Spacer(1, 0.2*inch))
        
        if headers_dict:
            # Security headers to highlight
            security_headers = [
                'content-security-policy', 'x-frame-options', 'x-content-type-options',
                'strict-transport-security', 'x-xss-protection', 'referrer-policy',
                'permissions-policy', 'x-powered-by', 'server'
            ]
            
            headers_data = [['Header Name', 'Value']]
            for header_name, header_value in headers_dict.items():
                # Truncate long values
                display_value = str(header_value)
                if len(display_value) > 80:
                    display_value = display_value[:77] + "..."
                
                # Highlight security headers
                if header_name.lower() in security_headers:
                    headers_data.append([f"<b>{header_name}</b>", display_value])
                else:
                    headers_data.append([header_name, display_value])
            
            headers_table = Table(headers_data, colWidths=[2.5*inch, 3.5*inch])
            headers_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(headers_table)
        else:
            story.append(Paragraph("No headers were captured in this scan.", normal_style))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Security Headers Analysis
        story.append(Paragraph("Security Headers Analysis", subtitle_style))
        security_analysis = analyze_security_headers(headers_dict)
        for item in security_analysis:
            story.append(Paragraph(f"• {item}", normal_style))
        
        story.append(Spacer(1, 0.3*inch))
        
        if zap_results and 'summary' in zap_results:
            story.append(Paragraph("OWASP ZAP Security Scan Results", subtitle_style))
            zap_summary = zap_results['summary']
            
            zap_stats_data = [
                ['Total Alerts:', str(zap_summary.get('total_alerts', 0))],
                ['High Risk:', str(zap_summary.get('high_risk', 0))],
                ['Medium Risk:', str(zap_summary.get('medium_risk', 0))],
                ['Low Risk:', str(zap_summary.get('low_risk', 0))]
            ]
            
            zap_stats_table = Table(zap_stats_data, colWidths=[2*inch, 4*inch])
            zap_stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(zap_stats_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Detailed ZAP Alerts
            if zap_summary.get('alerts'):
                story.append(PageBreak())
                story.append(Paragraph("Detailed Security Alerts", subtitle_style))
                story.append(Paragraph(
                    f"Total of {len(zap_summary['alerts'])} security alerts were detected. Details below:",
                    normal_style
                ))
                story.append(Spacer(1, 0.2*inch))
                
                # Group alerts by risk level
                high_risk_alerts = [a for a in zap_summary['alerts'] if a.get('risk') == 'High']
                medium_risk_alerts = [a for a in zap_summary['alerts'] if a.get('risk') == 'Medium']
                low_risk_alerts = [a for a in zap_summary['alerts'] if a.get('risk') == 'Low']
                info_alerts = [a for a in zap_summary['alerts'] if a.get('risk') not in ['High', 'Medium', 'Low']]
                
                # High Risk Alerts
                if high_risk_alerts:
                    story.append(Paragraph("High Risk Vulnerabilities", heading3_style))
                    for idx, alert in enumerate(high_risk_alerts, 1):
                        story.append(Paragraph(f"<b>{idx}. {alert.get('name', 'Unknown Alert')}</b>", normal_style))
                        story.append(Paragraph(f"<b>Risk:</b> {alert.get('risk', 'Unknown')}", normal_style))
                        story.append(Paragraph(f"<b>Description:</b> {alert.get('description', 'No description available')}", normal_style))
                        if alert.get('solution'):
                            story.append(Paragraph(f"<b>Solution:</b> {alert.get('solution')}", normal_style))
                        if alert.get('url'):
                            story.append(Paragraph(f"<b>URL:</b> {alert.get('url')}", normal_style))
                        story.append(Spacer(1, 0.15*inch))
                
                # Medium Risk Alerts
                if medium_risk_alerts:
                    story.append(Paragraph("Medium Risk Issues", heading3_style))
                    for idx, alert in enumerate(medium_risk_alerts, 1):
                        story.append(Paragraph(f"<b>{idx}. {alert.get('name', 'Unknown Alert')}</b>", normal_style))
                        story.append(Paragraph(f"<b>Risk:</b> {alert.get('risk', 'Unknown')}", normal_style))
                        story.append(Paragraph(f"<b>Description:</b> {alert.get('description', 'No description available')[:300]}...", normal_style))
                        if alert.get('solution'):
                            story.append(Paragraph(f"<b>Solution:</b> {alert.get('solution')[:200]}...", normal_style))
                        story.append(Spacer(1, 0.1*inch))
                
                # Low Risk Alerts (summary only)
                if low_risk_alerts:
                    story.append(Paragraph("Low Risk Findings", heading3_style))
                    story.append(Paragraph(f"Found {len(low_risk_alerts)} low-risk issues. Key findings:", normal_style))
                    for alert in low_risk_alerts[:10]:  # Show first 10
                        story.append(Paragraph(f"• {alert.get('name', 'Unknown')}: {alert.get('description', '')[:150]}...", normal_style))
                    if len(low_risk_alerts) > 10:
                        story.append(Paragraph(f"... and {len(low_risk_alerts) - 10} more low-risk findings.", normal_style))
                    story.append(Spacer(1, 0.2*inch))
                
                story.append(Spacer(1, 0.2*inch))
        
        story.append(PageBreak())
        
        # AI-Powered Analysis Section (if OpenAI is enabled)
        openai_enabled = get_setting('openai_enabled', 'false') == 'true'
        ai_analysis_result = None
        
        if openai_enabled:
            try:
                openai_api_key = get_setting('openai_api_key', '')
                openai_model = get_setting('openai_model', 'gpt-4')
                openai_temperature = float(get_setting('openai_temperature', '0.7'))
                
                if openai_api_key:
                    analyzer = create_openai_analyzer(
                        api_key=openai_api_key,
                        model=openai_model,
                        temperature=openai_temperature
                    )
                    
                    if analyzer and analyzer.is_available:
                        scan_data_dict = {
                            'url': scan_data[1],
                            'status_code': scan_data[2],
                            'scan_date': scan_data[4]
                        }
                        ai_analysis_result = analyzer.analyze_scan_results(
                            scan_data=scan_data_dict,
                            headers=headers_dict,
                            zap_results=zap_results
                        )
            except Exception as ai_error:
                # Continue without AI analysis if it fails
                pass
        
        if ai_analysis_result and 'success' in ai_analysis_result and ai_analysis_result['success']:
            story.append(Paragraph("AI-Powered Security Analysis (OpenAI)", subtitle_style))
            story.append(Paragraph(
                f"This section contains AI-generated analysis using OpenAI {ai_analysis_result.get('model_used', 'N/A')} model.",
                normal_style
            ))
            story.append(Spacer(1, 0.2*inch))
            
            structured = ai_analysis_result.get('structured_report', {})
            
            if structured.get('executive_summary'):
                story.append(Paragraph("Executive Summary", heading3_style))
                story.append(Paragraph(structured['executive_summary'], normal_style))
                story.append(Spacer(1, 0.2*inch))
            
            if structured.get('critical_findings'):
                story.append(Paragraph("Critical Findings", heading3_style))
                story.append(Paragraph(structured['critical_findings'], normal_style))
                story.append(Spacer(1, 0.2*inch))
            
            if structured.get('security_headers_analysis'):
                story.append(Paragraph("Security Headers Analysis", heading3_style))
                story.append(Paragraph(structured['security_headers_analysis'], normal_style))
                story.append(Spacer(1, 0.2*inch))
            
            if structured.get('vulnerability_assessment'):
                story.append(Paragraph("Vulnerability Assessment", heading3_style))
                story.append(Paragraph(structured['vulnerability_assessment'], normal_style))
                story.append(Spacer(1, 0.2*inch))
            
            if structured.get('risk_assessment'):
                story.append(Paragraph("Risk Assessment", heading3_style))
                story.append(Paragraph(structured['risk_assessment'], normal_style))
                story.append(Spacer(1, 0.2*inch))
            
            if structured.get('recommendations'):
                story.append(Paragraph("AI-Generated Recommendations", heading3_style))
                story.append(Paragraph(structured['recommendations'], normal_style))
                story.append(Spacer(1, 0.2*inch))
            
            if structured.get('best_practices'):
                story.append(Paragraph("Best Practices", heading3_style))
                story.append(Paragraph(structured['best_practices'], normal_style))
                story.append(Spacer(1, 0.2*inch))
            
            story.append(PageBreak())
        
        story.append(Paragraph("Expert Remediation Recommendations", subtitle_style))
        
        # Generate detailed recommendations
        recommendations = generate_recommendations(scan_data, headers_dict, zap_results)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", normal_style))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Status Code Analysis
        story.append(Paragraph("HTTP Status Code Analysis", subtitle_style))
        status_analysis = analyze_status_code(scan_data[2])
        story.append(Paragraph(status_analysis, normal_style))
        
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(f"CONFIDENTIAL - Generated by CyberShield Professional Security Platform", styles['Italic']))
        story.append(Paragraph(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC", styles['Italic']))
        
        doc.build(story)
        
        # Verify file was created
        if not os.path.exists(filename):
            raise Exception("PDF file was not created successfully")
        
        return filename
    except Exception as e:
        # Clean up partial file if it exists
        if os.path.exists(filename):
            try:
                os.remove(filename)
            except:
                pass
        raise Exception(f"Error generating PDF report: {str(e)}")

def determine_risk_level(scan_data, zap_results=None):
    """Determine overall risk level based on scan data and ZAP results"""
    status_code = scan_data[2]
    
    if zap_results and 'summary' in zap_results:
        zap_summary = zap_results['summary']
        if zap_summary.get('high_risk', 0) > 0:
            return "High"
        elif zap_summary.get('medium_risk', 0) > 0:
            return "Medium"
        elif zap_summary.get('low_risk', 0) > 0:
            return "Low"
    
    if status_code >= 500:
        return "High"
    elif status_code >= 400:
        return "Medium"
    else:
        return "Low"

def analyze_security_headers(headers_dict):
    """Analyze security headers and provide recommendations"""
    analysis = []
    headers_lower = {k.lower(): v for k, v in headers_dict.items()}
    
    # Check for Content Security Policy
    if 'content-security-policy' not in headers_lower:
        analysis.append("❌ <b>Missing Content-Security-Policy:</b> Implement CSP to prevent XSS attacks.")
    else:
        analysis.append("✓ Content-Security-Policy header is present.")
    
    # Check for X-Frame-Options
    if 'x-frame-options' not in headers_lower:
        analysis.append("❌ <b>Missing X-Frame-Options:</b> Add this header to prevent clickjacking attacks.")
    else:
        analysis.append(f"✓ X-Frame-Options: {headers_lower.get('x-frame-options', 'N/A')}")
    
    # Check for X-Content-Type-Options
    if 'x-content-type-options' not in headers_lower:
        analysis.append("❌ <b>Missing X-Content-Type-Options:</b> Add 'nosniff' to prevent MIME type sniffing.")
    else:
        analysis.append(f"✓ X-Content-Type-Options: {headers_lower.get('x-content-type-options', 'N/A')}")
    
    # Check for Strict-Transport-Security
    if 'strict-transport-security' not in headers_lower:
        analysis.append("⚠️ <b>Missing Strict-Transport-Security:</b> Recommended for HTTPS sites to enforce secure connections.")
    else:
        analysis.append(f"✓ Strict-Transport-Security header is present.")
    
    # Check for X-XSS-Protection
    if 'x-xss-protection' not in headers_lower:
        analysis.append("⚠️ <b>Missing X-XSS-Protection:</b> Consider adding this header for additional XSS protection.")
    else:
        analysis.append(f"✓ X-XSS-Protection header is present.")
    
    # Check for server information disclosure
    if 'server' in headers_lower:
        analysis.append(f"⚠️ <b>Server Information Disclosure:</b> Server header reveals '{headers_lower['server']}'. Consider hiding server information.")
    
    if 'x-powered-by' in headers_lower:
        analysis.append(f"⚠️ <b>Technology Disclosure:</b> X-Powered-By header reveals technology stack. Remove this header.")
    
    if not analysis:
        analysis.append("No security headers were found. This is a significant security concern.")
    
    return analysis

def generate_recommendations(scan_data, headers_dict, zap_results):
    """Generate detailed security recommendations"""
    recommendations = []
    
    # Status code recommendations
    status_code = scan_data[2]
    if status_code >= 500:
        recommendations.append("Server errors detected. Review server configuration and logs immediately.")
    elif status_code >= 400:
        recommendations.append("Client errors detected. Ensure proper error handling and user input validation.")
    
    # Header recommendations
    headers_lower = {k.lower(): v for k, v in headers_dict.items()}
    if 'content-security-policy' not in headers_lower:
        recommendations.append("Implement a Content Security Policy (CSP) to mitigate XSS attacks. Start with a restrictive policy and adjust as needed.")
    
    if 'strict-transport-security' not in headers_lower and scan_data[1].startswith('https://'):
        recommendations.append("Add Strict-Transport-Security header to enforce HTTPS connections and prevent protocol downgrade attacks.")
    
    # ZAP recommendations
    if zap_results and 'summary' in zap_results:
        zap_summary = zap_results['summary']
        if zap_summary.get('high_risk', 0) > 0:
            recommendations.append(f"URGENT: {zap_summary.get('high_risk', 0)} high-risk vulnerabilities detected. Address these immediately.")
        if zap_summary.get('medium_risk', 0) > 0:
            recommendations.append(f"Important: {zap_summary.get('medium_risk', 0)} medium-risk issues found. Plan remediation within 30 days.")
        if zap_summary.get('low_risk', 0) > 0:
            recommendations.append(f"Review {zap_summary.get('low_risk', 0)} low-risk findings and address as part of regular security maintenance.")
    
    # General recommendations
    recommendations.append("Regularly update all software components, frameworks, and dependencies to patch known vulnerabilities.")
    recommendations.append("Implement a Web Application Firewall (WAF) to provide an additional layer of protection.")
    recommendations.append("Conduct regular security audits and penetration testing to identify and remediate vulnerabilities.")
    recommendations.append("Ensure all sensitive data is encrypted in transit (HTTPS) and at rest.")
    recommendations.append("Implement proper access controls and authentication mechanisms.")
    recommendations.append("Set up security monitoring and logging to detect and respond to security incidents.")
    
    return recommendations

def analyze_status_code(status_code):
    """Analyze HTTP status code and provide explanation"""
    if status_code >= 200 and status_code < 300:
        return f"Status Code {status_code}: Success. The request was successful. This is the expected response for normal operations."
    elif status_code >= 300 and status_code < 400:
        return f"Status Code {status_code}: Redirection. The request was redirected to another location. Review redirect chains for security implications."
    elif status_code >= 400 and status_code < 500:
        if status_code == 401:
            return f"Status Code {status_code}: Unauthorized. Authentication is required. Ensure proper authentication mechanisms are in place."
        elif status_code == 403:
            return f"Status Code {status_code}: Forbidden. Access is denied. Review access control policies."
        elif status_code == 404:
            return f"Status Code {status_code}: Not Found. The requested resource was not found. Ensure proper error handling to prevent information disclosure."
        else:
            return f"Status Code {status_code}: Client Error. The request contains invalid data or cannot be processed. Review input validation and error handling."
    elif status_code >= 500:
        return f"Status Code {status_code}: Server Error. Internal server error occurred. This indicates a problem with the server configuration or application code. Immediate attention required."
    else:
        return f"Status Code {status_code}: Unknown status code. Review server configuration."
