# dashboard/app.py
"""
Streamlit Dashboard for AI AWS CSPM
Visualizes security scan results, scores, and AI remediation.
"""

import streamlit as st
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def generate_html_report(assessment, findings, scan_time):
    """Generate an HTML report from scan results."""
    score = assessment.get('security_score', 0)
    grade = assessment.get('grade', 'F')
    total_findings = len(findings)
    
    # Count by severity
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'MEDIUM')
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AWS Security Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }}
            .score {{ font-size: 48px; font-weight: bold; text-align: center; margin: 20px; }}
            .grade {{ font-size: 36px; color: {'green' if score >= 80 else 'orange' if score >= 60 else 'red'}; }}
            .severity {{ display: inline-block; padding: 5px 10px; margin: 5px; border-radius: 5px; }}
            .critical {{ background: #dc3545; color: white; }}
            .high {{ background: #fd7e14; color: white; }}
            .medium {{ background: #ffc107; color: black; }}
            .low {{ background: #28a745; color: white; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background: #333; color: white; }}
            .footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 AI AWS CSPM Security Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Scan Time: {scan_time}</p>
            </div>
            
            <div class="score">
                Security Score: <span class="grade">{score}% ({grade})</span>
            </div>
            
            <div style="text-align: center;">
                <span class="severity critical">CRITICAL: {severity_counts['CRITICAL']}</span>
                <span class="severity high">HIGH: {severity_counts['HIGH']}</span>
                <span class="severity medium">MEDIUM: {severity_counts['MEDIUM']}</span>
                <span class="severity low">LOW: {severity_counts['LOW']}</span>
            </div>
            
            <h2>📋 Findings ({total_findings})</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Service</th>
                    <th>Issue</th>
                    <th>Resource</th>
                </tr>
    """
    
    for f in findings[:50]:  # Limit to 50 for report
        severity = f.get('severity', 'MEDIUM')
        severity_class = severity.lower()
        html += f"""
                <tr>
                    <td><span class="severity {severity_class}">{severity}</span></td>
                    <td>{f.get('service', 'N/A')}</td>
                    <td>{f.get('issue', 'N/A')}</td>
                    <td><code>{f.get('resource_id', 'N/A')}</code></td>
                </tr>
        """
    
    html += f"""
            </table>
            
            <div class="footer">
                <p>AI AWS CSPM - Automated Security Assessment Tool</p>
                <p>Report includes findings from S3, IAM, EC2, and RDS scanners</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html
# Page configuration MUST be the first Streamlit command
st.set_page_config(
    page_title="AI AWS CSPM - Security Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .stApp {
        background-color: #f5f5f5;
    }
    .big-font {
        font-size: 30px !important;
        font-weight: bold;
    }
    .score-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 15px;
        color: white;
        text-align: center;
    }
    .critical { color: #dc3545; font-weight: bold; }
    .high { color: #fd7e14; font-weight: bold; }
    .medium { color: #ffc107; font-weight: bold; }
    .low { color: #28a745; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'current_scan' not in st.session_state:
    st.session_state.current_scan = None
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

def load_latest_scan():
    """Load the most recent scan results from data folder."""
    data_dir = "data"
    if not os.path.exists(data_dir):
        return None
    
    # Look for full_assessment.json
    assessment_file = os.path.join(data_dir, "full_assessment.json")
    if os.path.exists(assessment_file):
        try:
            with open(assessment_file, 'r') as f:
                data = json.load(f)
                return data
        except:
            return None
    return None

def load_scan_history():
    """Load all historical scan files."""
    data_dir = "data"
    if not os.path.exists(data_dir):
        return []
    
    history = []
    # Look for all JSON files (simplified - in production you'd have a history file)
    for file in os.listdir(data_dir):
        if file.endswith('.json') and file != 'full_assessment.json':
            try:
                with open(os.path.join(data_dir, file), 'r') as f:
                    data = json.load(f)
                    if 'scan_time' in data:
                        history.append({
                            'file': file,
                            'scan_time': data['scan_time'],
                            'total_findings': data.get('total_findings', 0)
                        })
            except:
                pass
    
    # Sort by scan_time (newest first)
    history.sort(key=lambda x: x['scan_time'], reverse=True)
    return history[:10]  # Last 10 scans

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/cloud-security.png", width=80)
    st.title("🔒 AI AWS CSPM")
    st.markdown("---")
    
    # Navigation
    page = st.radio(
        "Navigation",
        ["🏠 Dashboard", "📊 Findings", "🤖 AI Remediation", "📜 Compliance", "📈 History"]
    )
    
    st.markdown("---")
    
    # Scan controls
    st.subheader("📡 Scan Controls")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Run New Scan", use_container_width=True):
            st.info("Run scan from terminal: python scripts/run_with_scoring.py")
    
    with col2:
        if st.button("📂 Load Latest", use_container_width=True):
            st.session_state.current_scan = load_latest_scan()
            st.rerun()
    
    st.markdown("---")
    st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")

# Main content
st.title("🔒 AI-Powered AWS Security Scanner")

# Load data
if st.session_state.current_scan is None:
    st.session_state.current_scan = load_latest_scan()

if st.session_state.current_scan is None:
    # No data - show instructions
    st.warning("⚠️ No scan data found. Run a scan first:")
    st.code("python scripts/run_with_scoring.py", language="bash")
    st.info("After running the scan, click 'Load Latest' in the sidebar.")
    st.stop()

# Extract assessment data
assessment = st.session_state.current_scan.get('security_assessment', {})
findings = st.session_state.current_scan.get('findings', [])
scan_time = st.session_state.current_scan.get('scan_time', 'Unknown')

# Page routing
if page == "🏠 Dashboard":
    # Dashboard Header
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.markdown(f"### 📊 Security Assessment")
        st.caption(f"Scan completed: {scan_time}")
    
    with col2:
        # Security Score Gauge
        score = assessment.get('security_score', 0)
        grade = assessment.get('grade', 'F')
        
        # Create gauge chart
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = score,
            title = {'text': "Security Score", 'font': {'size': 24}},
            delta = {'reference': 80, 'increasing': {'color': "green"}},
            gauge = {
                'axis': {'range': [None, 100], 'tickwidth': 1},
                'bar': {'color': "darkblue"},
                'bgcolor': "white",
                'borderwidth': 2,
                'bordercolor': "gray",
                'steps': [
                    {'range': [0, 50], 'color': '#ff4b4b'},
                    {'range': [50, 70], 'color': '#ffa64b'},
                    {'range': [70, 90], 'color': '#ffdb4b'},
                    {'range': [90, 100], 'color': '#4bff4b'}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig.update_layout(height=250, margin=dict(l=20, r=20, t=50, b=20))
        st.plotly_chart(fig, use_container_width=True)
    
    with col3:
        # Grade Card
        grade_color = {
            'A+': '#00ff00', 'A': '#00ff00', 'B': '#ffdb4b', 
            'C': '#ffa64b', 'D': '#ff6b4b', 'F': '#ff4b4b'
        }.get(grade, '#ff4b4b')
        
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, {grade_color} 0%, {grade_color}99 100%); 
                    padding: 20px; border-radius: 15px; text-align: center;">
            <h2 style="margin:0; color:white;">Overall Grade</h2>
            <h1 style="margin:0; font-size: 72px; color:white;">{grade}</h1>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Key Metrics Row
    st.subheader("📈 Key Metrics")
    col1, col2, col3, col4, col5 = st.columns(5)
    
    risk_summary = assessment.get('risk_assessment', {}).get('risk_summary', {})
    
    with col1:
        st.metric("Total Findings", assessment.get('total_findings', 0))
    with col2:
        st.metric("🔴 CRITICAL", risk_summary.get('CRITICAL', 0), delta_color="inverse")
    with col3:
        st.metric("🟠 HIGH", risk_summary.get('HIGH', 0), delta_color="inverse")
    with col4:
        st.metric("🟡 MEDIUM", risk_summary.get('MEDIUM', 0))
    with col5:
        st.metric("🔵 LOW", risk_summary.get('LOW', 0))
    
    st.markdown("---")
    
    # Risk by Service Chart
    st.subheader("📊 Risk Distribution by Service")
    
    risk_by_service = assessment.get('risk_assessment', {}).get('risk_by_service', {})
    if risk_by_service:
        df_risk = pd.DataFrame([
            {'Service': service, 'Risk Score': score}
            for service, score in risk_by_service.items()
        ])
        fig = px.bar(df_risk, x='Service', y='Risk Score', 
                     title='Risk Score by AWS Service',
                     color='Risk Score',
                     color_continuous_scale='Reds')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No risk data available")
    
    # Top Recommendations
    st.subheader("🎯 Top Recommendations")
    recommendations = assessment.get('risk_assessment', {}).get('recommendations', [])
    if recommendations:
        for rec in recommendations[:5]:
            st.markdown(f"- {rec}")
    else:
        st.success("✅ No recommendations - perfect security posture!")
    
    # Recent Findings Preview
    st.subheader("🔍 Recent Findings")
    if findings:
        preview_df = pd.DataFrame([
            {
                'Severity': f.get('severity', 'N/A'),
                'Service': f.get('service', 'N/A'),
                'Issue': f.get('issue', 'N/A')[:80] + '...',
                'Resource': f.get('resource_id', 'N/A')
            }
            for f in findings[:10]
        ])
        st.dataframe(preview_df, use_container_width=True)
        
        if len(findings) > 10:
            st.caption(f"Showing 10 of {len(findings)} findings. Go to 'Findings' page for full list.")
    else:
        st.success("🎉 No findings! Your AWS account is secure!")
elif page == "📊 Findings":
    st.header("📊 Security Findings")
    
    if not findings:
        st.success("🎉 No security findings detected!")
        st.balloons()
        st.stop()
    
    # Filters
    st.subheader("🔍 Filter Findings")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.multiselect(
            "Severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
    
    with col2:
        services = list(set(f.get('service', 'Unknown') for f in findings))
        service_filter = st.multiselect("Service", options=services, default=services)
    
    with col3:
        search_term = st.text_input("Search", placeholder="Search by issue or resource...")
    
    # Apply filters
    filtered_findings = []
    for f in findings:
        if f.get('severity') not in severity_filter:
            continue
        if f.get('service') not in service_filter:
            continue
        if search_term:
            search_lower = search_term.lower()
            if not (search_lower in f.get('issue', '').lower() or 
                    search_lower in f.get('resource_id', '').lower()):
                continue
        filtered_findings.append(f)
    
    st.caption(f"Showing {len(filtered_findings)} of {len(findings)} findings")
    
    # Display findings
    for idx, finding in enumerate(filtered_findings):
        severity = finding.get('severity', 'MEDIUM')
        severity_color = {
            'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'
        }.get(severity, '⚪')
        
        with st.expander(f"{severity_color} [{severity}] {finding.get('service')}: {finding.get('issue', 'N/A')[:100]}"):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"**Resource:** `{finding.get('resource_id', 'N/A')}`")
                st.markdown(f"**Service:** {finding.get('service', 'N/A')}")
                st.markdown(f"**Issue:** {finding.get('issue', 'N/A')}")
                
                # Show details if present
                details = finding.get('details', {})
                if details:
                    with st.expander("📋 Details"):
                        st.json(details)
            
            with col2:
                # Severity badge
                st.markdown(f"""
                <div style="background-color: {'#dc3545' if severity == 'CRITICAL' else '#fd7e14' if severity == 'HIGH' else '#ffc107' if severity == 'MEDIUM' else '#28a745'}; 
                            padding: 10px; border-radius: 10px; text-align: center;">
                    <span style="color: white; font-weight: bold;">{severity}</span>
                </div>
                """, unsafe_allow_html=True)
            
            # AI Remediation preview
            remediation = finding.get('remediation', {})
            if remediation:
                st.markdown("---")
                st.markdown("### 🤖 AI Remediation")
                
                tab1, tab2, tab3 = st.tabs(["📖 Explanation", "🔧 CLI Fix", "🏗️ Terraform"])
                
                with tab1:
                    st.info(remediation.get('explanation', 'No explanation available')[:500])
                
                with tab2:
                    cli_cmd = remediation.get('cli_command', 'No CLI command available')
                    st.code(cli_cmd, language='bash')
                    if st.button(f"📋 Copy CLI", key=f"cli_{idx}"):
                        st.write("Copied to clipboard!")
                
                with tab3:
                    tf_fix = remediation.get('terraform_fix', 'No Terraform fix available')
                    if tf_fix != 'N/A':
                        st.code(tf_fix, language='hcl')
                    else:
                        st.caption("Terraform fix not applicable for this finding")
    
    # Export button
    if filtered_findings:
        st.markdown("---")
        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            if st.button("📥 Export to JSON"):
                export_data = {
                    "export_time": datetime.now().isoformat(),
                    "findings": filtered_findings
                }
                st.download_button(
                    label="Download JSON",
                    data=json.dumps(export_data, indent=2),
                    file_name=f"findings_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
    
elif page == "🤖 AI Remediation":
    st.header("🤖 AI-Powered Remediation")
    st.markdown("AI-generated fix suggestions for all security findings")
    
    if not findings:
        st.info("No findings to remediate")
        st.stop()
    
    # Filter for findings with remediation
    findings_with_remediation = [f for f in findings if f.get('remediation')]
    
    if not findings_with_remediation:
        st.warning("No remediation data available. Run a scan with AI enabled.")
        st.code("python scripts/run_with_scoring.py", language="bash")
        st.stop()
    
    # Summary cards
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Findings", len(findings_with_remediation))
    with col2:
        ai_count = sum(1 for f in findings_with_remediation 
                      if f.get('remediation', {}).get('ai_generated', False))
        st.metric("AI Generated", f"{ai_count}/{len(findings_with_remediation)}")
    with col3:
        st.metric("Services Affected", 
                  len(set(f.get('service') for f in findings_with_remediation)))
    
    st.markdown("---")
    
    # Group by service
    st.subheader("📂 Remediation by Service")
    
    services_grouped = {}
    for f in findings_with_remediation:
        service = f.get('service', 'Other')
        if service not in services_grouped:
            services_grouped[service] = []
        services_grouped[service].append(f)
    
    for service, service_findings in services_grouped.items():
        with st.expander(f"🔧 {service} ({len(service_findings)} findings)"):
            for idx, finding in enumerate(service_findings):
                severity = finding.get('severity', 'MEDIUM')
                remediation = finding.get('remediation', {})
                
                st.markdown(f"**{idx+1}. [{severity}] {finding.get('issue', 'N/A')}**")
                st.markdown(f"*Resource:* `{finding.get('resource_id', 'N/A')}`")
                
                tab1, tab2, tab3 = st.tabs(["📖 Fix Explanation", "💻 CLI Command", "📝 Terraform"])
                
                with tab1:
                    st.write(remediation.get('explanation', 'No explanation available'))
                
                with tab2:
                    cli_cmd = remediation.get('cli_command', '# No CLI command available')
                    st.code(cli_cmd, language='bash')
                    if st.button(f"📋 Copy", key=f"remediation_cli_{service}_{idx}"):
                        st.toast("Copied to clipboard!", icon="✅")
                
                with tab3:
                    tf_cmd = remediation.get('terraform_fix', '# No Terraform fix available')
                    if tf_cmd != 'N/A':
                        st.code(tf_cmd, language='hcl')
                    else:
                        st.info("Manual remediation required - Terraform not applicable")
                
                st.markdown("---")
    
    # Bulk remediation plan
    st.subheader("📋 Bulk Remediation Plan")
    if st.button("Generate Remediation Script"):
        script_lines = ["#!/bin/bash", "# AWS Security Remediation Script", f"# Generated: {datetime.now()}", ""]
        
        for f in findings_with_remediation:
            cli = f.get('remediation', {}).get('cli_command', '')
            if cli and cli != 'No CLI command available' and not cli.startswith('aws iam update-user'):
                script_lines.append(f"echo 'Fixing: {f.get('issue', '')[:50]}'")
                script_lines.append(cli)
                script_lines.append("")
        
        st.code('\n'.join(script_lines), language='bash')
        st.download_button(
            label="Download Remediation Script",
            data='\n'.join(script_lines),
            file_name=f"remediation_{datetime.now().strftime('%Y%m%d')}.sh",
            mime="text/plain"
        )
    
elif page == "📜 Compliance":
    st.header("📜 Compliance Framework Mapping")
    st.markdown("Security findings mapped to industry compliance frameworks")
    
    if not findings:
        st.info("No findings to display")
        st.stop()
    
    # Get compliance data
    compliance_report = assessment.get('compliance_report', {})
    compliance_by_framework = compliance_report.get('compliance_by_framework', {})
    failed_controls = compliance_report.get('failed_controls', {})
    
    # Framework selector
    frameworks = ['cis', 'nist', 'gdpr', 'hipaa', 'pci', 'sox']
    framework_labels = {
        'cis': 'CIS AWS Benchmarks',
        'nist': 'NIST 800-53',
        'gdpr': 'GDPR',
        'hipaa': 'HIPAA',
        'pci': 'PCI DSS',
        'sox': 'SOX'
    }
    
    selected_framework = st.selectbox(
        "Select Compliance Framework",
        frameworks,
        format_func=lambda x: framework_labels.get(x, x.upper())
    )
    
    # Display compliance score for selected framework
    score = compliance_by_framework.get(selected_framework, 0)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Gauge for this framework
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = score,
            title = {'text': f"{framework_labels.get(selected_framework, selected_framework.upper())} Compliance"},
            gauge = {
                'axis': {'range': [0, 100]},
                'bar': {'color': "#2ecc71" if score >= 80 else "#f39c12" if score >= 60 else "#e74c3c"},
                'steps': [
                    {'range': [0, 60], 'color': '#ffcccc'},
                    {'range': [60, 80], 'color': '#ffffcc'},
                    {'range': [80, 100], 'color': '#ccffcc'}
                ]
            }
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # All frameworks comparison
        st.subheader("All Frameworks")
        df_comp = pd.DataFrame([
            {'Framework': framework_labels.get(f, f.upper()), 'Score': compliance_by_framework.get(f, 0)}
            for f in frameworks if f in compliance_by_framework
        ])
        if not df_comp.empty:
            fig = px.bar(df_comp, x='Framework', y='Score', 
                        title='Compliance Scores by Framework',
                        color='Score',
                        color_continuous_scale='RdYlGn',
                        range_color=[0, 100])
            st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # Failed controls for selected framework
    st.subheader(f"❌ Failed Controls - {framework_labels.get(selected_framework, selected_framework.upper())}")
    
    failed = failed_controls.get(selected_framework, [])
    if failed:
        for control in failed:
            with st.expander(f"⚠️ {control.get('control', 'Unknown Control')}"):
                st.markdown(f"**Finding:** {control.get('finding', 'N/A')}")
                st.markdown(f"**Severity:** {control.get('severity', 'N/A')}")
                
                # Find the finding details
                matching_finding = next(
                    (f for f in findings if f.get('issue') == control.get('finding')), 
                    None
                )
                
                if matching_finding and matching_finding.get('remediation'):
                    remediation = matching_finding['remediation']
                    st.markdown("**Remediation:**")
                    st.code(remediation.get('cli_command', 'No CLI command'), language='bash')
    else:
        st.success(f"✅ All {framework_labels.get(selected_framework, selected_framework.upper())} controls passed!")
    
    st.markdown("---")
    
    # Compliance details table
    st.subheader("📋 Compliance Details")
    
    compliance_details = []
    for f in findings:
        comp = f.get('compliance', {})
        if comp:
            compliance_details.append({
                'Severity': f.get('severity', 'N/A'),
                'Service': f.get('service', 'N/A'),
                'Issue': f.get('issue', 'N/A')[:60],
                'CIS': comp.get('cis', 'N/A')[:40],
                'NIST': comp.get('nist', 'N/A')[:40],
                'GDPR': comp.get('gdpr', 'N/A')[:40]
            })
    
    if compliance_details:
        st.dataframe(pd.DataFrame(compliance_details), use_container_width=True)
    
    # Export compliance report
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📥 Export Compliance Report (JSON)"):
            export_data = {
                "export_time": datetime.now().isoformat(),
                "framework": selected_framework,
                "compliance_score": score,
                "failed_controls": failed,
                "all_findings": findings
            }
            st.download_button(
                label="Download JSON",
                data=json.dumps(export_data, indent=2),
                file_name=f"compliance_{selected_framework}_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json"
            )
    
elif page == "📈 History":
    st.header("📈 Security Score History")
    st.markdown("Track your security posture over time")
    
    # Initialize history manager
    from src.utils.history_manager import HistoryManager
    history_manager = HistoryManager()
    
    # Get history data
    history = history_manager.get_history(limit=30)
    trend_data = history_manager.get_score_trend()
    
    if not history:
        st.info("No historical data available. Run a scan to start tracking.")
        st.code("python scripts/run_with_scoring.py", language="bash")
        
        # Offer to save current scan
        if st.button("Save Current Scan to History"):
            from src.utils.history_manager import HistoryManager
            hm = HistoryManager()
            hm.save_scan(st.session_state.current_scan)
            st.success("Scan saved! Refresh the page.")
            st.rerun()
        st.stop()
    
    # Score trend chart
    st.subheader("📊 Security Score Evolution")
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=trend_data['dates'],
        y=trend_data['security_scores'],
        mode='lines+markers',
        name='Security Score',
        line=dict(color='#2ecc71', width=3),
        marker=dict(size=8)
    ))
    
    fig.add_trace(go.Scatter(
        x=trend_data['dates'],
        y=trend_data['risk_scores'],
        mode='lines+markers',
        name='Risk Score',
        line=dict(color='#3498db', width=2, dash='dash'),
        marker=dict(size=6)
    ))
    
    fig.add_trace(go.Scatter(
        x=trend_data['dates'],
        y=trend_data['compliance_scores'],
        mode='lines+markers',
        name='Compliance Score',
        line=dict(color='#e74c3c', width=2, dash='dot'),
        marker=dict(size=6)
    ))
    
    fig.update_layout(
        title='Security Posture Over Time',
        xaxis_title='Date',
        yaxis_title='Score (%)',
        yaxis_range=[0, 100],
        hovermode='x unified',
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # Finding trends
    st.subheader("📉 Finding Trends")
    
    # Extract finding counts over time
    finding_counts = []
    dates = []
    for scan in history:
        dates.append(scan['scan_time'][:10])
        risk_summary = scan.get('risk_summary', {})
        finding_counts.append({
            'CRITICAL': risk_summary.get('CRITICAL', 0),
            'HIGH': risk_summary.get('HIGH', 0),
            'MEDIUM': risk_summary.get('MEDIUM', 0),
            'LOW': risk_summary.get('LOW', 0)
        })
    
    # Reverse for chronological
    dates.reverse()
    finding_counts.reverse()
    
    fig2 = go.Figure()
    
    severity_colors = {
        'CRITICAL': '#e74c3c',
        'HIGH': '#e67e22',
        'MEDIUM': '#f1c40f',
        'LOW': '#2ecc71'
    }
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        counts = [fc[severity] for fc in finding_counts]
        fig2.add_trace(go.Bar(
            x=dates,
            y=counts,
            name=severity,
            marker_color=severity_colors[severity]
        ))
    
    fig2.update_layout(
        title='Security Findings Over Time',
        xaxis_title='Date',
        yaxis_title='Number of Findings',
        barmode='stack',
        legend=dict(orientation='h', yanchor='bottom', y=1.02)
    )
    
    st.plotly_chart(fig2, use_container_width=True)
    
    st.markdown("---")
    
    # Compliance trend for selected framework
    st.subheader("📜 Compliance Trend")
    
    frameworks = ['cis', 'nist', 'gdpr', 'hipaa', 'pci', 'sox']
    framework_labels = {
        'cis': 'CIS', 'nist': 'NIST', 'gdpr': 'GDPR',
        'hipaa': 'HIPAA', 'pci': 'PCI', 'sox': 'SOX'
    }
    
    selected_fw = st.selectbox("Select Framework", frameworks, format_func=lambda x: framework_labels.get(x, x.upper()))
    
    fw_trend = history_manager.get_compliance_trend(selected_fw)
    
    if fw_trend['dates']:
        fig3 = go.Figure(go.Scatter(
            x=fw_trend['dates'],
            y=fw_trend['scores'],
            mode='lines+markers',
            name=framework_labels.get(selected_fw, selected_fw.upper()),
            line=dict(color='#9b59b6', width=3),
            fill='tozeroy',
            fillcolor='rgba(155, 89, 182, 0.2)'
        ))
        
        fig3.update_layout(
            title=f'{framework_labels.get(selected_fw, selected_fw.upper())} Compliance Over Time',
            xaxis_title='Date',
            yaxis_title='Compliance Score (%)',
            yaxis_range=[0, 100]
        )
        
        st.plotly_chart(fig3, use_container_width=True)
    
    # Historical table
    st.subheader("📋 Scan History")
    
    history_table = []
    for scan in history[:10]:
        history_table.append({
            'Date': scan['scan_time'][:10],
            'Time': scan['scan_time'][11:19],
            'Score': f"{scan['security_score']}%",
            'Grade': scan['grade'],
            'Findings': scan['total_findings'],
            'Critical': scan['risk_summary'].get('CRITICAL', 0),
            'High': scan['risk_summary'].get('HIGH', 0)
        })
    
    st.dataframe(pd.DataFrame(history_table), use_container_width=True)
    
    # Clear history button (with confirmation)
    st.markdown("---")
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🗑️ Clear History", type="secondary"):
            import os
            if os.path.exists("data/scan_history.json"):
                os.remove("data/scan_history.json")
                st.success("History cleared! Refresh the page.")
                st.rerun()

# Add to Dashboard page, after the Recent Findings Preview section

    st.markdown("---")
    
    # Export Section
    st.subheader("📄 Export Reports")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Export Summary (JSON)", use_container_width=True):
            export_summary = {
                "export_time": datetime.now().isoformat(),
                "security_score": assessment.get('security_score', 0),
                "grade": assessment.get('grade', 'F'),
                "total_findings": len(findings),
                "risk_summary": risk_summary,
                "findings": findings
            }
            st.download_button(
                label="Download JSON",
                data=json.dumps(export_summary, indent=2),
                file_name=f"security_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                key="export_summary"
            )
    
    with col2:
        if st.button("📋 Generate HTML Report", use_container_width=True):
            html_report = generate_html_report(assessment, findings, scan_time)
            st.download_button(
                label="Download HTML",
                data=html_report,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html",
                key="export_html"
            )
    
    with col3:
        if st.button("💾 Save to History", use_container_width=True):
            from src.utils.history_manager import HistoryManager
            hm = HistoryManager()
            hm.save_scan(st.session_state.current_scan)
            st.success("✅ Scan saved to history!")

st.caption("AI AWS CSPM - Complete Security Assessment Tool")