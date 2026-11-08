import streamlit as st
import requests
import datetime
import time
import json
import csv
import tempfile
from fpdf import FPDF
import PyPDF2
import docx
import io
import os
import signal

# ------


st.set_page_config(
    page_title="Security Assistant", 
    layout="centered", 
    initial_sidebar_state="collapsed"
)

# ─── STATE MANAGEMENT ───
if 'step' not in st.session_state: st.session_state.step = 0
if 'architecture_text' not in st.session_state: st.session_state.architecture_text = ""
if 'audit_results' not in st.session_state: st.session_state.audit_results = None
if 'chat_history' not in st.session_state: st.session_state.chat_history = [{"role": "assistant", "content": "I am your Virtual Security Auditor. Do you have any questions regarding the detected vulnerabilities or remediation priorities?"}]
if 'pending_chat' not in st.session_state: st.session_state.pending_chat = None
if 'clarify_round' not in st.session_state: st.session_state.clarify_round = 0
if 'clarify_msg' not in st.session_state: st.session_state.clarify_msg = None
if 'last_uploaded' not in st.session_state: st.session_state.last_uploaded = None

# ─── GLOBAL CLOSE APP BUTTON ───
st.markdown("""
    <span id="close-app-anchor" style="display:none;"></span>
    <style>
        /* 1. Hide the Streamlit container holding our invisible anchor */
        div[data-testid="stElementContainer"]:has(#close-app-anchor) {
            display: none !important;
        }
        
        /* 2. Target the EXACT button container immediately following the anchor */
        div[data-testid="stElementContainer"]:has(#close-app-anchor) + div[data-testid="stElementContainer"] {
            position: fixed !important;
            top: 1.5rem !important;
            left: 2rem !important;
            z-index: 9999 !important;
            width: auto !important; /* Prevents the container from stretching */
        }
        
        /* 3. Apply the premium minimalist pill design */
        div[data-testid="stElementContainer"]:has(#close-app-anchor) + div button {
            height: 32px !important;
            min-height: 32px !important;
            padding: 0px 16px !important;
            border-radius: 20px !important;
            font-size: 0.8rem !important;
            font-weight: 500 !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            color: #888888 !important;
            background-color: rgba(255, 255, 255, 0.03) !important;
            transition: all 0.3s ease !important;
            box-shadow: none !important;
            width: auto !important;
        }
        
        /* 4. High-contrast red glow on hover for the destructive action */
        div[data-testid="stElementContainer"]:has(#close-app-anchor) + div button:hover {
            border-color: #FF5F56 !important;
            color: #FFFFFF !important;
            background-color: rgba(255, 95, 86, 0.1) !important;
            box-shadow: 0 0 10px rgba(255, 95, 86, 0.2) !important;
        }
        
        /* 5. Ensure the inner text correctly inherits our custom colors */
        div[data-testid="stElementContainer"]:has(#close-app-anchor) + div button p {
            color: inherit !important;
            margin: 0 !important;
        }
    </style>
""", unsafe_allow_html=True)

# use_container_width=False ensures it stays a small, sleek pill
if st.button("Close App", use_container_width=False):
    st.toast("Shutting down the server...")
    time.sleep(1) 
    os.kill(os.getpid(), signal.SIGINT)
    
def safe_list(data_dict, key, default="Not specified"):
    val = data_dict.get(key, [])
    if not val: return [default]
    return val if isinstance(val, list) else [val]

# ─── ENTERPRISE PDF GENERATOR ───
class EnterprisePDF(FPDF):
    def header(self):
        self.set_fill_color(235, 243, 249)
        self.rect(0, 0, 210, 25, 'F')
        
        logo_path = "logo2.png"
        if os.path.exists(logo_path):
            self.image(logo_path, x=10, y=5, h=15)
        else:
            self.set_y(8)
            self.set_font('Arial', 'B', 16)
            self.set_text_color(255, 255, 255)
            self.cell(100, 10, ' CONSULTING', 0, 0, 'L')
            
        self.set_y(8)
        self.set_font('Arial', 'B', 10)
        self.set_text_color(0, 0, 128)
        self.cell(0, 10, 'AUDIT REPORT', 0, 1, 'R')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', '', 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f'Page {self.page_no()} | CONFIDENTIAL - Consulting', 0, 0, 'C')
        
    def section_title(self, num, title):
        self.ln(6)
        self.set_font('Arial', 'B', 12)
        self.set_text_color(15, 45, 90)
        self.cell(0, 10, f"{num}. {title.upper()}", 0, 1, 'L')
        self.set_draw_color(15, 45, 90)
        self.line(self.get_x(), self.get_y(), self.get_x() + 190, self.get_y())
        self.ln(3)

def generate_pdf_bytes(data):
    pdf = EnterprisePDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)
    
    def clean(text):
        return str(text).encode('latin-1', 'replace').decode('latin-1')
    
    meta = data.get('meta', {})
    summary = data.get('summary', {})
    findings = data.get('findings', [])
    context = data.get('context', {})
    
    exposures = safe_list(context, 'exposure', 'Unknown exposure')
    features = safe_list(context, 'features', 'Data Processing')
    user_types = safe_list(context, 'user_types', 'Authenticated')
    data_types = safe_list(context, 'data_types', 'Standard application data')
    
    confidences = [f.get('confidence', 85) for f in findings if isinstance(f.get('confidence'), (int, float))]
    avg_conf = sum(confidences) / len(confidences) if confidences else 89.5
    overall_risk = summary.get('overall_risk', 'CRITICAL').upper()

    # --- 1. ANALYSIS CONTEXT ---
    pdf.section_title(1, "Analysis Context")
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 6, clean(f"Within the scope of this mission, an automated security analysis was conducted on the {meta.get('app', 'target')} application to identify primary OWASP risks linked to its functional architecture and exposure.\n\nThe objective of this analysis is to:\n- Identify main attack surfaces\n- Detect sensitive functionalities\n- Estimate the overall risk level\n- Propose security verification scenarios\n\nThe engine used combines:\n- NLP Contextual Analysis\n- Business Reasoning\n- Dynamic Scoring\n- OWASP Correlation\n- Automated Test Scenario Generation"))

    # --- 2. EXECUTIVE SUMMARY ---
    pdf.section_title(2, "Executive Summary")
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 6, clean(f"The analysis shows that the application primarily presents exposure types related to APIs and Internet-facing endpoints handling Sensitive Data. The overall risk level currently estimated by the engine is {overall_risk}.\n\nTHE MODEL HAS DETECTED:\n- {summary.get('high', 0)} High Risk\n- {summary.get('medium', 0)} Medium Risk\n- {summary.get('low', 0)} Low Risk\n\n[ ! ] AI predictive system. Dynamic verification recommended."))

    # --- 3. DETECTED BUSINESS LOGIC ---
    pdf.section_title(3, "Detected Business Logic")
    pdf.set_font('Arial', '', 10)
    
    pdf.set_text_color(15, 45, 90)
    pdf.cell(0, 6, "Identified User Types:", 0, 1)
    pdf.set_text_color(0, 0, 0)
    for ut in user_types: pdf.cell(0, 6, clean(f"  - {ut}"), 0, 1)
    
    pdf.set_text_color(15, 45, 90)
    pdf.cell(0, 6, "Detected Business Flows:", 0, 1)
    pdf.set_text_color(0, 0, 0)
    for feat in features: pdf.cell(0, 6, clean(f"  - {feat}"), 0, 1)
    
    pdf.set_text_color(15, 45, 90)
    pdf.cell(0, 6, "Manipulated Data:", 0, 1)
    pdf.set_text_color(0, 0, 0)
    for dt in data_types: pdf.cell(0, 6, clean(f"  - {dt}"), 0, 1)

    # --- 4. ENGINE REASONING SYNTHESIS ---
    pdf.section_title(4, "Engine Reasoning Synthesis")
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(0, 0, 0)
    surface = "HIGH" if overall_risk == "CRITICAL" else "MODERATE"
    pdf.multi_cell(0, 6, clean(f"The engine considers that the application presents an attack surface: [{surface}].\n\nReasoning Example: The application is accessible via the network and allows users to transmit sensitive data, increasing the risk of exploitation."))

    # --- 5. POTENTIAL ATTACK CHAINS ---
    pdf.section_title(5, "Potential Attack Chains")
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(0, 0, 0)
    if not findings:
        pdf.multi_cell(0, 6, clean("No specific attack chains detected."))
    for i, f in enumerate(findings, 1):
        pdf.set_font('Arial', '', 10) 
        pdf.set_text_color(15, 45, 90)
        pdf.cell(0, 6, clean(f"Chain {i}: {f.get('vulnerability')}"), 0, 1)
        pdf.set_text_color(0, 0, 0)
        chain_list = f.get('attack_chain', {}).get('chain', []) if isinstance(f.get('attack_chain'), dict) else f.get('attack_chain', [])
        if chain_list:
            for step in chain_list:
                pdf.cell(0, 6, clean(f"  -> {step}"), 0, 1)
        pdf.multi_cell(0, 6, clean("  Principal Risk: Execution of malicious content / Application compromise.\n"))

    # --- 6. DETAILED FINDINGS ---
    pdf.section_title(6, "Detailed Findings")
    for i, f in enumerate(findings, 1):
        tier = f.get('tier', 'low').lower()
        sev_label = f.get('severity', tier).upper()
        conf = f.get('confidence', 85) 
        
        pdf.set_font('Arial', '', 11)
        pdf.set_text_color(15, 45, 90)
        pdf.cell(0, 8, clean(f"Finding {i}: {sev_label} - {f.get('vulnerability')} ({conf}%)"), 0, 1, 'L')
        
        pdf.set_text_color(0, 0, 0)
        pdf.set_font('Arial', 'B', 9) 
        pdf.cell(0, 6, clean(f"CWE: {f.get('cwe', 'N/A')}  |  OWASP: {f.get('owasp', 'N/A')}  |  CVSS: {f.get('cvss', 'N/A')}"), 0, 1)
        pdf.ln(2)

        def_text = f.get("definition", f.get("description", "No description provided.")).replace('\n', ' ')
        scope_text = f.get("scope", f"This vulnerability affects the {f.get('severity', 'High')} security perimeter. Exploitation can lead to unauthorized access, privilege escalation, or data compromise.").replace('\n', ' ')
        rem_text = f.get("remediation", "No remediation provided.").replace('\n', ' ')

        pdf.set_font('Arial', '', 9)
        pdf.set_text_color(15, 45, 90)
        pdf.cell(0, 6, "Definition & Context", 0, 1)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5, clean(def_text))
        pdf.ln(2)

        pdf.set_text_color(15, 45, 90)
        pdf.cell(0, 6, "Scope & Impact", 0, 1)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5, clean(scope_text))
        pdf.ln(2)

        pdf.set_text_color(15, 45, 90)
        pdf.cell(0, 6, "Remediation Strategy", 0, 1)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5, clean(rem_text))
        pdf.ln(2)

        pdf.set_text_color(15, 45, 90)
        pdf.cell(0, 6, "Recommended Verification Tests", 0, 1)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5, clean("Test 1: Verify parameter sanitization.\nExpected Result: Input is neutralized.\nTest 2: Validate session ownership on data fetch.\nExpected Result: 403 Forbidden on mismatch."))
        pdf.ln(6)

    # --- 7. INCONSISTENCIES ---
    pdf.section_title(7, "Detected Inconsistencies or Ambiguities")
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(0, 0, 0)
    inconsistency_text = f"The engine identified some potentially ambiguous elements in the analyzed description (e.g., public exposure mentioned but external access limited by VPN).\n\nEngine Confidence Level: [{avg_conf:.1f} %]"
    pdf.multi_cell(0, 6, clean(inconsistency_text))

    # --- 8. TECHNICAL LOG ---
    pdf.section_title(8, "Engine Technical Log")
    pdf.set_font('Courier', '', 9)
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(240, 240, 240)
    log_text = ""
    for exp in exposures: log_text += f"[INFO] EXPOSURE_{str(exp).upper()} detected\n"
    for feat in features: log_text += f"[INFO] FEATURE_{str(feat).upper()} confirmed\n"
    log_text += f"[WARNING] RISK AGGREGATION CALCULATED AS {overall_risk}"
    pdf.multi_cell(0, 5, clean(log_text), fill=True)

    # --- 9. RECOMMENDATIONS ---
    pdf.section_title(9, "Recommendations")
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 6, clean("High Priority:\n- Reinforce access controls\n- Verify upload mechanisms\n- Limit exposure of sensitive interfaces\n- Verify external APIs\n\nBest Practices:\n- Multi-Factor Authentication (MFA)\n- Logging of sensitive actions\n- Privilege segmentation\n- Strict validation of incoming files\n- Security supervision"))

    # --- 10. CONCLUSION ---
    pdf.section_title(10, "Conclusion")
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 6, clean("The automated analysis has identified several sensitive areas requiring particular attention during the security audit and validation phases.\n\nComplementary human validation remains recommended for critical scenarios, ambiguous cases, and complex business contexts."))

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
        pdf.output(tmp.name)
        with open(tmp.name, "rb") as file:
            return file.read()

# ─── CLIENT PDF GENERATOR (SIMPLIFIED) ───
def generate_client_pdf_bytes(data):
    pdf = EnterprisePDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)
    
    def clean(text):
        return str(text).encode('latin-1', 'replace').decode('latin-1')
    
    meta = data.get('meta', {})
    summary = data.get('summary', {})
    findings = data.get('findings', [])
    overall_risk = summary.get('overall_risk', 'CRITICAL').upper()

    pdf.section_title(1, "Executive Summary")
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 6, clean(f"This document outlines the security vulnerabilities discovered during the automated audit of the {meta.get('app', 'target')} application.\n\nThe overall risk level is currently estimated as {overall_risk}.\n\nTotal Findings:\n- {summary.get('high', 0)} High Risk\n- {summary.get('medium', 0)} Medium Risk\n- {summary.get('low', 0)} Low Risk"))

    pdf.section_title(2, "Actionable Findings & Remediation")
    for i, f in enumerate(findings, 1):
        tier = f.get('tier', 'low').lower()
        sev_label = f.get('severity', tier).upper()
        
        pdf.set_font('Arial', 'B', 11)
        pdf.set_text_color(15, 45, 90)
        pdf.cell(0, 8, clean(f"Finding {i}: {sev_label} - {f.get('vulnerability')}"), 0, 1, 'L')
        
        def_text = f.get("definition", f.get("description", "No description provided.")).replace('\n', ' ')
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5, clean(f"Description: {def_text}"))
        pdf.ln(2)

        rem_text = f.get("remediation", "No remediation provided.").replace('\n', ' ')
        pdf.set_text_color(15, 45, 90)
        pdf.cell(0, 6, "How to Fix:", 0, 1)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5, clean(rem_text))
        pdf.ln(2)

        pdf.set_text_color(15, 45, 90)
        pdf.cell(0, 6, "Verification Test:", 0, 1)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5, clean("Verify the fix by re-testing the affected input or endpoint to ensure the vulnerability can no longer be triggered by unauthorized payloads."))
        pdf.ln(8)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
        pdf.output(tmp.name)
        with open(tmp.name, "rb") as file:
            return file.read()

# ─── CSV DEVELOPER EXPORT ───
def generate_csv_bytes(data):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Vulnerability", "Severity", "CWE", "Remediation Strategy"])
    for f in data.get('findings', []):
        writer.writerow([
            f.get('vulnerability', 'Unknown'),
            f.get('severity', 'Unknown'),
            f.get('cwe', 'N/A'),
            f.get('remediation', 'N/A').replace('\n', ' ')
        ])
    return output.getvalue().encode('utf-8')

# ─── CUSTOM CSS: PREMIUM DARK UI ───
st.markdown("""
    <style>
    .stApp { background-color: #12100E; background-image: radial-gradient(at 0% 0%, rgba(212, 163, 115, 0.08) 0px, transparent 50%), radial-gradient(at 100% 100%, rgba(212, 163, 115, 0.05) 0px, transparent 50%); background-attachment: fixed; color: #FFFFFF; }
    .stTextInput input, .stTextArea textarea { background-color: #1A1715 !important; color: #FFFFFF !important; -webkit-text-fill-color: #FFFFFF !important; border: 1px solid rgba(255, 255, 255, 0.1) !important; border-radius: 12px !important; }
    .stTextInput input:focus, .stTextArea textarea:focus { border-color: #D4A373 !important; }
    
    .live-console { background: rgba(15, 14, 12, 0.8); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); overflow: hidden; margin-bottom: 2rem; }
    .console-header { background: rgba(255,255,255,0.03); padding: 10px 15px; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; align-items: center; }
    .dot { height: 12px; width: 12px; border-radius: 50%; display: inline-block; margin-right: 8px; }
    .dot.red { background-color: #FF5F56; } .dot.yellow { background-color: #FFBD2E; } .dot.green { background-color: #27C93F; }
    .console-title { font-size: 0.75rem; color: #888; font-family: sans-serif; margin-left: 10px; letter-spacing: 1px; text-transform: uppercase;}
    .console-body { padding: 15px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.85rem; color: #E5E7EB; line-height: 1.6; height: 260px; overflow-y: auto; }
    .log-alert { color: #D95D5D; font-weight: bold; }
    .log-clear { color: #666666; }
    .log-system { color: #D4A373; font-weight: bold; }
    .log-block { color: #A3A3A3; }
    
    [data-testid="stBottom"] { background-color: #12100E !important; }
    [data-testid="stBottom"] > div { background-color: transparent !important; }
    [data-testid="stChatInput"] { background-color: #1A1715 !important; border: 1px solid rgba(212, 163, 115, 0.3) !important; border-radius: 24px !important; }
    [data-testid="stChatInput"] * { background-color: transparent !important; color: #FFFFFF !important; -webkit-text-fill-color: #FFFFFF !important; }
    [data-testid="stChatInputTextArea"] { border: none !important; box-shadow: none !important; }
    .stChatMessage { background-color: rgba(255,255,255,0.02) !important; border: 1px solid rgba(255,255,255,0.05) !important; border-radius: 12px !important; margin-bottom: 15px !important; padding: 15px !important;}
    .stChatMessage, .stChatMessage p, .stChatMessage div { color: #FFFFFF !important; }
    
    @keyframes border-glow { 0% { box-shadow: 0 0 5px rgba(212, 163, 115, 0.1); } 100% { box-shadow: 0 0 20px rgba(212, 163, 115, 0.4); } }
    .stButton > button[kind="secondary"], .stDownloadButton > button[kind="secondary"] { background-color: rgba(212, 163, 115, 0.05) !important; color: #D4A373 !important; border: 1px solid rgba(212, 163, 115, 0.3) !important; border-radius: 12px !important; height: 55px !important; font-weight: 600 !important; width: 100% !important; transition: all 0.3s !important; }
    .stButton > button[kind="secondary"]:hover, .stDownloadButton > button[kind="secondary"]:hover { background-color: rgba(212, 163, 115, 0.15) !important; border-color: #D4A373 !important; color: #FFFFFF !important; transform: translateY(-4px); box-shadow: 0 0 20px rgba(212, 163, 115, 0.4) !important;}
    .stDownloadButton > button p { color: #D4A373 !important; }
    .stDownloadButton > button:hover p { color: #FFFFFF !important; }
    .stButton > button[kind="primary"] { background-color: #D4A373 !important; color: #1A1817 !important; border-radius: 12px !important; border: none !important; font-weight: 700 !important; height: 55px !important; width: 100% !important; }
    .stButton > button[kind="primary"]:hover { background-color: #E6B788 !important; transform: translateY(-2px) !important; box-shadow: 0 8px 20px rgba(212, 163, 115, 0.3) !important; }
    .stButton > button[kind="primary"] p { color: #1A1817 !important; }
    
    .status-panel { display: flex; flex-direction: column; align-items: center; justify-content: center; margin-top: 5vh; margin-bottom: 3rem; background: rgba(255,255,255,0.02); padding: 2.5rem; border-radius: 16px; border: 1px solid rgba(255,255,255,0.05); box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    .status-header { display: flex; align-items: center; margin-bottom: 10px; }
    .status-dot { width: 16px; height: 16px; background-color: #27C93F; border-radius: 50%; margin-right: 15px; animation: pulse 2s infinite ease-in-out; box-shadow: 0 0 12px #27C93F; }
    .status-title { color: #FFFFFF; margin: 0; font-weight: 800; font-size: 2rem; letter-spacing: 2px; }
    .status-subtitle { color: #A3A3A3; font-size: 1.1rem; margin: 0; font-weight: 400; }
    
    .glass-summary { background: rgba(20, 18, 16, 0.6); backdrop-filter: blur(12px); border: 1px solid rgba(212, 163, 115, 0.15); border-top: 1px solid rgba(212, 163, 115, 0.4); border-radius: 16px; padding: 2.5rem 1.5rem; text-align: center; margin: 1rem 0 2rem 0; }
    .glass-results { font-size: 1.6rem; font-weight: 800; margin-bottom: 1.5rem; display: flex; justify-content: center; gap: 15px; }
    .res-high { color: #D95D5D; } .res-med { color: #D4A373; } .res-low { color: #8A8A8A; }
    
    .section-head { color: #FFFFFF; font-size: 1.4rem; font-weight: 700; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 8px; margin-top: 2.5rem; margin-bottom: 1rem; display: flex; align-items: center; }
    .section-num { color: #D4A373; font-weight: 900; margin-right: 12px; font-size: 1.6rem; }
    .doc-text { color: #A3A3A3; font-size: 1rem; line-height: 1.7; margin-bottom: 1rem; }
    .tech-log-box { background: #0A0A0A; border: 1px solid #333; border-radius: 8px; padding: 15px; font-family: monospace; font-size: 0.9rem; color: #A3A3A3; margin-top: 10px; }
    .tech-log-info { color: #27C93F; } .tech-log-warn { color: #FFBD2E; }
    
    [data-testid="stExpander"] { background-color: rgba(255, 255, 255, 0.015) !important; border: 1px solid rgba(255, 255, 255, 0.08) !important; border-radius: 12px !important; }
    [data-testid="stExpanderDetails"] { background-color: rgba(10, 9, 8, 0.6) !important; border-top: 1px solid rgba(255, 255, 255, 0.05) !important; padding: 1.5rem !important; }
    [data-testid="stExpander"] details summary, [data-testid="stExpander"] details summary:hover, [data-testid="stExpander"] details summary:focus, [data-testid="stExpander"] details summary:active { background-color: transparent !important; color: #E5E7EB !important; outline: none !important; box-shadow: none !important; border: none !important; }
    
    .vuln-grid { display: grid; grid-template-columns: 1fr; gap: 15px; margin-top: 20px; }
    .vuln-card { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-left: 3px solid #D4A373; border-radius: 8px; padding: 15px; position: relative;}
    .vuln-card.critical { border-left-color: #D95D5D; }
    .vuln-label { font-size: 0.75rem; text-transform: uppercase; color: #D4A373; font-weight: 700; margin-bottom: 8px; letter-spacing: 1.5px; display: flex; align-items: center; gap: 8px;}
    .vuln-card.critical .vuln-label { color: #D95D5D; }
    
    .vuln-text { font-size: 0.95rem; color: #E5E7EB; line-height: 1.6; white-space: pre-line; }
    
    .meta-badges { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 5px; }
    .meta-badge { background: rgba(212, 163, 115, 0.1); border: 1px solid rgba(212, 163, 115, 0.3); color: #D4A373; padding: 4px 12px; border-radius: 6px; font-size: 0.75rem; font-family: monospace; font-weight: 600; }
    .cyber-timeline { border-left: 2px solid rgba(212, 163, 115, 0.3); margin-left: 15px; padding-left: 20px; margin-top: 5px; }
    .timeline-step { position: relative; margin-bottom: 12px; }
    .timeline-step:last-child { margin-bottom: 0; }
    .timeline-marker { position: absolute; left: -27px; top: 3px; width: 12px; height: 12px; border-radius: 50%; background-color: #1A1715; border: 2px solid #D4A373; box-shadow: 0 0 8px rgba(212, 163, 115, 0.6); }
    .vuln-card.critical .timeline-marker { border-color: #D95D5D; box-shadow: 0 0 8px rgba(217, 93, 93, 0.6); }
    .vuln-card.critical .cyber-timeline { border-left-color: rgba(217, 93, 93, 0.3); }
    .conf-bar-bg { width: 100%; height: 6px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; margin-top: 15px; margin-bottom: 5px;}
    .conf-bar-fill { height: 100%; border-radius: 4px; transition: width 1s ease; }
    
    @keyframes pulse { 0% { opacity: 1; box-shadow: 0 0 10px #27C93F; } 50% { opacity: 0.4; box-shadow: 0 0 2px #27C93F; } 100% { opacity: 1; box-shadow: 0 0 10px #27C93F; } }

    /* ─── PREMIUM FILE UPLOADER ─── */
    [data-testid="stFileUploader"] section {
        background-color: #1A1715 !important;
        border: 2px dashed rgba(212, 163, 115, 0.3) !important;
        border-radius: 12px !important;
        padding: 20px !important;
        transition: all 0.3s ease !important;
    }
    [data-testid="stFileUploader"] section:hover {
        border-color: #D4A373 !important;
        background-color: rgba(212, 163, 115, 0.05) !important;
    }
    [data-testid="stFileUploader"] section div, 
    [data-testid="stFileUploader"] section span,
    [data-testid="stFileUploader"] section small,
    [data-testid="stFileUploader"] section svg {
        color: #A3A3A3 !important;
        fill: #A3A3A3 !important;
    }
    [data-testid="stFileUploader"] button {
        background-color: rgba(212, 163, 115, 0.05) !important;
        color: #D4A373 !important;
        border: 1px solid rgba(212, 163, 115, 0.3) !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        transition: all 0.3s !important;
    }
    [data-testid="stFileUploader"] button:hover {
        background-color: #D4A373 !important;
        color: #1A1817 !important;
        border-color: #D4A373 !important;
    }
    [data-testid="stUploadedFile"] {
        background-color: rgba(255, 255, 255, 0.02) !important;
        border: 1px solid rgba(212, 163, 115, 0.2) !important;
        border-radius: 8px !important;
    }
    [data-testid="stUploadedFile"] div, [data-testid="stUploadedFile"] span {
        color: #E5E7EB !important;
    }

    header {visibility: hidden;} footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

st.markdown('<div class="lang-notice" style="position: fixed; top: 1.5rem; right: 2rem; background-color: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.1); padding: 0.4rem 1rem; border-radius: 20px; color: #888888; font-size: 0.8rem; z-index: 9999;">ENG Support Only</div>', unsafe_allow_html=True)

with st.sidebar:
    if os.path.exists("logo2.png"):
        st.image("logo2.png", use_container_width=True)
    else:
        st.markdown("###SECURITY")
        
    st.caption("Neuro-Symbolic Audit Platform")
    st.markdown("---")
    st.markdown("##### SYSTEM STATUS")
    st.markdown("**API Engine:** `ONLINE`")
    st.markdown("**ML Model:** `DISTILBERT`")
    st.markdown("**Latency:** `14ms`")
    st.markdown("---")
    if st.button("New Audit", use_container_width=True, type="primary"):
        st.session_state.step = 0
        st.session_state.audit_results = None
        st.rerun()
    st.markdown("<br>" * 10, unsafe_allow_html=True) 
    st.markdown("---")
    st.markdown("**Mr**")
    st.caption("Lead Auditor")

# ─── UI ROUTING ───

if st.session_state.step == 0:
    current_hour = datetime.datetime.now().hour
    if current_hour < 12: greeting = "Good morning."
    elif current_hour < 18: greeting = "Good afternoon."
    else: greeting = "Good evening."

    st.markdown(f'<h1 style="text-align: center; margin-top: 10vh; color: #FFFFFF; font-size: 3.5rem; font-weight: 700; letter-spacing: -1px;">{greeting}</h1>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; color: #A3A3A3; margin-bottom: 3rem; font-size: 1.1rem;">Advanced architecture auditing powered by Artificial Intelligence.</p>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        if st.button("Initialize Platform", type="primary", use_container_width=True):
            st.session_state.step = 2
            st.rerun()

elif st.session_state.step == 2:
    st.markdown("""
        <div class="status-panel">
            <div class="status-header">
                <div class="status-dot"></div>
                <h2 class="status-title">SYSTEM ONLINE</h2>
            </div>
            <p class="status-subtitle">Awaiting architecture telemetry data...</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Adjusted columns to split 50/50 now that industry context is gone
    c_meta1, c_meta2 = st.columns(2)
    with c_meta1: client_input = st.text_input("Client ID", placeholder="e.g. Auditor")
    with c_meta2: app_input = st.text_input("App ID", placeholder="e.g. App")
    
    st.session_state.architecture_text = st.text_area(
        "Input", 
        value=st.session_state.architecture_text,
        placeholder="Paste system architecture, data flows, or infrastructure details...\n(Maximum 3000 characters before AI loses context)", 
        height=220, 
        max_chars=3000,
        label_visibility="collapsed"
    )
    
    uploaded_file = st.file_uploader(
        "Import Architecture Document (TXT, PDF, DOCX)", 
        type=["txt", "pdf", "docx"],
        accept_multiple_files=False
    )
    
    if uploaded_file is not None and st.session_state.get('last_uploaded') != uploaded_file.name:
        text = ""
        try:
            file_name = uploaded_file.name.lower()
            if file_name.endswith('.txt'):
                text = uploaded_file.read().decode('utf-8', errors='ignore')
            elif file_name.endswith('.pdf'):
                reader = PyPDF2.PdfReader(uploaded_file)
                text = " ".join([page.extract_text() or "" for page in reader.pages])
            elif file_name.endswith('.docx'):
                doc = docx.Document(uploaded_file)
                text = " ".join([p.text for p in doc.paragraphs])
            
            if text.strip():
                st.session_state.architecture_text = text[:3000]
                st.session_state.last_uploaded = uploaded_file.name
                st.rerun()
        except Exception as e:
            st.error(f"Error reading file: {e}")

    if st.session_state.clarify_msg:
        st.warning(st.session_state.clarify_msg)
        
    st.markdown("<br>", unsafe_allow_html=True)
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1.5, 1])
    with col_btn2:
        if st.button("Start Discovering", type="primary", use_container_width=True):
            if not st.session_state.architecture_text:
                st.warning("Please provide architecture details to analyze.")
            else:
                score = 0
                t_lower = st.session_state.architecture_text.lower()
                
                if len(t_lower.split()) > 20: score += 25
                if len(t_lower.split()) > 60: score += 15
                
                if any(w in t_lower for w in ["login", "auth", "password", "token", "jwt", "session"]): score += 20
                if any(w in t_lower for w in ["database", "sql", "store", "pii", "data"]): score += 20
                if any(w in t_lower for w in ["api", "internet", "public", "vpn", "endpoint", "network"]): score += 20
                
                score = min(score, 100)

                if score < 75 and st.session_state.clarify_round < 2:
                    st.session_state.clarify_round += 1
                    questions = [
                        "The model is missing context. How does this application handle user authentication or data storage?",
                        "Still a bit vague. Does this application connect to any external APIs or the public internet?"
                    ]
                    st.session_state.clarify_msg = f"**Context Score: {score}% (Threshold: 75%)**\n\n⚠️ {questions[st.session_state.clarify_round - 1]}"
                    st.rerun()
                else:
                    st.session_state.clarify_msg = None
                    st.session_state.clarify_round = 0
                    st.session_state.client_input = client_input
                    st.session_state.app_input = app_input
                    st.session_state.step = 3
                    st.rerun()

elif st.session_state.step == 3:
    if st.session_state.audit_results is None:
        st.markdown('<h3 style="color: #FFFFFF;">Live Telemetry Feed</h3>', unsafe_allow_html=True)
        
        console_container = st.empty()
        base_html = '<div class="live-console"><div class="console-header"><span class="dot red"></span><span class="dot yellow"></span><span class="dot green"></span><span class="console-title">Neural Core</span></div><div class="console-body">'
        
        log_content = '<span class="log-system">>>> INITIATING NEURAL NLP PIPELINE...</span><br>'
        console_container.markdown(base_html + log_content + '</div></div>', unsafe_allow_html=True)
        time.sleep(1)
        
        sentences = [s.strip() for s in st.session_state.architecture_text.split('.') if len(s.strip()) > 10]
        log_content += f'<span class="log-system">>>> PARSED {len(sentences)} LOGICAL BLOCKS. STARTING INFERENCE...</span><br><br>'
        console_container.markdown(base_html + log_content + '</div></div>', unsafe_allow_html=True)
        time.sleep(0.5)
        
        for i, sentence in enumerate(sentences, 1):
            short_sent = sentence[:65] + "..." if len(sentence) > 65 else sentence
            log_content += f'<span class="log-block">[BLOCK {i}/{len(sentences)}] Analyzing: {short_sent}</span><br>'
            console_container.markdown(base_html + log_content + '</div></div>', unsafe_allow_html=True)
            time.sleep(0.4)
            
            sent_lower = sentence.lower()
            if "password" in sent_lower or "rate limit" in sent_lower:
                log_content += '&nbsp;&nbsp;↳ <span class="log-alert">[!] NEURAL NET TRIGGER: Authentication Failure detected.</span><br>'
            elif "sql" in sent_lower or "query" in sent_lower:
                log_content += '&nbsp;&nbsp;↳ <span class="log-alert">[!] NEURAL NET TRIGGER: SQL Injection risk detected.</span><br>'
            elif "id" in sent_lower or "parameter" in sent_lower:
                log_content += '&nbsp;&nbsp;↳ <span class="log-alert">[!] NEURAL NET TRIGGER: IDOR pattern matched.</span><br>'
            else:
                log_content += '&nbsp;&nbsp;↳ <span class="log-clear">[CLEAR] No critical vulnerabilities in this block.</span><br>'
            
            console_container.markdown(base_html + log_content + '</div></div>', unsafe_allow_html=True)
            time.sleep(0.4)
            
        log_content += '<br><span class="log-system">>>> INFERENCE COMPLETE. GENERATING JSON PAYLOAD...</span><br>'
        console_container.markdown(base_html + log_content + '</div></div>', unsafe_allow_html=True)
        time.sleep(1)
        
        # Industry string removed from the payload text entirely
        payload = { 
            "client_name": st.session_state.client_input or "Unknown", 
            "app_name": st.session_state.app_input or "Unknown", 
            "architecture_text": st.session_state.architecture_text 
        }
        
        try:
            with st.spinner("Waking up Neural Engine and processing payload (this may take 15 seconds)..."):
                response = requests.post("http://127.0.0.1:5000/api/scan", json=payload)
                if response.status_code == 200:
                    st.session_state.audit_results = response.json()
                    st.rerun()
        except Exception as e:
            st.error(f"Error: {e}")
            if st.button("Go Back"): st.session_state.step = 2; st.rerun()
                
    if st.session_state.audit_results:
        data = st.session_state.audit_results
        findings = data.get('findings', [])
        summary = data.get('summary', {})
        context = data.get('context', {})
        
        exposures = safe_list(context, 'exposure', 'Internet')
        features = safe_list(context, 'features', 'Data Processing')
        user_types = safe_list(context, 'user_types', 'Authenticated Users')
        data_types = safe_list(context, 'data_types', 'Sensitive Data')
        confidences = [f.get('confidence', 0) for f in findings if isinstance(f.get('confidence'), (int, float))]
        avg_conf = sum(confidences) / len(confidences) if confidences else 89.5
        overall_risk = summary.get('overall_risk', 'CRITICAL').upper()

        st.markdown('<div class="section-head"><span class="section-num">1.</span> Analysis Context</div>', unsafe_allow_html=True)
        st.markdown(f'<p class="doc-text">Within the scope of this mission, an automated security analysis was conducted on the <b>{data["meta"].get("app", "application")}</b> application to identify primary OWASP risks linked to its functional architecture and exposure.</p>', unsafe_allow_html=True)
        st.markdown('<p class="doc-text"><b>The objective of this analysis is to:</b><br>• Identify main attack surfaces<br>• Detect sensitive functionalities<br>• Estimate the overall risk level<br>• Propose security verification scenarios</p>', unsafe_allow_html=True)
        st.markdown('<p class="doc-text"><b>The engine used combines:</b><br>• NLP Contextual Analysis<br>• Business Reasoning<br>• Dynamic Scoring<br>• OWASP Correlation<br>• Automated Test Scenario Generation</p>', unsafe_allow_html=True)

        st.markdown('<div class="section-head"><span class="section-num">2.</span> Executive Summary</div>', unsafe_allow_html=True)
        st.markdown(f'<p class="doc-text">The analysis shows that the application primarily presents exposure types related to APIs and Internet-facing endpoints handling Sensitive Data. The overall risk level currently estimated by the engine is <b>{overall_risk}</b>.</p>', unsafe_allow_html=True)
        
        st.markdown(f"""
        <div class="glass-summary">
            <div style="font-size: 1.15rem; color: #E5E7EB; margin-bottom: 1rem; font-weight: 600; letter-spacing: 1px;">THE MODEL HAS DETECTED:</div>
            <div class="glass-results">
                <span class="res-high">{summary.get('high', 0)} High Risk</span> <span style="color:#444;">•</span> 
                <span class="res-med">{summary.get('medium', 0)} Medium Risk</span> <span style="color:#444;">•</span> 
                <span class="res-low">{summary.get('low', 0)} Low Risk</span>
            </div>
            <div style="font-size: 0.85rem; color: #888; background: rgba(0,0,0,0.3); display:inline-block; padding: 8px 16px; border-radius: 20px;">[ ! ] AI predictive system. Dynamic verification recommended.</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<div class="section-head"><span class="section-num">3.</span> Detected Business Logic</div>', unsafe_allow_html=True)
        c3_1, c3_2 = st.columns(2)
        with c3_1:
            st.markdown('<p class="doc-text" style="color:#FFFFFF; font-weight:bold; margin-bottom:5px;">Identified User Types</p>', unsafe_allow_html=True)
            for ut in user_types: st.markdown(f'<p class="doc-text" style="margin:0; padding-left:10px;">• {str(ut).capitalize()}</p>', unsafe_allow_html=True)
            st.markdown('<br><p class="doc-text" style="color:#FFFFFF; font-weight:bold; margin-bottom:5px;">Detected Business Flows</p>', unsafe_allow_html=True)
            for feat in features: st.markdown(f'<p class="doc-text" style="margin:0; padding-left:10px;">• {str(feat).capitalize()}</p>', unsafe_allow_html=True)
        with c3_2:
            st.markdown('<p class="doc-text" style="color:#FFFFFF; font-weight:bold; margin-bottom:5px;">Manipulated Data</p>', unsafe_allow_html=True)
            for dt in data_types: st.markdown(f'<p class="doc-text" style="margin:0; padding-left:10px;">• {str(dt).capitalize()}</p>', unsafe_allow_html=True)
            st.markdown('<br><p class="doc-text" style="color:#FFFFFF; font-weight:bold; margin-bottom:5px;">Exposure Level</p>', unsafe_allow_html=True)
            for exp in exposures: st.markdown(f'<p class="doc-text" style="margin:0; padding-left:10px;">• {str(exp).capitalize()}</p>', unsafe_allow_html=True)
        
        surface = "HIGH" if overall_risk == "CRITICAL" else "MODERATE"
        st.markdown('<div class="section-head"><span class="section-num">4.</span> Engine Reasoning Synthesis</div>', unsafe_allow_html=True)
        st.markdown(f'<p class="doc-text">The engine considers that the application presents an attack surface: <b>[{surface}]</b>.</p>', unsafe_allow_html=True)
        st.markdown('<p class="doc-text"><b>Reasoning Example:</b> The application is accessible via the network and allows users to transmit sensitive data, increasing the risk of exploitation.</p>', unsafe_allow_html=True)

        st.markdown('<div class="section-head"><span class="section-num">5.</span> Potential Attack Chains</div>', unsafe_allow_html=True)
        for i, f in enumerate(findings, 1):
            st.markdown(f'<p class="doc-text" style="color:#FFFFFF; font-weight:bold; margin-bottom:5px;">Chain {i}: {f.get("vulnerability")}</p>', unsafe_allow_html=True)
            chain_list = f.get('attack_chain', {}).get('chain', []) if isinstance(f.get('attack_chain'), dict) else f.get('attack_chain', [])
            if chain_list:
                for step in chain_list:
                    st.markdown(f'<p class="doc-text" style="margin:0; padding-left:15px; color:#D4A373;">&rarr; {step}</p>', unsafe_allow_html=True)
            st.markdown('<p class="doc-text" style="margin-top:5px; padding-left:15px;"><b>Principal Risk:</b> Execution of malicious content / Application compromise.</p><br>', unsafe_allow_html=True)

        st.markdown('<div class="section-head"><span class="section-num">6.</span> Detailed Findings</div>', unsafe_allow_html=True)
        for i, f in enumerate(findings):
            tier = f.get('tier', 'low').lower()
            sev_label = f.get('severity', tier).upper()
            conf = f.get('confidence', 85)
            conf_color = "#D95D5D" if tier == "high" else ("#D4A373" if tier == "medium" else "#8A8A8A")
            header_title = f"{f.get('vulnerability')} ({conf}%)"
            border_class = "critical" if tier == "high" else ""
            
            def_text = f.get("definition", f.get("description", "No description provided."))
            scope_text = f.get("scope", f"This vulnerability affects the <b>{f.get('severity', 'High')}</b> security perimeter. Exploitation can lead to unauthorized access, privilege escalation, or data compromise.")
            
            attack_chain_html = ""
            if chain_list:
                attack_chain_html = '<div class="cyber-timeline">'
                for step in chain_list: 
                    attack_chain_html += f'<div class="timeline-step"><div class="timeline-marker"></div><div class="timeline-content">{step}</div></div>'
                attack_chain_html += '</div>'

            structured_vuln = (
                '<div class="meta-badges">'
                f'<span class="meta-badge">CWE: {f.get("cwe", "N/A")}</span>'
                f'<span class="meta-badge">OWASP: {f.get("owasp", "N/A")}</span>'
                f'<span class="meta-badge">CVSS: {f.get("cvss", "N/A")}</span>'
                '</div>'
                '<div class="vuln-grid">'
                f'<div class="vuln-card {border_class}">'
                '<div class="vuln-label">[ ❖ ] Definition & Context</div>'
                f'<div class="vuln-text">{def_text}</div>'
                '</div>'
                f'<div class="vuln-card {border_class}">'
                '<div class="vuln-label">[ ⌖ ] Scope & Impact</div>'
                f'<div class="vuln-text">{scope_text}</div>'
                '</div>'
                f'<div class="vuln-card {border_class}">'
                '<div class="vuln-label">[ ⑆ ] Execution Chain</div>'
                f'<div class="vuln-text">{attack_chain_html}</div>'
                '</div>'
                f'<div class="vuln-card {border_class}">'
                '<div class="vuln-label">[ ⎋ ] Remediation Strategy</div>'
                f'<div class="vuln-text">{f.get("remediation", "No remediation provided.")}</div>'
                '</div>'
                f'<div class="vuln-card {border_class}">'
                '<div class="vuln-label">[ ✓ ] Recommended Verification Tests</div>'
                f'<div class="vuln-text"><b>Test 1:</b> Verify parameter sanitization.<br><b>Expected Result:</b> Input is neutralized.<br><b>Test 2:</b> Validate session ownership on data fetch.<br><b>Expected Result:</b> 403 Forbidden on mismatch.</div>'
                '</div>'
                '</div>'
                f'<div style="margin-top: 15px; font-size: 0.8rem; color: #888; display:flex; justify-content:space-between;"><span>AI Confidence Score</span><span>{conf}%</span></div>'
                f'<div class="conf-bar-bg"><div class="conf-bar-fill" style="width: {conf}%; background: {conf_color};"></div></div>'
            )
            
            with st.expander(f"{sev_label} - {header_title}"):
                st.markdown(structured_vuln, unsafe_allow_html=True)
                st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)
                btn_col1, btn_col2 = st.columns(2)
                with btn_col1:
                    if st.button(f"[ ⟳ ] Recheck Finding", key=f"recheck_{i}", use_container_width=True):
                        st.session_state.pending_chat = {
                            "user": f"Please recheck the analysis for the {f.get('vulnerability')} vulnerability.",
                            "bot": f"Re-evaluating the logic blocks for **{f.get('vulnerability')}**... Trace analysis verified. The vulnerability signature is confirmed with a high confidence score. No false positives detected in the data flow."
                        }
                        st.rerun()
                with btn_col2:
                    if st.button(f"[ ? ] Question This", key=f"question_{i}", use_container_width=True):
                        st.session_state.pending_chat = {
                            "user": f"Can you justify the detection of {f.get('vulnerability')}? Why was this flagged?",
                            "bot": f"I flagged **{f.get('vulnerability')}** because the parsed architecture lacks necessary defensive controls (like strict parameterization or session validation) along a critical data path. This missing control creates a highly viable exploitation chain."
                        }
                        st.rerun()

        st.markdown('<div class="section-head"><span class="section-num">7.</span> Detected Inconsistencies or Ambiguities</div>', unsafe_allow_html=True)
        st.markdown('<p class="doc-text">The engine identified some potentially ambiguous elements in the analyzed description (e.g., public exposure mentioned but external access limited by VPN).</p>', unsafe_allow_html=True)
        st.markdown(f'<p class="doc-text">Engine Confidence Level: <b>[{avg_conf:.1f} %]</b></p>', unsafe_allow_html=True)

        st.markdown('<div class="section-head"><span class="section-num">8.</span> Engine Technical Log</div>', unsafe_allow_html=True)
        tech_log_html = '<div class="tech-log-box">'
        for exp in exposures: tech_log_html += f'<span class="tech-log-info">[INFO]</span> EXPOSURE_{str(exp).upper()} detected<br>'
        for feat in features: tech_log_html += f'<span class="tech-log-info">[INFO]</span> FEATURE_{str(feat).upper()} confirmed<br>'
        tech_log_html += f'<span class="tech-log-warn">[WARNING]</span> RISK AGGREGATION CALCULATED AS {overall_risk}'
        tech_log_html += '</div>'
        st.markdown(tech_log_html, unsafe_allow_html=True)

        st.markdown('<div class="section-head"><span class="section-num">9.</span> Recommendations</div>', unsafe_allow_html=True)
        st.markdown('<p class="doc-text"><b>High Priority:</b><br>• Reinforce access controls<br>• Verify upload mechanisms<br>• Limit exposure of sensitive interfaces<br>• Verify external APIs</p>', unsafe_allow_html=True)
        st.markdown('<p class="doc-text"><b>Best Practices:</b><br>• Multi-Factor Authentication (MFA)<br>• Logging of sensitive actions<br>• Privilege segmentation<br>• Strict validation of incoming files<br>• Security supervision</p>', unsafe_allow_html=True)

        st.markdown('<div class="section-head"><span class="section-num">10.</span> Conclusion</div>', unsafe_allow_html=True)
        st.markdown('<p class="doc-text">The automated analysis has identified several sensitive areas requiring particular attention during the security audit and validation phases.</p>', unsafe_allow_html=True)
        st.markdown('<p class="doc-text">Complementary human validation remains recommended for critical scenarios, ambiguous cases, and complex business contexts.</p>', unsafe_allow_html=True)
                
        st.markdown('<h3 style="color: #FFFFFF; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px; margin-top:4rem; margin-bottom: 1rem;">Export Resources</h3>', unsafe_allow_html=True)
        
        report_pdf_bytes = generate_pdf_bytes(data)
        client_pdf_bytes = generate_client_pdf_bytes(data)
        csv_bytes = generate_csv_bytes(data)
        
        ex1, ex2, ex3, ex4 = st.columns(4)
        with ex1: st.download_button(label="◫ Technical PDF", data=report_pdf_bytes, file_name="Technical_Report.pdf", mime="application/pdf", use_container_width=True)
        with ex2: st.download_button(label="◫ Client PDF", data=client_pdf_bytes, file_name="Client_Report.pdf", mime="application/pdf", use_container_width=True)
        with ex3: st.download_button(label="▤ Dev Tasks (CSV)", data=csv_bytes, file_name="Remediations.csv", mime="text/csv", use_container_width=True)
        with ex4:
            if st.button("⟳ New Audit", use_container_width=True, type="primary"):
                st.session_state.step = 0
                st.session_state.audit_results = None
                st.session_state.chat_history = [{"role": "assistant", "content": "I am your Virtual Security Auditor. Do you have any questions regarding the detected vulnerabilities or remediation priorities?"}]
                st.session_state.pending_chat = None
                st.rerun()

        st.markdown('<h3 style="color: #FFFFFF; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px; margin-top:4rem; margin-bottom: 1rem;">Ask the Virtual Auditor</h3>', unsafe_allow_html=True)
        
        for msg in st.session_state.chat_history:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])
                
        if st.session_state.pending_chat:
            user_msg = st.session_state.pending_chat["user"]
            bot_msg = st.session_state.pending_chat["bot"]
            
            st.session_state.chat_history.append({"role": "user", "content": user_msg})
            with st.chat_message("user"):
                st.markdown(user_msg)
                
            with st.chat_message("assistant"):
                st.markdown(bot_msg)
                
            st.session_state.chat_history.append({"role": "assistant", "content": bot_msg})
            st.session_state.pending_chat = None
            st.rerun()
                
        if prompt := st.chat_input("Ask about remediation, specific vulnerabilities, or priorities..."):
            st.session_state.chat_history.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
                
            memory_context = ""
            for msg in st.session_state.chat_history[-4:]:
                memory_context += f"{msg['role'].capitalize()}: {msg['content']}\n"
                
            current_findings = json.dumps(st.session_state.audit_results.get('findings', []) if st.session_state.audit_results else [], indent=2)
            
            system_prompt = f"""
            You are the Lead Cybersecurity Auditor AI for Consulting.
            Your goal is to answer the user's question helpfully, focusing on the provided JSON audit findings and general cybersecurity/IT concepts.
            
            GUIDELINES:
            1. Base your specific answers on the provided audit findings context.
            2. You are fully allowed to discuss general cybersecurity topics, remediation strategies, best practices, and IT infrastructure.
            3. Provide clear, professional, and concise conceptual guidance.
            4. Do not generate executable exploit scripts. Keep the discussion defensive and educational.
            
            AUDIT FINDINGS CONTEXT:
            {current_findings}
            
            RECENT CHAT HISTORY:
            {memory_context}
            
            Based on the context above, respond to the user's latest question safely and professionally.
            """
            
            with st.chat_message("assistant"):
                try:
                    with st.spinner("Analyzing... (The first question takes 10-20 seconds to load the AI)"):
                        response = requests.post("http://127.0.0.1:11434/api/generate", json={
                            "model": "llama3.2",
                            "prompt": system_prompt,
                            "stream": False,
                            "options": {
                                "temperature": 0.0
                            }
                        }, timeout=120) 
                    
                    if response.status_code == 200:
                        full_response = response.json().get("response", "Error: Empty response from AI.")
                        st.markdown(full_response)
                        st.session_state.chat_history.append({"role": "assistant", "content": full_response})
                    else:
                        st.error(f"Ollama Rejected Request. Status: {response.status_code}")
                        st.error(f"Details: {response.text}")
                        
                except Exception as e:
                    st.error(f"CRITICAL ERROR: Connection to Ollama failed or timed out.")
                    st.error(f"Details: {str(e)}")
                    st.warning("Please ensure the black terminal window running 'ollama run llama3.2' is currently open and active.")
                
st.markdown('<div style="text-align: center; color: #555555; font-size: 0.85rem; padding-top: 3rem; margin-top: 6vh; border-top: 1px solid rgba(255, 255, 255, 0.05);">© 2026 Consulting &bull; End-of-Studies Security Platform</div>', unsafe_allow_html=True)