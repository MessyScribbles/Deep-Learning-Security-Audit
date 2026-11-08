from fastapi import FastAPI
from pydantic import BaseModel
from transformers import pipeline
import requests
import json
import datetime

app = FastAPI()

# ─── STAGE 1: THE EXTRACTOR (DistilBERT) ───
try:
    print("Loading Neural Network...")
    classifier = pipeline("ner", model=r"D:\Neural Net Model\model_final", aggregation_strategy="simple",local_files_only=True)
    print("DistilBERT Ready.")
except Exception as e:
    print(f"Error loading model: {e}")
    classifier = None

class ScanRequest(BaseModel):
    client_name: str
    app_name: str
    architecture_text: str

# ─── THE SYMBOLIC ENGINE (Threat Matrix) ───
THREAT_MATRIX = {
    "FILE_UPLOAD": {
        "vulnerability": "Unrestricted File Upload",
        "cwe": "CWE-434",
        "severity": "Critical",
        "tier": "high",
        "description": "The application allows file uploads. If the server saves these directly to the web-root without validation, attackers can achieve RCE.",
        "remediation": "Store uploaded files outside the web-root and enforce strict MIME-type validation."
    },
    "AUTHENTICATION": {
        "vulnerability": "Authentication Brute-Force Risk",
        "cwe": "CWE-307",
        "severity": "High",
        "tier": "high",
        "description": "A user login portal was detected. Highly vulnerable to automated credential stuffing.",
        "remediation": "Implement progressive rate-limiting, CAPTCHA after 3 failed attempts, and an account lockout policy."
    },
    "PAYMENT": {
        "vulnerability": "Insecure Financial Transaction",
        "cwe": "CWE-319",
        "severity": "High",
        "tier": "high",
        "description": "Financial transaction capabilities detected. Lack of strict verification can lead to payment manipulation.",
        "remediation": "Enforce strict server-side validation of all cart totals and ensure TLS 1.3 is used."
    },
    "EXTERNAL_API": {
        "vulnerability": "Insecure API Communication",
        "cwe": "CWE-20",
        "severity": "Medium",
        "tier": "medium",
        "description": "The system communicates with third-party APIs. Exposes the internal architecture to SSRF or injection.",
        "remediation": "Implement strict input validation for all API responses."
    },
    "ADMIN_PRIVILEGES": {
        "vulnerability": "Broken Access Control (Admin)",
        "cwe": "CWE-285",
        "severity": "High",
        "tier": "high",
        "description": "Administrative functionalities detected. Standard users may elevate privileges without strict RBAC.",
        "remediation": "Enforce strict RBAC checks on every protected endpoint."
    },
    "REPORTING": {
        "vulnerability": "Sensitive Data Exposure (Reports)",
        "cwe": "CWE-200",
        "severity": "Medium",
        "tier": "medium",
        "description": "The system generates downloadable reports. IDOR vulnerabilities are likely.",
        "remediation": "Use unguessable UUIDs for file storage and verify session ownership."
    }
}

# ─── STAGE 2: THE REASONER (Llama-3 Semantic Ontology) ───
# ─── STAGE 2: THE REASONER (Llama-3 Semantic Ontology) ───
def extract_hybrid_features(architecture_text: str):
    text_lower = architecture_text.lower()
    raw_triggers = set()
    
    if classifier:
        try:
            entities = classifier(architecture_text)
            for entity in entities:
                word = entity['word'].lower()
                for k in ["upload", "import", "pdf", "file"]:
                    if k in word: raw_triggers.add("FILE_UPLOAD")
                for k in ["login", "auth", "account", "sso"]:
                    if k in word: raw_triggers.add("AUTHENTICATION")
                for k in ["api", "external", "partner"]:
                    if k in word: raw_triggers.add("EXTERNAL_API")
                for k in ["admin", "backoffice", "system"]:
                    if k in word: raw_triggers.add("ADMIN_PRIVILEGES")
                for k in ["payment", "transfer", "card", "checkout", "transaction"]:
                    if k in word: raw_triggers.add("PAYMENT")
                for k in ["report", "export", "csv", "statistic"]:
                    if k in word: raw_triggers.add("REPORTING")
        except Exception as e:
            print(f"DistilBERT Error: {e}")

    keywords = {
        "PAYMENT": ["payment", "checkout", "bank"],
        "FILE_UPLOAD": ["upload", "attachment"],
        "AUTHENTICATION": ["login", "sso", "credentials"],
        "EXTERNAL_API": ["api", "third-party"],
        "ADMIN_PRIVILEGES": ["admin", "backoffice"],
        "REPORTING": ["report", "export"]
    }
    for feature, kws in keywords.items():
        if any(kw in text_lower for kw in kws):
            raw_triggers.add(feature)

    if not raw_triggers:
        return {"verified_risks": [], "exposure": ["Unknown Exposure"]}

    system_prompt = f"""
    You are a Lead Security Auditor. Evaluate these extracted triggers: {list(raw_triggers)}
    against this architecture: "{architecture_text}"
    
    Here is the Semantic Ontology for the flagged risks. A risk is ONLY valid if it meets the EXACT criteria:
    - FILE_UPLOAD: The user interface must contain a mechanism allowing external client files to be written to the server's storage.
    - PAYMENT: The architecture must facilitate the active exchange of monetary currency or financial value.
    - AUTHENTICATION: The system must require users to prove their identity (e.g., passwords, SSO, MFA) to access a restricted boundary.
    - EXTERNAL_API: The system must actively communicate with third-party or external services outside its own network.
    - ADMIN_PRIVILEGES: The system must contain privileged roles (admins, backoffice) that have elevated access over standard users.
    - REPORTING: The system must actively generate, export, or download data reports (e.g., CSV, PDF).
    
    Output a JSON object. You MUST evaluate the text against the ontology definitions in a "reasoning" field BEFORE outputting the arrays.
    
    Format EXACTLY like this example:
    {{
        "reasoning": "The system syncs with SAP (EXTERNAL_API) and has Admins (ADMIN_PRIVILEGES) and SSO (AUTHENTICATION). It explicitly negates payments, so PAYMENT is false. Users cannot upload, so FILE_UPLOAD is false.",
        "verified_risks": ["AUTHENTICATION", "EXTERNAL_API", "ADMIN_PRIVILEGES"],
        "exposure": "Public / Internet"
    }}
    """
    
    try:
        response = requests.post("http://localhost:11434/api/generate", json={
            "model": "llama3",
            "prompt": system_prompt,
            "stream": False,
            "format": "json"
        }, timeout=20)
        
        result_json = json.loads(response.json()["response"])
        verified_risks = result_json.get("verified_risks", [])
        exposure_val = result_json.get("exposure", "Unknown Exposure")
        final_exposure = [exposure_val] if exposure_val in ["Public / Internet", "VPN Restricted", "Internal Network"] else ["Unknown Exposure"]
        
    except Exception as e:
        print(f"Llama-3 Batch Error: {e}")
        verified_risks = list(raw_triggers)
        final_exposure = ["Unknown Exposure"]

    return {"verified_risks": verified_risks, "exposure": final_exposure}

@app.post("/api/scan")
async def process_security_scan(request: ScanRequest):
    hybrid_result = extract_hybrid_features(request.architecture_text)
    
    verified_keys = hybrid_result.get("verified_risks", [])
    findings = [THREAT_MATRIX[f] for f in verified_keys if f in THREAT_MATRIX]
    final_exposure = hybrid_result.get("exposure", ["Unknown Exposure"])
    
    high_count = sum(1 for f in findings if f["tier"] == "high")
    med_count = sum(1 for f in findings if f["tier"] == "medium")
    overall_risk = "CRITICAL" if high_count > 0 else ("MEDIUM" if med_count > 0 else "LOW")
    if not findings: overall_risk = "LOW"

    dynamic_user_types = []
    if "Internal Network" in final_exposure:
        dynamic_user_types = ["Admin", "Internal Users"]
    elif "VPN Restricted" in final_exposure:
        dynamic_user_types = ["Authenticated Employees"]
        if "ADMIN_PRIVILEGES" in verified_keys: dynamic_user_types.append("Admin")
    else: 
        dynamic_user_types = ["Anonymous"]
        if "AUTHENTICATION" in verified_keys: dynamic_user_types.append("Authenticated")
        if "ADMIN_PRIVILEGES" in verified_keys: dynamic_user_types.append("Admin")

    return {
        "meta": {
            "client": request.client_name,
            "app": request.app_name,
            "date": datetime.datetime.now().strftime("%Y-%m-%d"),
            "audit_id": {datetime.datetime.now().strftime('%Y%m%d%H%M')}
        },
        "summary": {
            "overall_risk": overall_risk,
            "high": high_count,
            "medium": med_count,
            "low": 0,
            "overview": "Neuro-Symbolic scan completed using DistilBERT extraction and Llama-3 semantic validation."
        },
        "context": {
            "exposure": final_exposure,
            "features": verified_keys,
            "user_types": dynamic_user_types,
            "data_types": ["Standard Application Data"]
        },
        "findings": findings
    }