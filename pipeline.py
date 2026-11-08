# ================================================================
# FILE: pipeline.py
# PURPOSE: Conversational security audit pipeline.
# Multi-label detection, clarification loop, Q&A mode.
# Neuro-Symbolic AI Guardrail implemented for false-positive suppression.
# Exports to PDF or JSON.
# ================================================================

import torch, chromadb, json, re, spacy
from datetime import datetime
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sentence_transformers import SentenceTransformer

# ── LOAD ─────────────────────────────────────────────────────────
print("Loading Neural System...")
DEVICE        = torch.device("cuda" if torch.cuda.is_available() else "cpu")
clf_tokenizer = AutoTokenizer.from_pretrained("./model_final", local_files_only=True)
clf_model     = AutoModelForSequenceClassification.from_pretrained("./model_final", local_files_only=True)
clf_model.eval()
clf_model     = clf_model.to(DEVICE)

print("Loading RAG Knowledge Base...")
embedder      = SentenceTransformer("all-MiniLM-L6-v2")
chroma_client = chromadb.PersistentClient(path="./rag_knowledge_base")
collection    = chroma_client.get_collection("security_knowledge")

print("Loading Neuro-Symbolic Grammar Engine...")
nlp = spacy.load("en_core_web_sm")

LABELS    = ["Authentication Failure","CSRF","IDOR","SQL Injection","XSS","XXE"]
THRESHOLD = 0.30

BOLD="\033[1m"; RESET="\033[0m"; CYAN="\033[96m"
GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"
BLUE="\033[94m"; DIM="\033[2m"; SEP="═"*68; SEP2="─"*68

SEV_COL = {"Critical":RED,"High":YELLOW,"Medium":BLUE,"Low":GREEN}

ATTACK_CHAINS = {
    "SQL Injection":{"chain":["User submits input via form or parameter","Application builds database query from raw input","Crafted input modifies query logic","Database executes unintended commands","Data extracted, modified, or deleted"],"primary":"Database compromise, authentication bypass, data breach.","secondary":"Exposure of all data accessible to the database account."},
    "XSS":{"chain":["Attacker submits script via input field","Application stores or reflects input without encoding","Victim browser renders the injected script","Script executes in victim's browser context","Session stolen or victim actions forged"],"primary":"Account takeover via session hijacking.","secondary":"Keylogging, redirection, or defacement of victim browsers."},
    "IDOR":{"chain":["Authenticated user notes a resource identifier","User modifies identifier to reference another user's resource","Server returns resource without ownership check","Attacker accesses or modifies other users' data","Horizontal privilege escalation at scale"],"primary":"Unauthorized access to other users' data.","secondary":"Bulk extraction by enumerating sequential identifiers."},
    "Authentication Failure":{"chain":["Attacker targets login or password reset endpoint","No rate limiting or lockout enforced","Automated credential attack runs unimpeded","Valid credentials obtained","Full account access without authorization"],"primary":"Account compromise and unauthorized data access.","secondary":"Privilege escalation if the account has elevated roles."},
    "CSRF":{"chain":["Attacker crafts forged request for a state-changing endpoint","Victim visits page containing the forged request","Browser sends request with victim's session cookie","Server processes as if from the legitimate user","Unauthorized action executed on victim's behalf"],"primary":"Unauthorized account modifications on behalf of users.","secondary":"Particularly severe on administrative endpoints."},
    "XXE":{"chain":["Application accepts XML from external source","Parser has external entity resolution enabled","Attacker embeds malicious entity declaration","Parser resolves entity, reading files or making requests","Server files exposed or internal network probed"],"primary":"Arbitrary file read from server filesystem.","secondary":"SSRF via outbound entity resolution."}
}

CONTEXT_KW = {
    "user_types":{"anonymous":["anonymous","public","unauthenticated"],"authenticated":["authenticated","logged in","user account","registered"],"administrator":["admin","administrator","superuser"],"external":["partner","third party","external","api client"]},
    "data_types":{"personal":["personal","pii","name","email","address"],"financial":["financial","payment","bank","transaction","card","billing"],"documents":["document","file","upload","attachment","pdf"],"technical":["log","config","database","credential","token","key"]},
    "exposure":{"internet":["internet","public","web","online","external"],"vpn":["vpn","private network","internal","intranet"],"api":["api","rest","endpoint","service","webhook"]},
    "features":{"authentication":["login","auth","password","credential","session","token","oauth","jwt"],"file_upload":["upload","file","attachment","import","document"],"payment":["payment","transaction","billing","checkout","invoice"],"admin":["admin","backoffice","dashboard","management","console"],"api":["api","endpoint","rest","integration","webhook"]}
}

CONTRA = [
    (["public","internet"],["vpn only","internal only","no external"],"Application described as both publicly accessible and internal-only"),
    (["no authentication","anonymous"],["authenticated users","login required"],"Authentication described as both absent and required"),
    (["read only"],["update","delete","modify","write"],"Application described as both read-only and write-capable"),
    (["no file upload"],["upload","file submission","attachment"],"File upload described as both absent and present")
]

print("System ready.\n")

# ── CORE CLASSIFICATION ──────────────────────────────────────────
def classify(text, max_length=256, stride=128):
    # 1. Semantic Segmentation
    sentences = [s.strip() for s in re.split(r'(?<=[.!?]) +', text) if len(s.strip()) > 10]
    if not sentences:
        sentences = [text]

    all_findings_map = {}
    global_probs = {label: [] for label in LABELS}

    # 2. Bi-Directional Guardrail Dictionaries
    MITIGATION_KEYWORDS = ["prevent", "mitigat", "block", "disable", "sanitiz", "encode", "guard"]
    
    # The Positive Validation Map
    VULN_CONTEXT = {
        "CSRF": ["csrf", "forgery", "token", "state-changing", "request", "session"],
        "IDOR": ["url", "parameter", "increment", "identifier", "id", "reference", "sequential"],
        "Authentication Failure": ["password", "login", "captcha", "lock", "brute", "guess"],
        "SQL Injection": ["sql", "query", "database", "injection", "select"],
        "XSS": ["xss", "script", "html", "render", "dom", "react"],
        "XXE": ["xml", "xxe", "entity", "parser", "dtd"]
    }

    print(f"\n{CYAN}{'='*55}")
    print(f"🔍 NLP X-RAY DEBUGGER: BI-DIRECTIONAL GUARDRAILS")
    print(f"{'='*55}{RESET}")

    # 3. Run Neural inference on each sentence
    for idx, sentence in enumerate(sentences, 1):
        print(f"\n{BOLD}Sentence {idx}:{RESET} {sentence}")
        
        tokens = clf_tokenizer(sentence, return_tensors="pt", truncation=True, max_length=max_length)
        inputs = {k: v.to(DEVICE) for k, v in tokens.items()}
        
        with torch.no_grad():
            out = clf_model(**inputs)
        
        probs = torch.sigmoid(out.logits)[0]
        
        for i, p in enumerate(probs):
            c = p.item()
            label = LABELS[i]
            
            # 4. THE BI-DIRECTIONAL LOGIC GATE
            if c >= THRESHOLD:
                print(f"  {RED}⚠ RAW NEURAL HIT:{RESET} {label} ({c*100:.1f}%)")
                
                s_lower = sentence.lower()
                
                # Rule A: Negative Guardrail (Token-Aware Regex to prevent Substring Collisions)
                if any(re.search(r'\b' + kw, s_lower) for kw in MITIGATION_KEYWORDS):
                    print(f"  {GREEN}🛡️ NEGATIVE GUARDRAIL:{RESET} Suppressed '{label}' (Mitigation context detected)")
                    c = 0.0
                    
                # Rule B: Positive Guardrail (Does the vocabulary match the claim?)
                elif label in VULN_CONTEXT and not any(kw in s_lower for kw in VULN_CONTEXT[label]):
                    print(f"  {YELLOW}🛡️ POSITIVE GUARDRAIL:{RESET} Cross-Class Entanglement! '{label}' lacks contextual vocabulary. Suppressed.")
                    c = 0.0

            global_probs[label].append(c)
            
            # 5. Log validated findings
            if c >= THRESHOLD:
                if label not in all_findings_map or c > all_findings_map[label]["raw"]:
                    all_findings_map[label] = {
                        "vulnerability": label,
                        "confidence":    round(c * 100, 1),
                        "raw":           c,
                        "tier":          "high" if c >= 0.75 else "medium" if c >= 0.50 else "low"
                    }

    print(f"\n{CYAN}{'='*55}{RESET}\n")

    findings = list(all_findings_map.values())
    findings.sort(key=lambda x: x["raw"], reverse=True)
    
    all_p_dict = {
        label: round(sum(scores) / len(scores), 4) if scores else 0.0 
        for label, scores in global_probs.items()
    }
    
    return findings, all_p_dict
# ── RAG & REPORTING ──────────────────────────────────────────────

def retrieve(vuln):
    content = {}
    for field,query in {
        "description": f"{vuln} vulnerability mechanism",
        "remediation": f"fix prevent {vuln}",
        "standard":    f"OWASP {vuln} standard"
    }.items():
        try:
            r = collection.query(
                query_texts=[query],
                where={"$and":[{"vulnerability_class":{"$eq":vuln}},{"field_type":{"$eq":field}}]},
                n_results=2
            )
            if r["documents"] and r["documents"][0]:
                meta = r["metadatas"][0][0]
                raw  = " ".join(r["documents"][0])
                sents = [s.strip() for s in raw.replace("\n"," ").split(".") if len(s.strip())>40]
                content[field] = {
                    "text":     ". ".join(sents[:3])+"." if sents else raw[:300],
                    "source":   meta.get("document",""),
                    "cwe":      meta.get("cwe",""),
                    "owasp":    meta.get("owasp",""),
                    "severity": meta.get("severity","Medium"),
                    "cvss":     meta.get("cvss","N/A")
                }
        except:
            content[field] = None
    return content


def detect_context(text):
    tl  = text.lower()
    ctx = {k:{} for k in CONTEXT_KW}
    for cat,groups in CONTEXT_KW.items():
        for label,kws in groups.items():
            if any(kw in tl for kws in groups.values() for kw in kws):
                ctx[cat][label] = True
    return {k:list(v.keys()) for k,v in ctx.items()}


def detect_incoherences(text, findings):
    tl   = text.lower()
    incs = []
    for pos,neg,msg in CONTRA:
        if any(k in tl for k in pos) and any(k in tl for k in neg):
            incs.append(msg)
    low = [f for f in findings if f["tier"]=="low"]
    if low:
        names = ", ".join(f["vulnerability"] for f in low)
        incs.append(f"Low confidence detections ({names}) — description may lack sufficient detail.")
    return incs


def overall_risk(findings):
    rank = {"Critical":4,"High":3,"Medium":2,"Low":1}
    best = 0
    sev  = "Low"
    for f in findings:
        if f["tier"] in ["high","medium"]:
            r = retrieve(f["vulnerability"])
            s = r.get("description",{}).get("severity","Medium") if r.get("description") else "Medium"
            if rank.get(s,0) > best:
                best = rank[s]; sev = s
    if not findings: return "LOW"
    return sev.upper()


def build_report(description, client, app_name):
    findings, all_p = classify(description)
    ctx   = detect_context(description)
    incs  = detect_incoherences(description, findings)
    risk  = overall_risk(findings)
    detail = []
    for f in findings:
        rag  = retrieve(f["vulnerability"])
        d    = rag.get("description") or {}
        detail.append({
            "vulnerability": f["vulnerability"],
            "confidence":    f["confidence"],
            "tier":          f["tier"],
            "severity":      d.get("severity","Medium"),
            "cvss":          d.get("cvss","N/A"),
            "cwe":           d.get("cwe",""),
            "owasp":         d.get("owasp",""),
            "attack_chain":  ATTACK_CHAINS.get(f["vulnerability"],{}),
            "description":   (rag.get("description") or {}).get("text","Not available."),
            "remediation":   (rag.get("remediation") or {}).get("text","Not available."),
            "standard":      (rag.get("standard") or {}).get("text","Not available."),
            "sources": {
                "description": (rag.get("description") or {}).get("source",""),
                "remediation": (rag.get("remediation") or {}).get("source",""),
                "standard":    (rag.get("standard") or {}).get("source","")
            }
        })
    return {
        "meta": {
            "client":    client,
            "app":       app_name,
            "date":      datetime.now().strftime("%Y-%m-%d"),
            "audit_id":  f"AUDIT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "summary": {
            "total":         len(findings),
            "high":          len([f for f in findings if f["tier"]=="high"]),
            "medium":        len([f for f in findings if f["tier"]=="medium"]),
            "low":           len([f for f in findings if f["tier"]=="low"]),
            "overall_risk":  risk
        },
        "all_probs":         all_p,
        "findings":          detail,
        "context":           ctx,
        "incoherences":      incs,
        "input":             description,
        "disclaimer":        "This report was generated by an AI predictive system. Findings are probabilistic predictions, not confirmed vulnerabilities. Dynamic testing with BurpSuite is recommended post-deployment."
    }

def wrap(text, width=66):
    words,line,lines = text.split(),"  ",[]
    for w in words:
        if len(line)+len(w)>width: lines.append(line); line="  "+w+" "
        else: line+=w+" "
    if line.strip(): lines.append(line)
    return "\n".join(lines)

def display(report):
    m,s = report["meta"],report["summary"]
    print(f"\n{SEP}")
    print(f"{BOLD}  SECURITY AUDIT REPORT{RESET}")
    print(f"  {report['meta']['app']}  |  Prepared for: {report['meta']['client']}")
    print(f"  {m['date']}  |  Ref: {m['audit_id']}")
    print(SEP)

    rc = {"CRITICAL":RED,"HIGH":YELLOW,"MEDIUM":BLUE,"LOW":GREEN}.get(s["overall_risk"],"")
    print(f"\n  {rc}{BOLD}Overall Risk: {s['overall_risk']}{RESET}  |  "
          f"{s['total']} finding(s)  |  "
          f"High: {s['high']}  Med: {s['medium']}  Low: {s['low']}")

    print(f"\n  {'#':<3}{'Vulnerability':<26}{'Confidence':>10}  {'Tier':<8}{'Severity'}")
    print(f"  {'─'*58}")
    for i,f in enumerate(report["findings"],1):
        tc = {GREEN:"high",YELLOW:"medium",RED:"low"}.get
        tier_disp = {"high":f"{GREEN}HIGH{RESET}","medium":f"{YELLOW}MED{RESET}","low":f"{RED}LOW{RESET}"}.get(f["tier"],"")
        sc = SEV_COL.get(f["severity"],"")
        print(f"  {i:<3}{f['vulnerability']:<26}{f['confidence']:>9.1f}%  {tier_disp:<8}{sc}{f['severity']}{RESET}")

    for i,f in enumerate(report["findings"],1):
        sc = SEV_COL.get(f["severity"],"")
        print(f"\n{SEP2}")
        print(f"  {BOLD}{sc}[{f['severity']}] Finding {i}: {f['vulnerability']}{RESET}  "
              f"({f['confidence']}% confidence)")
        print(f"  {f['cwe']}  |  OWASP {f['owasp']}  |  CVSS {f['cvss']}")
        if f["tier"]=="low":
            print(f"  {YELLOW}⚠ Low confidence — review before acting{RESET}")
        print(f"\n  {BOLD}Description:{RESET}")
        print(wrap(f["description"]))
        chain = f["attack_chain"]
        if chain.get("chain"):
            print(f"\n  {BOLD}Attack chain:{RESET}")
            for j,step in enumerate(chain["chain"],1):
                print(f"    {j}. {step}")
        print(f"\n  {BOLD}Remediation:{RESET}")
        print(wrap(f["remediation"]))
        if f["sources"]["remediation"]:
            print(f"\n  {DIM}Source: {f['sources']['remediation']}{RESET}")

    if report["incoherences"]:
        print(f"\n{SEP2}")
        print(f"{BOLD}  Incoherences / Ambiguities{RESET}")
        for inc in report["incoherences"]:
            print(f"  ⚠  {inc}")

    print(f"\n{SEP2}")
    print(f"  {DIM}{report['disclaimer']}{RESET}")
    print(f"\n{SEP}\n")

def answer(question, session):
    q        = question.lower().strip()
    report   = session["report"]
    findings = report["findings"]
    if not findings:
        return "No findings detected above threshold."
    primary = findings[0]

    target = primary
    for f in findings:
        if f["vulnerability"].lower() in q:
            target = f; break

    if any(w in q for w in ["list","all","findings","how many","summary"]):
        lines = [f"{len(findings)} finding(s) detected:\n"]
        for i,f in enumerate(findings,1):
            note = " ⚠ low confidence" if f["tier"]=="low" else ""
            lines.append(f"  {i}. {f['vulnerability']} — {f['confidence']}% ({f['severity']}){note}")
        return "\n".join(lines)

    if any(w in q for w in ["why","explain","reason"]):
        return (f"{target['vulnerability']} ({target['confidence']}%):\n\n"
                f"{target['description']}\n\nSource: {target['sources']['description']}")

    if any(w in q for w in ["fix","remediat","prevent","how to"]):
        return (f"Remediation for {target['vulnerability']}:\n\n"
                f"{target['remediation']}\n\nSource: {target['sources']['remediation']}")

    if any(w in q for w in ["severity","cvss","risk","dangerous"]):
        lines = ["Severity overview:\n"]
        for f in findings:
            lines.append(f"  {f['vulnerability']}: {f['severity']} (CVSS {f['cvss']})")
        return "\n".join(lines)

    if any(w in q for w in ["owasp","cwe","standard","reference"]):
        return (f"{target['vulnerability']}:\n"
                f"  CWE:   {target['cwe']}\n"
                f"  OWASP: {target['owasp']}\n\n"
                f"{target['standard']}\n\nSource: {target['sources']['standard']}")

    if any(w in q for w in ["attack","chain","exploit","scenario"]):
        c = target["attack_chain"]
        return ("Attack chain:\n\n" +
                "\n".join(f"  {i+1}. {s}" for i,s in enumerate(c.get("chain",[]))) +
                f"\n\nPrimary: {c.get('primary','')}")

    if any(w in q for w in ["confidence","sure","certain"]):
        return (f"{target['vulnerability']}: {target['confidence']}% ({target['tier']} tier)\n\n" +
                "\n".join(f"  {f['vulnerability']}: {f['confidence']}% ({f['tier']})"
                           for f in findings))

    return (f"I can discuss any of the {len(findings)} finding(s).\n"
            f"Detected: {', '.join(f['vulnerability'] for f in findings)}\n\n"
            "Ask about: 'explain [vulnerability]', 'remediation', "
            "'severity', 'attack chain', 'OWASP references', 'list all findings'")

CLARIFY_Q = [
    "What type of application is this? (web app, API, mobile, etc.)",
    "How does the application handle user input? (forms, parameters, file uploads, etc.)",
    "What data does it store or process? (user data, financial data, files, etc.)",
    "Does it use authentication? If so, how? (login, JWT, OAuth, etc.)",
    "What external systems does it connect to? (database, APIs, payment systems, etc.)"
]

MANDATORY_KW = [
    "input","user","form","field","parameter","request","data","value",
    "login","auth","api","endpoint","database","query","file","upload",
    "session","token","url","application","app","system","server","client",
    "pass","store","process","validate","access","return","display","render"
]

def check_quality(text):
    words   = text.lower().split()
    matches = sum(1 for kw in MANDATORY_KW if kw in text.lower())
    if len(words) < 15: return False,"too_short"
    if matches < 2:     return False,"too_vague"
    return True,"ok"

def run():
    print(f"\n{SEP}")
    print(f"{BOLD}{CYAN}  SECURITY AUDIT ASSISTANT{RESET}")
    print(f"  Neural Network-Based Vulnerability Analysis")
    print(f"{SEP}\n")

    client   = input("  Prepared for (client name): ").strip() or "Consulting Client"
    app_name = input("  Application name:           ").strip() or "Application Under Review"

    session = {"description":"","rounds":0,"max_rounds":2,"report":None}

    print(f"\n{BOLD}Describe the application:{RESET}")
    print(f"{DIM}Include: input handling, authentication, data types, external connections{RESET}\n")

    initial = input(f"{CYAN}You:{RESET} ").strip()
    if not initial: return
    session["description"] = initial

    while session["rounds"] < session["max_rounds"]:
        ok,reason = check_quality(session["description"])
        if ok: break
        session["rounds"] += 1
        q = ("Could you describe how the application handles user input and what data it processes?"
             if reason=="too_short"
             else CLARIFY_Q[(session["rounds"]-1) % len(CLARIFY_Q)])
        print(f"\n{YELLOW}Assistant:{RESET} Need more context.")
        print(f"  {q}")
        print(f"  {DIM}(Round {session['rounds']}/{session['max_rounds']}){RESET}\n")
        more = input(f"{CYAN}You:{RESET} ").strip()
        if more: session["description"] += " " + more
        else: break

    print(f"\n{YELLOW}Assistant:{RESET} Analyzing...\n")
    report          = build_report(session["description"], client, app_name)
    session["report"] = report
    display(report)

    print(f"\n{BOLD}Export:{RESET}")
    print("  1. PDF + JSON")
    print("  2. JSON only")
    print("  3. Skip")
    choice = input("  Choose (1/2/3): ").strip()

    app_slug  = app_name.replace(" ","_")[:20]
    client_slug = client.replace(" ","_")[:15]
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"SecurityAudit_{app_slug}_{client_slug}_{ts}"

    if choice in ["1","2"]:
        jpath = f"{base_name}.json"
        json.dump(report, open(jpath,"w",encoding="utf-8"), indent=2, ensure_ascii=False)
        print(f"{DIM}JSON: {jpath}{RESET}")

    if choice == "1":
        try:
            from pdf_report import generate_pdf
            ppath = generate_pdf(report, output_path=f"{base_name}.pdf")
            print(f"{DIM}PDF:  {ppath}{RESET}")
        except ImportError:
            print(f"{YELLOW}pdf_report.py not found. JSON saved only.{RESET}")

    print(f"\n{SEP}")
    print(f"{BOLD}  Q&A MODE — Ask about any finding{RESET}")
    print(f"  'new info' to add context  |  'exit' to quit")
    print(f"{SEP}\n")

    while True:
        user_input = input(f"{CYAN}You:{RESET} ").strip()
        if not user_input: continue
        if user_input.lower() in ["exit","quit","done"]:
            print(f"\n{YELLOW}Assistant:{RESET} Session complete.\n"); break
        if user_input.lower() in ["new info","add","update"]:
            print(f"\n{YELLOW}Assistant:{RESET} Provide additional information:\n")
            more = input(f"{CYAN}You:{RESET} ").strip()
            if more:
                session["description"] += " " + more
                print(f"\n{YELLOW}Assistant:{RESET} Re-analyzing...\n")
                report            = build_report(session["description"], client, app_name)
                session["report"] = report
                display(report)
            continue
        print(f"\n{YELLOW}Assistant:{RESET} {answer(user_input, session)}\n")

if __name__ == "__main__":
    run()