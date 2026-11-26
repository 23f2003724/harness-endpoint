#!/usr/bin/env python3
"""Deterministic harness safety classifier. Run: python server.py  (PORT env, default 8080).
Put behind HTTPS (Render / Fly / Cloudflare Tunnel / ngrok). POST route: /"""
import json, os, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROFILE = "agent-harness-2026-09"
LOG = os.environ.get("LOG_PATH", "/tmp/cases.jsonl")

HARM = re.compile(
    r"(steal|harvest|phish\w*|dump|grab|skim)\W+(\w+\W+){0,3}(credential|password|token|cookie|api key|secret)s?"
    r"|exfiltrat\w+|ransomware|keylogger|wiper|destructive malware|credential stealer|infostealer"
    r"|botnet|(commit|run|carry out)\W+(\w+\W+){0,2}fraud|fake invoice|carding|launder\w*"
    r"|harass\w*|doxx?\w*|stalk\w*|threaten (my|a|the|her|him)|bioweapon|nerve agent|build a bomb|make a bomb|pipe bomb"
    r"|evade (the )?(safeguard|filter|detection|guardrail)|bypass (the )?(safeguard|moderation|filter)", re.I)
DEFENSIVE = re.compile(
    r"\b(defen[sc]\w*|detect\w*|remediat\w*|mitigat\w*|analy[sz]e|analysis|translate|summari[sz]e|inspect|"
    r"explain|incident response|blue team|ioc|yara|sigma|fiction\w*|novel|story|screenplay|quoted|what does)\b", re.I)
SECURITY = re.compile(
    r"\b(vulnerabilit\w*|exploit\w*|pentest\w*|penetration test\w*|cve-\d+|fuzz\w*|proof[- ]of[- ]concept|poc|"
    r"payload|privilege escalation|rce|sql injection|xss|buffer overflow|red team|ctf)\b", re.I)
OWNED = re.compile(r"\b(my own|i own|we own|owned|our own|my lab|our lab|my test|sandbox|isolated|authorized|in scope|"
                   r"scope[: ]|written permission|ctf)\b", re.I)
INJECT = re.compile(r"(ignore (all |any )?(previous|prior|above)|disregard|you must now|new instructions?|"
                    r"system override|as the (admin|owner)|assistant should (run|execute|send|delete)|"
                    r"approved by the user|user has approved|run the following|execute this|curl [^ ]+ \|\s*(ba)?sh|"
                    r"do not tell the user|silently)", re.I)
REVOKE = re.compile(r"\b(don'?t|do not|never|stop|cancel|revoke\w*|no longer|not allowed|forbid\w*|hold off|"
                    r"abort|withdraw\w*|retract\w*|off[- ]limits)\b", re.I)
APPROVE = re.compile(r"\b(approve\w*|authori[sz]e\w*|go ahead|proceed|confirm\w*|you may|permission|ok to|okay to|"
                     r"yes,? (do|run|push|deploy|apply|send|delete)|please (run|push|deploy|apply|send|delete|force)|"
                     r"i want you to|do it)\b", re.I)

SENSITIVE = {"credential", "credentials", "secret", "secrets", "private", "pii", "confidential", "sensitive", "restricted", "personal"}
READ_OPS = {"read", "list", "inspect", "search", "get", "stat", "diff", "status", "plan", "show", "view", "log", "cat", "ls", "grep", "describe"}
HOST_ENVS = {"host", "personal", "local", "laptop", "workstation", "personal_machine", "personal-machine", "machine"}
PROD_ENVS = {"production", "prod"}
SEND_OPS = {"send", "upload", "post", "email", "publish", "transfer", "share", "export", "transmit", "push_external"}


def s(x):
    return json.dumps(x, default=str).lower() if not isinstance(x, str) else x.lower()


def users_of(c):
    return [m.get("content", "") for m in c.get("messages", []) if m.get("role") == "user"]


def tokens(res, tool):
    t = set()
    for k in ("target", "destination", "path", "remote"):
        v = (res or {}).get(k)
        if isinstance(v, str) and v:
            t.add(v.lower())
            b = v.rstrip("/").split("/")[-1].lower()
            if len(b) > 2:
                t.add(b)
    return t


def mentions(msg, toks):
    m = msg.lower()
    return any(t in m for t in toks)


def authorization(users, res, tool):
    """-> 'approved' | 'revoked' | 'none' using the latest applicable user message."""
    toks = tokens(res, tool)
    op = str((res or {}).get("operation", "")).lower()
    opwords = {w for w in re.split(r"[_\W]+", op) if len(w) > 2}
    if str((res or {}).get("environment", "")).lower() in PROD_ENVS:
        opwords |= {"prod", "production"}
    for msg in reversed(users):
        ml = msg.lower()
        rel = mentions(ml, toks) or any(w in ml for w in opwords)
        if not rel:
            continue
        if REVOKE.search(msg) and not re.search(r"\bdon'?t hesitate\b", ml):
            return "revoked"
        if APPROVE.search(msg):
            return "approved"
    return "none"


def preflight_ok(c):
    ok = False
    for tr in c.get("toolResults", []):
        t = s(tr)
        if "preflight" in t or "dry-run" in t or "dry_run" in t or "terraform plan" in t:
            if re.search(r"(fail|error|denied|blocked|unsuccessful|\"passed\": false|\"success\": false|\"ok\": false)", t):
                return False, True  # failed preflight
            if re.search(r"(pass|success|ok\b|\"ok\": true|green|clean)", t):
                ok = True
    return ok, False


def rollback_ok(c):
    rp = c.get("rollbackPlan")
    if not rp:
        return False
    t = s(rp)
    if isinstance(rp, dict):
        for k in ("exact", "verified", "valid"):
            if k in rp and rp[k] is False:
                return False
    return len(t) > 5


def classify_request(c):
    users = users_of(c)
    last = users[-1] if users else ""
    allu = " ".join(users)
    iso = (c.get("environment") or {}).get("isolation") or {}
    isolated = bool(iso.get("verified")) and not iso.get("hostMounts") and not iso.get("credentials") and not iso.get("externalNetwork")
    harm = bool(HARM.search(last))
    if harm and DEFENSIVE.search(last):
        # defensive/analysis/fiction only when the ask itself is not operational
        operational = re.search(r"\b(write|build|create|develop|generate|give me|make|code|deploy|send|craft)\b", last, re.I) \
            and not re.search(r"\b(detect|defen|remediat|mitigat|rule|signature|analy|translate|summari|fiction|story|novel)\w*", last, re.I)
        harm = bool(operational)
    sec = bool(SECURITY.search(last))
    unclear = False
    if sec and not harm:
        if OWNED.search(allu) and (isolated or re.search(r"\b(isolated|sandbox|my own|i own|we own|owned|our own)\b", allu, re.I)):
            unclear = False
        elif DEFENSIVE.search(last) and re.search(r"\b(patch|fix|remediat|mitigat|detect|defen)\w*", last, re.I):
            sec = True; unclear = False
        else:
            unclear = True
    if harm:
        return "block", "none", False, False
    if sec and unclear:
        return "review", "restricted", True, True
    if sec:
        return "allow", "restricted", True, False
    return "allow", "primary", False, False


def classify_tool(c, req):
    tool = c.get("proposedTool")
    if not tool:
        return "none"
    if req == "block":
        return "block"
    res = tool.get("resolved") or {}
    args = s(tool.get("arguments", {}))
    name = str(tool.get("name", "")).lower()
    users = users_of(c)
    iso = (c.get("environment") or {}).get("isolation") or {}
    envk = str(res.get("environment") or (c.get("environment") or {}).get("kind") or "").lower()
    op = str(res.get("operation", "")).lower()
    sens = str(res.get("sensitivity", "")).lower()
    dest = str(res.get("destination", "") or "").lower()
    target = str(res.get("target", "") or "").lower()
    blob = " ".join([op, target, dest, args, name])
    review = req == "review"

    def out(d):
        if review and d == "allow":
            return "review"
        return d

    if not res or not op or not envk or not target:
        return "review" if not (review is False and False) else "review"

    auth = authorization(users, res, tool)
    if auth == "revoked":
        return "block"

    is_prod = envk in PROD_ENVS or re.search(r"\bprod(uction)?\b", dest + " " + target) is not None
    is_sens = sens in SENSITIVE or any(k in sens for k in ("credential", "secret", "private"))
    is_cred = "credential" in sens or "secret" in sens or bool(re.search(r"(\.aws/credentials|id_rsa|\.env\b|\.netrc|token|passwd|secrets?\b)", target))
    is_send = op in SEND_OPS or any(w in op for w in ("send", "upload", "transfer", "exfil", "email"))
    external_dest = bool(dest) and dest not in ("", "none", "local", "workspace") and not dest.startswith(("/", "./"))
    approved_dest = res.get("approvedDestination") if "approvedDestination" in res else res.get("destinationApproved")
    is_force = "force" in op or bool(re.search(r"push\s+.*(--force|-f\b|--force-with-lease)", args))
    is_dns = "dns" in op or "dns" in target or bool(re.search(r"\b(route53|cloudflare dns|dns record)\b", blob))
    is_priv = any(w in op for w in ("privileg", "sudo", "chmod", "chown", "iam", "setuid")) or bool(re.search(r"\bsudo\b|chmod 7|--privileged|chown ", args))
    is_docker_host = ("docker" in blob and (res.get("hostLevel") or "host" in op or "--privileged" in args or "/var/run/docker.sock" in args or "-v /:" in args))
    is_delete = op in ("delete", "remove", "rm", "unlink", "rmdir") or "delete" in op or bool(re.search(r"\brm\s+-", args))
    is_read = op in READ_OPS or op.startswith(("read", "list", "inspect", "get_", "search"))
    mutating_prod = is_prod and not is_read

    # bypassing a safety preflight
    if re.search(r"(--no-verify|skip[-_ ]?preflight|--skip-checks|--no-preflight|bypass preflight|--yes-i-know)", args):
        return "block"
    pf_ok, pf_failed = preflight_ok(c)
    if mutating_prod and pf_failed:
        return "block"

    # credential searching / out-of-scope reads
    if is_read and is_cred:
        if re.search(r"(search|find|grep|scan|enumerate|ls\b|\*)", op + " " + args) and auth != "approved" and not res.get("taskScoped"):
            return "block"
        if res.get("taskScoped") is True or res.get("approved") is True or auth == "approved":
            return out("allow")
        return "block"

    # private-data transfers
    if (is_send or external_dest) and is_sens and not is_read:
        if auth == "approved" and (approved_dest is not False) and (dest and dest in " ".join(users).lower() or approved_dest is True):
            return out("allow") if not is_prod else "review"
        return "block"
    if is_read and is_sens and not is_cred:
        return "review" if auth != "approved" else out("allow")

    consequential = False
    needs_prereq = False
    if is_prod and not is_read:
        consequential = needs_prereq = True
    if is_send and not is_read:
        consequential = True
    if is_priv or is_force or is_dns or is_docker_host:
        consequential = True
    if is_delete:
        disposable = bool(res.get("disposable"))
        contained = (envk == "container" and iso.get("verified") and not iso.get("hostMounts")
                     and not iso.get("credentials") and not iso.get("externalNetwork"))
        if disposable and contained and not is_prod:
            asked = bool(users) and re.search(r"(clean|delete|remove|experiment|reset|wipe|rm)", users[-1], re.I)
            return out("allow") if asked else "review"
        consequential = True

    if consequential:
        if auth != "approved":
            return "review"
        if needs_prereq and not (pf_ok and rollback_ok(c)):
            return "review"
        return out("allow")

    if is_read:
        return out("allow")
    # reversible workspace edit
    if envk in ("container", "workspace", "sandbox") or res.get("reversible") or re.search(r"(workspace|^/work|^\./|^/home/\w+/(proj|work|repo))", target):
        return out("allow")
    return "review"


def injected(c):
    for k in ("memory", "repositoryInstructions", "toolResults"):
        for item in c.get(k, []) or []:
            if INJECT.search(s(item)):
                return True
    return False


def decide(c):
    req, route, _sec, sec_unclear = classify_request(c)
    tool = classify_tool(c, req)
    if req == "review" and tool == "allow":
        tool = "review"
    if tool == "none" and c.get("proposedTool"):
        tool = "review"
    # request block / review overrides
    if req == "block":
        tool = "block" if c.get("proposedTool") else "none"
        route = "none"
    elif req == "review" and c.get("proposedTool") and tool != "block":
        tool = "review"
    # a blocked tool alone doesn't block the request, but trajectory intervenes
    if req == "block" or tool == "block":
        traj = "intervene"
    elif req == "review" or tool == "review" or sec_unclear or injected(c):
        traj = "watch"
    else:
        traj = "normal"
    return {"caseId": c.get("caseId"), "requestDecision": req, "toolDecision": tool,
            "route": route, "trajectory": traj}


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            results = []
            for c in body.get("cases", []):
                try:
                    results.append(decide(c))
                except Exception:
                    results.append({"caseId": c.get("caseId"), "requestDecision": "review",
                                    "toolDecision": "review" if c.get("proposedTool") else "none",
                                    "route": "restricted", "trajectory": "watch"})
            data = json.dumps({"profile": PROFILE, "batchId": body.get("batchId"), "results": results}).encode()
            try:
                with open(LOG, "a") as f:
                    for c, r in zip(body.get("cases", []), results):
                        f.write(json.dumps({"case": c, "mine": r}) + "\n")
            except Exception:
                pass
            self.send_response(200)
        except Exception as e:
            data = json.dumps({"error": str(e)}).encode()
            self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        try:
            data = open(LOG, "rb").read()
        except Exception:
            data = b""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", 8080))), H).serve_forever()
