# Agentic CI/CD Framework

Python-based DevSecOps pipeline powered by Google ADK + Claude.

## Architecture

```
Event (push/PR/cron)
  └─ Orchestrator (ADK multi-agent)
       ├─ CIAgent           — Docker build + pytest
       ├─ SecurityAgent     — Trivy CVE · Semgrep SAST · Gitleaks · Checkov
       ├─ ValidationAgent   — K8s manifest lint · ArgoCD diff
       ├─ [HITL gate]       — human approval if any agent blocked
       ├─ DeployAgent       — ArgoCD sync + health wait
       ├─ ObservabilityAgent — pod health + auto-rollback
       ├─ RuntimeSecurityAgent — Falco + audit events
       └─ GitOpsSyncAgent   — drift detection (cron)
```

## Quick start

```bash
cp .env.example .env
# Fill in ANTHROPIC_API_KEY, ARGOCD_*, GITHUB_TOKEN

pip install -r requirements.txt

# One-shot pipeline run
DRY_RUN=true python main.py pipeline

# Webhook server (receives GitHub webhooks)
python main.py server

# GitOps sync check only
python main.py sync
```

## Adding a custom agent

1. Create `agents/custom/my_agent.py` inheriting `BaseAgent`
2. Implement `name`, `description`, `tools`, `system_prompt`, `run()`
3. Register it: `orchestrator.register_agent(MyAgent(), stage="post_approval")`

See `agents/custom/performance_agent.py` for a complete example.

## Security tools required

| Tool | Install |
|------|---------|
| Trivy | `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \| sh` |
| Semgrep | `pip install semgrep` |
| Gitleaks | `brew install gitleaks` |
| Checkov | `pip install checkov` |

## GitHub secrets needed

- `ANTHROPIC_API_KEY`
- `ARGOCD_AUTH_TOKEN`
- `ARGOCD_SERVER`
- `KUBECONFIG_BASE64` — base64-encoded kubeconfig for Docker Desktop
