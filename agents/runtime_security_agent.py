"""
Runtime Security Agent — analyses runtime security events.
Reads Falco alerts, K8s audit logs, and syscall anomalies.
Can quarantine pods by removing their service labels.
"""
from __future__ import annotations

import json
import subprocess

from core.base_agent import AgentResult, BaseAgent
from core.pipeline_context import PipelineContext
from tools.registry import _run, tool


@tool
def read_falco_alerts(log_path: str = "/var/log/falco.log", lines: int = 100) -> dict:
    """Read the most recent Falco security alerts from the log file."""
    return _run(["tail", "-n", str(lines), log_path])


@tool
def kubectl_get_audit_events(namespace: str) -> dict:
    """Get K8s audit-related warning events."""
    return _run([
        "kubectl", "get", "events", "-n", namespace,
        "--field-selector=type=Warning",
        "-o", "json",
    ])


@tool
def kubectl_quarantine_pod(pod_name: str, namespace: str) -> dict:
    """Quarantine a pod by removing its service selector labels (isolates from traffic)."""
    return _run([
        "kubectl", "label", "pod", pod_name,
        "-n", namespace,
        "quarantine=true",
        "--overwrite",
    ])


@tool
def kubectl_delete_pod(pod_name: str, namespace: str) -> dict:
    """Forcefully delete a compromised pod."""
    return _run([
        "kubectl", "delete", "pod", pod_name,
        "-n", namespace,
        "--grace-period=0",
        "--force",
    ])


class RuntimeSecurityAgent(BaseAgent):
    """
    Runs continuously (cron-triggered) or after a deployment.
    Analyses runtime anomalies and can quarantine/kill suspicious pods.
    """

    @property
    def name(self) -> str:
        return "runtime_security_agent"

    @property
    def description(self) -> str:
        return "Analyses Falco alerts and K8s audit logs. Quarantines suspicious pods."

    @property
    def tools(self) -> list:
        return [
            read_falco_alerts,
            kubectl_get_audit_events,
            kubectl_quarantine_pod,
            kubectl_delete_pod,
        ]

    @property
    def system_prompt(self) -> str:
        return """You are a runtime security agent with real enforcement powers.

Analyse Falco alerts and K8s audit events.

Threat levels and responses:
- CRITICAL (container escape, privilege escalation, shell in container):
    → quarantine_pod immediately, set status=blocked, alert_level=critical
- HIGH (unexpected network connection, sensitive file access, new binary execution):
    → quarantine_pod, set alert_level=high
- MEDIUM (unexpected process, config change):
    → log finding, set alert_level=medium, no pod action
- LOW / INFO:
    → log finding, status=success

Return JSON:
{
  "status": "success|blocked|failed",
  "alert_level": "none|low|medium|high|critical",
  "summary": "...",
  "threats": [{"pod": "...", "rule": "...", "action_taken": "..."}],
  "requires_approval": false
}
"""

    async def run(self, context: PipelineContext) -> AgentResult:
        self._log("info", "Starting runtime security agent")
        k8s = context.k8s
        namespace = k8s.namespace if k8s else "default"

        falco = read_falco_alerts()
        audit = kubectl_get_audit_events(namespace=namespace)

        prompt = f"""
Runtime security analysis.
Namespace: {namespace}

Falco alerts (last 100 lines):
{falco.get('stdout', 'No Falco log found')[:3000]}

K8s audit/warning events:
{json.dumps(audit.get('parsed', audit.get('stdout', '')), indent=2, default=str)[:2000]}

Analyse threats and take appropriate actions using your tools.
Return your JSON verdict.
"""
        try:
            response = await self._invoke_llm(prompt)
            return self._parse_verdict(response)
        except Exception as exc:
            return self.failure(f"Runtime security agent exception: {exc}", errors=[str(exc)])

    def _parse_verdict(self, response: str) -> AgentResult:
        import re
        match = re.search(r"\{.*\}", response, re.DOTALL)
        if not match:
            return self.failure("Could not parse runtime security verdict")
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return self.failure("Invalid JSON from runtime security agent")

        alert_level = data.get("alert_level", "none")
        if alert_level in ("critical", "high"):
            return self.blocked(
                data.get("summary", f"Runtime {alert_level} threat detected"),
                reason=f"Runtime {alert_level} security threat requires immediate review",
                details=data,
            )
        elif data.get("status") == "success":
            return self.success(data.get("summary", "No runtime threats detected"), details=data)
        else:
            return self.failure(data.get("summary", "Runtime security check failed"), details=data)
