"""
GitOps Sync Agent — continuously monitors ArgoCD for drift and re-syncs.
Can be scheduled via cron or triggered by ArgoCD webhook events.
"""
from __future__ import annotations

import json

from core.base_agent import AgentResult, BaseAgent
from core.pipeline_context import PipelineContext
from tools.registry import (
    argocd_diff_app,
    argocd_get_app_status,
    argocd_list_apps,
    argocd_sync_app,
)


class GitOpsSyncAgent(BaseAgent):

    def __init__(self, auto_sync: bool = True, alert_on_drift: bool = True):
        super().__init__()
        self.auto_sync = auto_sync
        self.alert_on_drift = alert_on_drift

    @property
    def name(self) -> str:
        return "gitops_sync_agent"

    @property
    def description(self) -> str:
        return "Detects ArgoCD drift and auto-resyncs out-of-sync applications."

    @property
    def tools(self) -> list:
        return [argocd_list_apps, argocd_get_app_status, argocd_diff_app, argocd_sync_app]

    @property
    def system_prompt(self) -> str:
        return """You are a GitOps sync agent monitoring ArgoCD.

Your responsibilities:
1. List all ArgoCD applications.
2. Check each app's sync status (Synced/OutOfSync) and health (Healthy/Degraded/Progressing).
3. For OutOfSync apps: get the diff, evaluate if it's expected or drift.
4. If auto_sync enabled and drift detected: trigger sync.
5. Report any apps that are Degraded and cannot be auto-healed.

Drift is: live state differs from git desired state without a recent deployment.
Expected divergence: a deployment is in progress (Progressing health).

Return JSON:
{
  "status": "success|failed",
  "summary": "...",
  "apps_total": N,
  "apps_synced": N,
  "apps_drifted": N,
  "apps_degraded": N,
  "drift_details": [{"app": "...", "diff_summary": "...", "action": "synced|alert|skip"}],
  "syncs_triggered": N
}
"""

    async def run(self, context: PipelineContext) -> AgentResult:
        self._log("info", "Starting GitOps sync agent")
        k8s = context.k8s
        server = k8s.argocd_server if k8s else "localhost:8080"

        apps = argocd_list_apps(server=server)

        prompt = f"""
GitOps sync check.
ArgoCD server: {server}
Auto-sync enabled: {self.auto_sync}

All apps:
{json.dumps(apps.get('parsed', apps.get('stdout', 'error listing apps')), indent=2, default=str)[:5000]}

Check each app. For OutOfSync apps, get their diff and decide action.
Return your JSON verdict.
"""
        try:
            response = await self._invoke_llm(prompt)
            return self._parse_result(response)
        except Exception as exc:
            return self.failure(f"GitOps sync agent exception: {exc}", errors=[str(exc)])

    def _parse_result(self, response: str) -> AgentResult:
        import re
        match = re.search(r"\{.*\}", response, re.DOTALL)
        if not match:
            return self.failure("Could not parse sync result")
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return self.failure("Invalid JSON from sync agent")

        degraded = data.get("apps_degraded", 0)
        drifted = data.get("apps_drifted", 0)

        if degraded > 0:
            return self.failure(
                data.get("summary", f"{degraded} apps degraded"),
                details=data,
            )
        elif drifted > 0 and not self.auto_sync:
            return self.blocked(
                data.get("summary", f"{drifted} apps drifted — manual sync required"),
                reason="Drift detected, auto-sync disabled — needs human approval",
                details=data,
            )
        else:
            return self.success(
                data.get("summary", "All apps synced and healthy"),
                details=data,
            )
