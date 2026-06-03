"""
Deploy Agent — drives deployments via ArgoCD with automated health checks
and rollback on failure.
"""
from __future__ import annotations

import json
import time

from core.base_agent import AgentResult, BaseAgent
from core.pipeline_context import PipelineContext
from tools.registry import (
    argocd_get_app_status,
    argocd_rollback_app,
    argocd_sync_app,
    kubectl_get_events,
    kubectl_rollout_status,
)


class DeployAgent(BaseAgent):

    def __init__(self, auto_rollback: bool = True):
        super().__init__(approval_required=True)  # always requires approval for prod
        self.auto_rollback = auto_rollback

    @property
    def name(self) -> str:
        return "deploy_agent"

    @property
    def description(self) -> str:
        return "Deploys to Kubernetes via ArgoCD, monitors health, auto-rolls back on failure."

    @property
    def tools(self) -> list:
        return [
            argocd_sync_app,
            argocd_get_app_status,
            argocd_rollback_app,
            kubectl_rollout_status,
            kubectl_get_events,
        ]

    @property
    def system_prompt(self) -> str:
        return """You are a Kubernetes deployment agent.
You control deployments exclusively through ArgoCD (GitOps).

Deployment protocol:
1. Check app health before starting (argocd_get_app_status).
2. Trigger sync (argocd_sync_app).
3. Wait for rollout (kubectl_rollout_status).
4. Check app health again after sync.
5. If health = Healthy AND sync = Synced → SUCCESS.
6. If health = Degraded or pods crash-looping → trigger rollback, report FAILED.
7. Fetch K8s events to include in failure report.

Never bypass ArgoCD. Never use kubectl apply directly for deployments.

Return JSON:
{
  "status": "success|failed",
  "summary": "...",
  "health_before": "...",
  "health_after": "...",
  "sync_status": "...",
  "rollback_triggered": true|false,
  "events": [...]
}
"""

    async def run(self, context: PipelineContext) -> AgentResult:
        self._log("info", "Starting deploy agent")
        k8s = context.k8s

        if not k8s or not k8s.argocd_app_name:
            return self.failure("No ArgoCD app name configured in K8s context")

        prompt = f"""
Deployment task:
- ArgoCD app: {k8s.argocd_app_name}
- ArgoCD server: {k8s.argocd_server}
- Namespace: {k8s.namespace}
- Image being deployed: {context.docker.full_image if context.docker else 'unknown'}
- Commit SHA: {context.git.commit_sha if context.git else 'unknown'}

Execute the deployment protocol. Use the available tools in sequence.
Auto-rollback if deployment fails: {self.auto_rollback}
"""
        try:
            response = await self._invoke_llm(prompt)
            return self._parse_result(response)
        except Exception as exc:
            return self.failure(f"Deploy agent exception: {exc}", errors=[str(exc)])

    def _parse_result(self, response: str) -> AgentResult:
        import re
        match = re.search(r"\{.*\}", response, re.DOTALL)
        if not match:
            return self.failure("Could not parse deploy result")
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return self.failure("Invalid JSON from deploy agent")

        if data.get("status") == "success":
            return self.success(
                data.get("summary", "Deployment successful"),
                details=data,
            )
        else:
            return self.failure(
                data.get("summary", "Deployment failed"),
                errors=data.get("events", []),
                details=data,
            )
