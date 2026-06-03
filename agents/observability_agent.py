"""
Observability Agent — post-deploy health monitoring.
Watches pods, events, and resource usage. Triggers auto-rollback if degraded.
"""
from __future__ import annotations

import json

from core.base_agent import AgentResult, BaseAgent
from core.pipeline_context import PipelineContext
from tools.registry import (
    kubectl_get_events,
    kubectl_get_pods,
    kubectl_get_resource_usage,
    kubectl_rollback,
)


class ObservabilityAgent(BaseAgent):

    def __init__(self, watch_minutes: int = 5):
        super().__init__()
        self.watch_minutes = watch_minutes

    @property
    def name(self) -> str:
        return "observability_agent"

    @property
    def description(self) -> str:
        return "Monitors post-deploy pod health, events, and resource usage."

    @property
    def tools(self) -> list:
        return [
            kubectl_get_pods,
            kubectl_get_events,
            kubectl_get_resource_usage,
            kubectl_rollback,
        ]

    @property
    def system_prompt(self) -> str:
        return """You are an observability agent monitoring a Kubernetes deployment.

Analyse pod status, events, and resource usage.

Health criteria:
- All pods: Running or Completed (no CrashLoopBackOff, OOMKilled, Error)
- No Warning events in the last 10 minutes related to the deployment
- Resource usage within expected range (no OOM pressure)
- At least 1 pod ready

If unhealthy:
- Identify the root cause from events and pod logs
- Recommend rollback (set "recommend_rollback": true)

Return JSON:
{
  "status": "healthy|degraded|unknown",
  "summary": "...",
  "pod_states": {"running": N, "pending": N, "crashloop": N, "error": N},
  "warning_events": ["..."],
  "recommend_rollback": false,
  "rollback_reason": "..."
}
"""

    async def run(self, context: PipelineContext) -> AgentResult:
        self._log("info", "Starting observability agent")
        k8s = context.k8s
        if not k8s:
            return self.success("No K8s context — skipping observability")

        app_label = f"app={context.docker.image_name}" if context.docker else ""

        pods = kubectl_get_pods(namespace=k8s.namespace, label_selector=app_label)
        events = kubectl_get_events(namespace=k8s.namespace)
        usage = kubectl_get_resource_usage(namespace=k8s.namespace)

        prompt = f"""
Post-deploy observability check.
Namespace: {k8s.namespace}
App label: {app_label}

Pod status:
{json.dumps(pods.get('parsed', pods.get('stdout', '')), indent=2, default=str)[:3000]}

Warning events:
{events.get('stdout', '')[:2000]}

Resource usage:
{usage.get('stdout', '')[:1000]}

Analyse health and return your JSON verdict.
"""
        try:
            response = await self._invoke_llm(prompt)
            return self._parse_health(response, k8s)
        except Exception as exc:
            return self.failure(f"Observability agent exception: {exc}", errors=[str(exc)])

    def _parse_health(self, response: str, k8s) -> AgentResult:
        import re
        match = re.search(r"\{.*\}", response, re.DOTALL)
        if not match:
            return self.failure("Could not parse observability result")
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return self.failure("Invalid JSON from observability agent")

        if data.get("recommend_rollback"):
            # Execute rollback
            if k8s:
                kubectl_rollback(deployment=k8s.argocd_app_name or "app", namespace=k8s.namespace)
            return self.failure(
                f"Auto-rollback triggered: {data.get('rollback_reason', 'degraded health')}",
                details=data,
            )
        elif data.get("status") == "healthy":
            return self.success(data.get("summary", "All pods healthy"), details=data)
        else:
            return self.failure(
                data.get("summary", "Deployment degraded"),
                details=data,
                errors=data.get("warning_events", []),
            )
