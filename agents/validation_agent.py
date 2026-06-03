"""
Validation Agent — validates Kubernetes manifests and deployment policies
before anything is applied to the cluster.
"""
from __future__ import annotations

import json
import os

from core.base_agent import AgentResult, BaseAgent
from core.pipeline_context import PipelineContext
from tools.registry import (
    argocd_diff_app,
    kubectl_validate_manifest,
)


class ValidationAgent(BaseAgent):

    @property
    def name(self) -> str:
        return "validation_agent"

    @property
    def description(self) -> str:
        return "Validates K8s manifests, checks resource limits, and verifies ArgoCD app diff."

    @property
    def tools(self) -> list:
        return [kubectl_validate_manifest, argocd_diff_app]

    @property
    def system_prompt(self) -> str:
        return """You are a Kubernetes validation agent.

Validate the provided manifests against these rules:
1. Every Deployment must have resource requests and limits defined.
2. No container should run as root (securityContext.runAsNonRoot: true).
3. Image tags must not be 'latest'.
4. LivenessProbe and ReadinessProbe must be defined.
5. Namespace must be explicitly set (not 'default' in production).
6. ArgoCD diff must show expected changes only (no surprise deletions).

Output JSON:
{
  "status": "success|failed",
  "summary": "...",
  "violations": [
    {"rule": "...", "resource": "...", "severity": "critical|warning"}
  ],
  "manifest_count": <n>,
  "argocd_diff_summary": "..."
}
Block on any critical violation.
"""

    async def run(self, context: PipelineContext) -> AgentResult:
        self._log("info", "Starting validation agent")
        repo_path = context.artifacts.get("repo_path", "/tmp/repo")
        k8s = context.k8s

        if not k8s:
            return self.success("No K8s context — skipping validation")

        manifest_dir = os.path.join(repo_path, k8s.manifest_dir)

        # Collect manifest files
        manifests = []
        if os.path.isdir(manifest_dir):
            for fname in os.listdir(manifest_dir):
                if fname.endswith((".yaml", ".yml")):
                    manifests.append(os.path.join(manifest_dir, fname))

        # Validate each manifest
        validation_results = {}
        for mf in manifests:
            validation_results[os.path.basename(mf)] = kubectl_validate_manifest(
                manifest_path=mf
            )

        # Get ArgoCD diff if app exists
        argocd_diff = {}
        if k8s.argocd_app_name:
            argocd_diff = argocd_diff_app(
                app_name=k8s.argocd_app_name, server=k8s.argocd_server
            )

        # Read manifest contents for Claude review
        manifest_contents = {}
        for mf in manifests[:10]:  # cap at 10 to stay within token budget
            try:
                with open(mf) as f:
                    manifest_contents[os.path.basename(mf)] = f.read()[:3000]
            except OSError:
                pass

        prompt = f"""
Kubernetes validation task.

Manifests found ({len(manifests)} files): {[os.path.basename(m) for m in manifests]}

Manifest contents:
{json.dumps(manifest_contents, indent=2)[:6000]}

kubectl dry-run results:
{json.dumps(validation_results, indent=2, default=str)[:2000]}

ArgoCD diff:
{json.dumps(argocd_diff, indent=2, default=str)[:2000]}

Apply all validation rules. Return your JSON verdict.
"""
        try:
            response = await self._invoke_llm(prompt)
            return self._parse_verdict(response, len(manifests))
        except Exception as exc:
            return self.failure(f"Validation agent exception: {exc}", errors=[str(exc)])

    def _parse_verdict(self, response: str, manifest_count: int) -> AgentResult:
        import re
        match = re.search(r"\{.*\}", response, re.DOTALL)
        if not match:
            return self.failure("Could not parse validation verdict")
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return self.failure("Invalid JSON from validation agent")

        violations = data.get("violations", [])
        critical = [v for v in violations if v.get("severity") == "critical"]

        if data.get("status") == "success" and not critical:
            return self.success(data.get("summary", f"All {manifest_count} manifests valid"), details=data)
        elif critical:
            return self.failure(
                data.get("summary", f"{len(critical)} critical violations found"),
                errors=[f"{v['rule']} in {v['resource']}" for v in critical],
                details=data,
            )
        else:
            return self.success(
                data.get("summary", "Validation passed with warnings"),
                details=data,
            )
