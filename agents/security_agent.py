"""
Security Agent — DevSecOps scanning layer.
Runs: Trivy (CVE), Semgrep (SAST), Gitleaks (secrets), Checkov (IaC).
Uses Claude to synthesise findings and decide severity.
"""
from __future__ import annotations

import json

from core.base_agent import AgentResult, AgentStatus, BaseAgent
from core.pipeline_context import PipelineContext
from tools.registry import (
    checkov_scan_k8s,
    gitleaks_scan,
    semgrep_scan,
    trivy_scan_filesystem,
    trivy_scan_image,
)


BLOCK_ON_CRITICAL = True   # set False to warn-only in dev


class SecurityAgent(BaseAgent):

    def __init__(self, block_on_critical: bool = BLOCK_ON_CRITICAL):
        super().__init__(approval_required=block_on_critical)
        self.block_on_critical = block_on_critical

    @property
    def name(self) -> str:
        return "security_agent"

    @property
    def description(self) -> str:
        return "Runs CVE, SAST, secret, and IaC security scans. Blocks on critical findings."

    @property
    def tools(self) -> list:
        return [
            trivy_scan_image,
            trivy_scan_filesystem,
            semgrep_scan,
            gitleaks_scan,
            checkov_scan_k8s,
        ]

    @property
    def system_prompt(self) -> str:
        return """You are a DevSecOps security agent.
You receive raw scan outputs from Trivy, Semgrep, Gitleaks, and Checkov.
Your job: analyse findings, calculate risk, and decide whether to block the pipeline.

Decision rules:
- CRITICAL CVE with a fix available → BLOCK (status: blocked, requires_approval: true)
- HIGH CVE no fix available → WARN (status: success with warning)
- Secrets found → BLOCK immediately
- SAST HIGH severity → BLOCK
- SAST MEDIUM → WARN
- IaC CRITICAL misconfig → BLOCK
- Zero findings → status: success

Output a JSON object:
{
  "status": "success|blocked|failed",
  "summary": "one-line summary",
  "requires_approval": true|false,
  "approval_reason": "...",
  "findings": {
    "cve_critical": <count>,
    "cve_high": <count>,
    "secrets": <count>,
    "sast_high": <count>,
    "iac_critical": <count>
  },
  "top_issues": ["<issue1>", "<issue2>", ...]
}
"""

    async def run(self, context: PipelineContext) -> AgentResult:
        self._log("info", "Starting security scans")

        scan_results: dict = {}

        # -- Trivy image scan --
        if context.docker:
            self._log("info", f"Trivy image scan: {context.docker.full_image}")
            scan_results["trivy_image"] = trivy_scan_image(
                image=context.docker.full_image, severity="HIGH,CRITICAL"
            )

        # -- Trivy filesystem scan --
        repo_path = context.artifacts.get("repo_path", "/tmp/repo")
        self._log("info", f"Trivy FS scan: {repo_path}")
        scan_results["trivy_fs"] = trivy_scan_filesystem(path=repo_path)

        # -- Semgrep SAST --
        self._log("info", "Semgrep SAST scan")
        scan_results["semgrep"] = semgrep_scan(path=repo_path)

        # -- Gitleaks secrets --
        self._log("info", "Gitleaks secrets scan")
        scan_results["gitleaks"] = gitleaks_scan(repo_path=repo_path)

        # -- Checkov K8s IaC --
        if context.k8s:
            manifest_dir = f"{repo_path}/{context.k8s.manifest_dir}"
            self._log("info", f"Checkov IaC scan: {manifest_dir}")
            scan_results["checkov"] = checkov_scan_k8s(manifest_dir=manifest_dir)

        # -- Ask Claude to synthesise --
        prompt = f"""
Security scan results for {context.docker.full_image if context.docker else 'repo'}:

{json.dumps(scan_results, indent=2, default=str)[:8000]}

Analyse all findings. Apply decision rules. Return your JSON verdict.
"""
        try:
            response = await self._invoke_llm(prompt)
            return self._parse_verdict(response, scan_results)
        except Exception as exc:
            return self.failure(f"Security agent exception: {exc}", errors=[str(exc)])

    def _parse_verdict(self, response: str, scan_results: dict) -> AgentResult:
        import re
        match = re.search(r"\{.*\}", response, re.DOTALL)
        if not match:
            return self.failure("Could not parse security verdict", errors=[response[:500]])
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return self.failure("Invalid JSON from security agent", errors=[response[:500]])

        status = data.get("status", "failed")
        summary = data.get("summary", "Security scan complete")
        findings = data.get("findings", {})
        top_issues = data.get("top_issues", [])

        if status == "blocked":
            return self.blocked(
                summary,
                reason=data.get("approval_reason", "Critical security findings require human review"),
                details={"findings": findings, "top_issues": top_issues, "raw_scans": {
                    k: v.get("parsed", v.get("stdout", ""))[:500] for k, v in scan_results.items()
                }},
            )
        elif status == "success":
            return self.success(summary, details={"findings": findings, "top_issues": top_issues})
        else:
            return self.failure(summary, details={"findings": findings})
