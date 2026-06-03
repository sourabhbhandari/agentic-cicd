"""
PipelineContext — the single shared state object that flows through every agent.
Agents read from it and write their results back into it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core.base_agent import AgentResult


@dataclass
class GitContext:
    repo_url: str
    branch: str
    commit_sha: str
    pr_number: int | None = None
    author: str = ""
    message: str = ""


@dataclass
class DockerContext:
    image_name: str
    image_tag: str
    registry: str = "docker.io"
    dockerfile_path: str = "Dockerfile"

    @property
    def full_image(self) -> str:
        return f"{self.registry}/{self.image_name}:{self.image_tag}"


@dataclass
class K8sContext:
    namespace: str = "default"
    cluster: str = "docker-desktop"
    manifest_dir: str = "k8s"
    argocd_app_name: str = ""
    argocd_server: str = "localhost:8080"


@dataclass
class PipelineContext:
    # Identity
    run_id: str
    triggered_by: str                   # "push" | "pr" | "cron" | "manual"
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Sub-contexts
    git: GitContext | None = None
    docker: DockerContext | None = None
    k8s: K8sContext | None = None

    # Results written by each agent
    results: dict[str, AgentResult] = field(default_factory=dict)

    # Shared scratchpad — agents may write findings here
    artifacts: dict[str, Any] = field(default_factory=dict)

    # Human-in-the-loop
    approved: bool = False
    approver: str = ""
    approval_notes: str = ""

    # Audit
    audit_log: list[dict] = field(default_factory=list)

    def record(self, result: AgentResult) -> None:
        self.results[result.agent_name] = result
        self.audit_log.append({
            "ts": datetime.utcnow().isoformat(),
            "agent": result.agent_name,
            "status": result.status.value,
            "summary": result.summary,
        })

    def has_blocker(self) -> bool:
        return any(r.is_blocking() for r in self.results.values())

    def pending_approvals(self) -> list[AgentResult]:
        from core.base_agent import AgentStatus
        return [r for r in self.results.values() if r.status == AgentStatus.BLOCKED]

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "triggered_by": self.triggered_by,
            "started_at": self.started_at,
            "git": vars(self.git) if self.git else None,
            "docker": vars(self.docker) if self.docker else None,
            "k8s": vars(self.k8s) if self.k8s else None,
            "results": {k: v.to_dict() for k, v in self.results.items()},
            "approved": self.approved,
            "audit_log": self.audit_log,
        }
