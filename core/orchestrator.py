"""
Orchestrator Agent — the brain of the pipeline.
Uses Google ADK multi-agent to coordinate all specialist agents.
Decides which agents to run, in what order, and handles HITL approval gates.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Callable

from core.base_agent import AgentStatus
from core.pipeline_context import PipelineContext, GitContext, DockerContext, K8sContext
from agents.ci_agent import CIAgent
from agents.security_agent import SecurityAgent
from agents.validation_agent import ValidationAgent
from agents.deploy_agent import DeployAgent
from agents.observability_agent import ObservabilityAgent
from agents.runtime_security_agent import RuntimeSecurityAgent
from agents.gitops_sync_agent import GitOpsSyncAgent

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """
    Coordinates the full CI/CD pipeline.

    Pipeline stages (sequential, short-circuits on blocker):
        1. CI          — build, test
        2. Security    — CVE, SAST, secrets, IaC
        3. Validation  — K8s manifest checks
        4. [HITL gate] — human approval if any agent blocked
        5. Deploy      — ArgoCD sync
        6. Observability — post-deploy health
        7. Runtime security — live threat watch

    GitOps sync agent runs independently (cron).

    Add custom agents via register_agent().
    """

    def __init__(
        self,
        approval_handler: Callable[[PipelineContext], bool] | None = None,
        dry_run: bool = False,
    ):
        # default approval: auto-approve if dry_run, else block
        self._approval_handler = approval_handler or self._default_approval
        self.dry_run = dry_run

        # Core pipeline agents (ordered)
        self._pipeline_agents = [
            CIAgent(),
            SecurityAgent(block_on_critical=not dry_run),
            ValidationAgent(),
        ]
        self._post_approval_agents = [
            DeployAgent(auto_rollback=not dry_run),
            ObservabilityAgent(watch_minutes=5),
            RuntimeSecurityAgent(),
        ]

        # Extra agents registered at runtime
        self._custom_agents: list = []

        # Independent agents (cron / event-driven)
        self._sync_agent = GitOpsSyncAgent(auto_sync=not dry_run)

    # ── public API ───────────────────────────────────────────────────────────

    def register_agent(self, agent, stage: str = "post_approval") -> None:
        """
        Register a custom agent.
        stage: "pre_approval" | "post_approval" | "independent"
        """
        if stage == "pre_approval":
            self._pipeline_agents.append(agent)
        elif stage == "post_approval":
            self._post_approval_agents.append(agent)
        else:
            self._custom_agents.append(agent)
        logger.info(f"Registered custom agent: {agent.name} at stage={stage}")

    async def run_pipeline(
        self,
        repo_url: str,
        branch: str,
        commit_sha: str,
        image_name: str,
        image_tag: str,
        argocd_app: str,
        namespace: str = "default",
        triggered_by: str = "push",
        pr_number: int | None = None,
    ) -> PipelineContext:
        """Execute the full CI/CD pipeline for a given commit."""

        run_id = str(uuid.uuid4())[:8]
        logger.info(f"=== Pipeline run {run_id} started ===")
        logger.info(f"  Repo: {repo_url}  Branch: {branch}  SHA: {commit_sha[:8]}")

        context = PipelineContext(
            run_id=run_id,
            triggered_by=triggered_by,
            git=GitContext(
                repo_url=repo_url,
                branch=branch,
                commit_sha=commit_sha,
                pr_number=pr_number,
            ),
            docker=DockerContext(
                image_name=image_name,
                image_tag=image_tag,
            ),
            k8s=K8sContext(
                namespace=namespace,
                argocd_app_name=argocd_app,
                manifest_dir="k8s",
            ),
        )

        # Stage 1: pre-approval agents
        logger.info("--- Stage 1: Pre-approval agents ---")
        await self._run_stage(self._pipeline_agents, context)

        if context.has_blocker():
            self._print_blockers(context)
            approved = self._approval_handler(context)
            if not approved:
                logger.warning("Pipeline blocked — approval denied or timed out")
                self._print_summary(context)
                return context
            context.approved = True
            context.approver = "auto" if self.dry_run else "human"
            logger.info("Pipeline approved — continuing to deployment")

        # Stage 2: post-approval agents
        logger.info("--- Stage 2: Post-approval agents ---")
        await self._run_stage(self._post_approval_agents, context)

        # Stage 3: any registered custom post-approval agents
        if self._custom_agents:
            logger.info("--- Stage 3: Custom agents ---")
            await self._run_stage(self._custom_agents, context)

        self._print_summary(context)
        return context

    async def run_sync_check(self, argocd_server: str, namespace: str = "default") -> None:
        """Run the GitOps sync agent independently (cron job)."""
        context = PipelineContext(
            run_id=f"sync-{uuid.uuid4()!s:.8}",
            triggered_by="cron",
            k8s=K8sContext(namespace=namespace, argocd_server=argocd_server),
        )
        result = await self._sync_agent.run(context)
        context.record(result)
        logger.info(f"[GitOps sync] {result.status.value}: {result.summary}")

    # ── internals ────────────────────────────────────────────────────────────

    async def _run_stage(self, agents: list, context: PipelineContext) -> None:
        for agent in agents:
            if context.has_blocker() and not context.approved:
                logger.info(f"Skipping {agent.name} — pipeline blocked")
                continue
            logger.info(f"Running agent: {agent.name}")
            try:
                result = await agent.run(context)
            except Exception as exc:
                from core.base_agent import AgentResult
                result = AgentResult(
                    agent_name=agent.name,
                    status=AgentStatus.FAILED,
                    summary=f"Unhandled exception: {exc}",
                    errors=[str(exc)],
                )
                logger.exception(f"Agent {agent.name} crashed")
            context.record(result)
            self._log_result(result)

    @staticmethod
    def _default_approval(context: PipelineContext) -> bool:
        """
        CLI fallback approval handler.
        In production replace this with Slack/PagerDuty/web hook.
        """
        print("\n" + "="*60)
        print("⚠  HUMAN APPROVAL REQUIRED")
        print("="*60)
        for r in context.pending_approvals():
            print(f"\nAgent: {r.agent_name}")
            print(f"Reason: {r.approval_reason}")
            if r.details.get("top_issues"):
                print("Top issues:")
                for issue in r.details["top_issues"][:5]:
                    print(f"  • {issue}")
        print()
        answer = input("Approve deployment? [y/N]: ").strip().lower()
        return answer == "y"

    @staticmethod
    def _log_result(result) -> None:
        icon = {"success": "✓", "failed": "✗", "blocked": "⚠", "skipped": "–"}.get(
            result.status.value, "?"
        )
        logger.info(f"  {icon} {result.agent_name}: {result.summary}")

    @staticmethod
    def _print_blockers(context: PipelineContext) -> None:
        logger.warning("Pipeline has blockers:")
        for r in context.pending_approvals():
            logger.warning(f"  • {r.agent_name}: {r.approval_reason}")

    @staticmethod
    def _print_summary(context: PipelineContext) -> None:
        print("\n" + "="*60)
        print(f"Pipeline run {context.run_id} — SUMMARY")
        print("="*60)
        for name, result in context.results.items():
            icon = {"success": "✓", "failed": "✗", "blocked": "⚠", "skipped": "–"}.get(
                result.status.value, "?"
            )
            print(f"  {icon}  {name:<30} {result.summary}")
        overall = "PASSED" if not context.has_blocker() else "FAILED/BLOCKED"
        print(f"\nOverall: {overall}")
        print("="*60 + "\n")
