"""
Base agent class — every specialist agent inherits from this.
Provides: ADK integration, Claude LLM wiring, structured logging,
human-in-the-loop approval, and result reporting.
"""
from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService

logger = logging.getLogger(__name__)


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"       # needs human approval
    SKIPPED = "skipped"


@dataclass
class AgentResult:
    agent_name: str
    status: AgentStatus
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    requires_approval: bool = False
    approval_reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "agent": self.agent_name,
            "status": self.status.value,
            "summary": self.summary,
            "details": self.details,
            "artifacts": self.artifacts,
            "errors": self.errors,
            "requires_approval": self.requires_approval,
            "approval_reason": self.approval_reason,
            "timestamp": self.timestamp,
        }

    def is_blocking(self) -> bool:
        return self.status in (AgentStatus.FAILED, AgentStatus.BLOCKED)


class BaseAgent(ABC):
    """
    Abstract base for all CI/CD agents.

    Subclass and implement:
        - name (str property)
        - description (str property)
        - tools (list of @tool functions)
        - system_prompt (str property)
        - run(context) -> AgentResult
    """

    MODEL = "anthropic/claude-sonnet-4-20250514"  # via LiteLLM

    def __init__(self, approval_required: bool = False):
        self.approval_required = approval_required
        self._session_service = InMemorySessionService()
        self._adk_agent: Agent | None = None

    # ── subclass interface ──────────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique agent identifier, e.g. 'security_agent'."""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description shown in orchestrator tool list."""

    @property
    @abstractmethod
    def tools(self) -> list:
        """List of @tool-decorated functions this agent may call."""

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """System prompt injected into every LLM call."""

    @abstractmethod
    async def run(self, context: dict) -> AgentResult:
        """
        Execute the agent's task.
        `context` carries the pipeline run state — see PipelineContext.
        """

    # ── ADK wiring ──────────────────────────────────────────────────────────

    def _build_adk_agent(self) -> Agent:
        if self._adk_agent is None:
            self._adk_agent = Agent(
                name=self.name,
                model=LiteLlm(model=self.MODEL),
                description=self.description,
                instruction=self.system_prompt,
                tools=self.tools,
            )
        return self._adk_agent

    async def _invoke_llm(self, prompt: str, session_id: str | None = None) -> str:
        """Run a single LLM turn through ADK and return the text response."""
        agent = self._build_adk_agent()
        sid = session_id or f"{self.name}-{datetime.utcnow().timestamp()}"
        runner = Runner(
            agent=agent,
            app_name="agentic-cicd",
            session_service=self._session_service,
        )
        from google.adk.sessions import Session
        session = await self._session_service.create_session(
            app_name="agentic-cicd", user_id="pipeline", session_id=sid
        )
        from google.genai import types as genai_types
        content = genai_types.Content(
            role="user",
            parts=[genai_types.Part(text=prompt)],
        )
        response_text = ""
        async for event in runner.run_async(
            user_id="pipeline", session_id=sid, new_message=content
        ):
            if event.is_final_response() and event.content and event.content.parts:
                response_text = "".join(
                    p.text for p in event.content.parts if hasattr(p, "text")
                )
        return response_text

    # ── helpers ─────────────────────────────────────────────────────────────

    def _log(self, level: str, msg: str, **kwargs) -> None:
        extra = {"agent": self.name, **kwargs}
        getattr(logger, level)(f"[{self.name}] {msg}", extra=extra)

    def _make_result(
        self,
        status: AgentStatus,
        summary: str,
        **kwargs,
    ) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            status=status,
            summary=summary,
            **kwargs,
        )

    def success(self, summary: str, **kwargs) -> AgentResult:
        self._log("info", f"SUCCESS — {summary}")
        return self._make_result(AgentStatus.SUCCESS, summary, **kwargs)

    def failure(self, summary: str, errors: list[str] | None = None, **kwargs) -> AgentResult:
        self._log("error", f"FAILED — {summary}")
        return self._make_result(AgentStatus.FAILED, summary, errors=errors or [], **kwargs)

    def blocked(self, summary: str, reason: str, **kwargs) -> AgentResult:
        self._log("warning", f"BLOCKED — {reason}")
        return self._make_result(
            AgentStatus.BLOCKED,
            summary,
            requires_approval=True,
            approval_reason=reason,
            **kwargs,
        )
