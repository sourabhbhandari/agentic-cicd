"""
Example custom agent — shows how to add any specialist capability.

This one does performance regression testing:
- Runs a load test after deployment
- Compares p99 latency against a baseline
- Blocks if regression > 20%

Copy this file, rename the class, implement run(), and register it:

    from agents.custom.performance_agent import PerformanceAgent
    orchestrator.register_agent(PerformanceAgent(), stage="post_approval")
"""
from __future__ import annotations

import json
import subprocess

from core.base_agent import AgentResult, BaseAgent
from core.pipeline_context import PipelineContext
from tools.registry import _run, tool


@tool
def run_k6_load_test(target_url: str, vus: int = 10, duration: str = "30s") -> dict:
    """Run a k6 load test against a URL and return JSON summary."""
    script = f"""
import http from 'k6/http';
import {{ check, sleep }} from 'k6';
export const options = {{ vus: {vus}, duration: '{duration}' }};
export default function () {{
  const res = http.get('{target_url}');
  check(res, {{ 'status is 200': (r) => r.status === 200 }});
  sleep(0.1);
}}
"""
    with open("/tmp/k6-test.js", "w") as f:
        f.write(script)
    return _run(["k6", "run", "--out", "json=/tmp/k6-results.json", "/tmp/k6-test.js"],
                timeout=120)


class PerformanceAgent(BaseAgent):
    """
    Post-deploy performance regression agent.
    Runs k6 load test and compares p99 latency against baseline.
    """

    REGRESSION_THRESHOLD = 0.20   # 20% regression triggers a block

    @property
    def name(self) -> str:
        return "performance_agent"

    @property
    def description(self) -> str:
        return "Runs k6 load test post-deploy and checks for latency regressions."

    @property
    def tools(self) -> list:
        return [run_k6_load_test]

    @property
    def system_prompt(self) -> str:
        return f"""You are a performance regression agent.
You run k6 load tests and compare results against a baseline.
Block if p99 latency increased by more than {self.REGRESSION_THRESHOLD*100:.0f}%.

Return JSON:
{{
  "status": "success|blocked|failed",
  "summary": "...",
  "p99_baseline_ms": <n>,
  "p99_current_ms": <n>,
  "regression_pct": <n>,
  "blocked_reason": "..."
}}
"""

    async def run(self, context: PipelineContext) -> AgentResult:
        self._log("info", "Starting performance agent")
        target = f"http://localhost/api/health"  # adjust per your service

        results = run_k6_load_test(target_url=target, vus=20, duration="30s")

        prompt = f"""
Performance test results:
{results.get('stdout', results.get('stderr', 'no output'))[:3000]}

Baseline p99 from previous run: {context.artifacts.get('perf_baseline_p99', 'unknown')} ms

Analyse results. Return JSON verdict.
"""
        try:
            response = await self._invoke_llm(prompt)
            return self._parse_result(response)
        except Exception as exc:
            return self.failure(f"Performance agent error: {exc}", errors=[str(exc)])

    def _parse_result(self, response: str) -> AgentResult:
        import re
        match = re.search(r"\{.*\}", response, re.DOTALL)
        if not match:
            return self.failure("Could not parse performance result")
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return self.failure("Invalid JSON from performance agent")

        if data.get("status") == "blocked":
            return self.blocked(
                data.get("summary", "Performance regression detected"),
                reason=data.get("blocked_reason", f"p99 regression > {self.REGRESSION_THRESHOLD*100:.0f}%"),
                details=data,
            )
        elif data.get("status") == "success":
            return self.success(data.get("summary", "Performance within threshold"), details=data)
        else:
            return self.failure(data.get("summary", "Performance test failed"), details=data)
