"""
CI Agent — responsible for build, test, and lint.
Uses Docker to build the image and run tests in isolation.
"""
from __future__ import annotations

from core.base_agent import AgentResult, AgentStatus, BaseAgent
from core.pipeline_context import PipelineContext
from tools.registry import (
    docker_build,
    docker_push,
    docker_run_tests,
    github_set_commit_status,
)


class CIAgent(BaseAgent):

    @property
    def name(self) -> str:
        return "ci_agent"

    @property
    def description(self) -> str:
        return "Builds Docker images, runs tests, and reports results to GitHub."

    @property
    def tools(self) -> list:
        return [docker_build, docker_push, docker_run_tests, github_set_commit_status]

    @property
    def system_prompt(self) -> str:
        return """You are a CI agent in an automated DevSecOps pipeline.
Your job: build a Docker image, run the test suite inside it, and report pass/fail.

Rules:
- Always run tests before pushing the image.
- If tests fail, report FAILED and include the test output in errors.
- If build fails, report FAILED immediately — don't attempt tests.
- Summarise test results concisely: X passed, Y failed, Z errors.
- Never push an image that failed tests.
- Return a JSON object with keys: status, summary, test_output, image_built, image_pushed.
"""

    async def run(self, context: PipelineContext) -> AgentResult:
        self._log("info", "Starting CI agent")
        dc = context.docker
        gc = context.git

        if not dc or not gc:
            return self.failure("Missing docker or git context")

        prompt = f"""
Pipeline context:
- Repo: {gc.repo_url}  Branch: {gc.branch}  SHA: {gc.commit_sha}
- Image: {dc.full_image}  Dockerfile: {dc.dockerfile_path}

Steps:
1. Build Docker image {dc.full_image} from {dc.dockerfile_path}
2. Run 'pytest --tb=short -q' inside the image
3. If tests pass, push the image
4. Report result as JSON

Execute now.
"""
        try:
            response = await self._invoke_llm(prompt)
            return self._parse_llm_result(response, context)
        except Exception as exc:
            return self.failure(f"CI agent exception: {exc}", errors=[str(exc)])

    def _parse_llm_result(self, response: str, context: PipelineContext) -> AgentResult:
        import json, re
        match = re.search(r"\{.*\}", response, re.DOTALL)
        if not match:
            return self.failure("Could not parse CI agent response", errors=[response[:500]])
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return self.failure("Invalid JSON from CI agent", errors=[response[:500]])

        status_str = data.get("status", "failed")
        if status_str == "success":
            return self.success(
                data.get("summary", "Build and tests passed"),
                details=data,
                artifacts=[context.docker.full_image] if context.docker else [],
            )
        else:
            return self.failure(
                data.get("summary", "Build or tests failed"),
                errors=data.get("errors", [data.get("test_output", "")[:2000]]),
                details=data,
            )
