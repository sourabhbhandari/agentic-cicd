"""
Main entrypoint for the Agentic CI/CD system.

Modes:
  python main.py pipeline  -- run a pipeline directly (CLI)
  python main.py server    -- start webhook HTTP server (GitHub webhooks)
  python main.py sync      -- run the GitOps sync agent once (cron)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from core.orchestrator import PipelineOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")

# ── Config (from env) ────────────────────────────────────────────────────────
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
ARGOCD_SERVER = os.getenv("ARGOCD_SERVER", "localhost:8080")
DEFAULT_NAMESPACE = os.getenv("K8S_NAMESPACE", "default")
DEFAULT_REGISTRY = os.getenv("DOCKER_REGISTRY", "docker.io")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"


# ── Webhook server ───────────────────────────────────────────────────────────

class GitHubWebhookHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/webhook":
            self._respond(404, "Not found")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        if GITHUB_WEBHOOK_SECRET:
            sig = self.headers.get("X-Hub-Signature-256", "")
            expected = "sha256=" + hmac.new(
                GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(sig, expected):
                self._respond(401, "Unauthorized")
                return

        event = self.headers.get("X-GitHub-Event", "")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, "Bad JSON")
            return

        self._respond(202, "Accepted")

        # Dispatch in background
        asyncio.get_event_loop().create_task(
            _dispatch_webhook(event, payload)
        )

    def _respond(self, code: int, msg: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(msg.encode())

    def log_message(self, format, *args):
        logger.info(f"[webhook] {format % args}")


async def _dispatch_webhook(event: str, payload: dict) -> None:
    """Route GitHub webhook events to the appropriate pipeline trigger."""
    orchestrator = PipelineOrchestrator(dry_run=DRY_RUN)

    if event == "push":
        ref = payload.get("ref", "")
        branch = ref.replace("refs/heads/", "")
        sha = payload.get("after", "")
        repo = payload.get("repository", {})
        repo_url = repo.get("clone_url", "")
        repo_name = repo.get("full_name", "")
        image_name = f"{DEFAULT_REGISTRY}/{repo_name.replace('/', '-')}"

        logger.info(f"Push event: {repo_name} {branch} {sha[:8]}")
        await orchestrator.run_pipeline(
            repo_url=repo_url,
            branch=branch,
            commit_sha=sha,
            image_name=image_name,
            image_tag=sha[:8],
            argocd_app=repo.get("name", "app"),
            namespace=DEFAULT_NAMESPACE,
            triggered_by="push",
        )

    elif event == "pull_request":
        action = payload.get("action", "")
        if action not in ("opened", "synchronize"):
            return
        pr = payload.get("pull_request", {})
        repo = payload.get("repository", {})
        logger.info(f"PR event: {repo.get('full_name')} #{pr.get('number')}")
        await orchestrator.run_pipeline(
            repo_url=repo.get("clone_url", ""),
            branch=pr.get("head", {}).get("ref", ""),
            commit_sha=pr.get("head", {}).get("sha", ""),
            image_name=f"{DEFAULT_REGISTRY}/{repo.get('name', 'app')}",
            image_tag=f"pr-{pr.get('number')}",
            argocd_app=repo.get("name", "app"),
            namespace=DEFAULT_NAMESPACE,
            triggered_by="pr",
            pr_number=pr.get("number"),
        )
    else:
        logger.debug(f"Ignoring event: {event}")


# ── CLI pipeline run ─────────────────────────────────────────────────────────

async def run_pipeline_cli() -> None:
    orchestrator = PipelineOrchestrator(dry_run=DRY_RUN)

    # Override: pass these as CLI args or env vars for your actual repo
    await orchestrator.run_pipeline(
        repo_url=os.getenv("REPO_URL", "https://github.com/your-org/your-app"),
        branch=os.getenv("BRANCH", "main"),
        commit_sha=os.getenv("COMMIT_SHA", "abc123"),
        image_name=os.getenv("IMAGE_NAME", "myapp"),
        image_tag=os.getenv("IMAGE_TAG", "latest"),
        argocd_app=os.getenv("ARGOCD_APP", "myapp"),
        namespace=DEFAULT_NAMESPACE,
        triggered_by="manual",
    )


async def run_sync_cli() -> None:
    orchestrator = PipelineOrchestrator(dry_run=DRY_RUN)
    await orchestrator.run_sync_check(
        argocd_server=ARGOCD_SERVER,
        namespace=DEFAULT_NAMESPACE,
    )


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "pipeline"

    if mode == "server":
        port = int(os.getenv("WEBHOOK_PORT", "8000"))
        logger.info(f"Starting webhook server on :{port}")
        server = HTTPServer(("0.0.0.0", port), GitHubWebhookHandler)
        asyncio.get_event_loop().run_until_complete(
            asyncio.get_event_loop().run_in_executor(None, server.serve_forever)
        )

    elif mode == "sync":
        asyncio.run(run_sync_cli())

    elif mode == "pipeline":
        asyncio.run(run_pipeline_cli())

    else:
        print(f"Unknown mode: {mode}. Use: pipeline | server | sync")
        sys.exit(1)


if __name__ == "__main__":
    main()
