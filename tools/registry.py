"""
Shared tool registry.
Every tool is a plain Python function decorated with @tool from google.adk.
Agents import only the tools they need.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any

from google.adk.tools import tool


# ── helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: list[str], cwd: str | None = None, timeout: int = 300) -> dict:
    """Run a subprocess and return {stdout, stderr, returncode}."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timed out", "returncode": -1, "success": False}
    except FileNotFoundError as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "success": False}


# ── GitHub tools ──────────────────────────────────────────────────────────────

@tool
def github_clone_repo(repo_url: str, branch: str, target_dir: str) -> dict:
    """Clone a GitHub repository at a specific branch."""
    return _run(["git", "clone", "--depth=1", "-b", branch, repo_url, target_dir])


@tool
def github_get_pr_files(repo: str, pr_number: int) -> dict:
    """List files changed in a GitHub pull request using gh CLI."""
    return _run(["gh", "pr", "view", str(pr_number), "--repo", repo, "--json",
                 "files,title,body,author,baseRefName,headRefName"])


@tool
def github_post_pr_comment(repo: str, pr_number: int, body: str) -> dict:
    """Post a comment on a GitHub pull request."""
    return _run(["gh", "pr", "comment", str(pr_number), "--repo", repo, "--body", body])


@tool
def github_set_commit_status(repo: str, sha: str, state: str, description: str, context: str) -> dict:
    """Set a commit status (pending/success/failure/error) on GitHub."""
    return _run([
        "gh", "api", f"repos/{repo}/statuses/{sha}",
        "-f", f"state={state}",
        "-f", f"description={description}",
        "-f", f"context={context}",
    ])


@tool
def github_create_check_run(repo: str, sha: str, name: str, conclusion: str, summary: str) -> dict:
    """Create a GitHub check run with a conclusion."""
    payload = json.dumps({
        "name": name,
        "head_sha": sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {"title": name, "summary": summary},
    })
    return _run(["gh", "api", f"repos/{repo}/check-runs", "--input", "-"],
                cwd=None)  # pipe payload via stdin in real use


# ── Docker tools ──────────────────────────────────────────────────────────────

@tool
def docker_build(context_dir: str, image_name: str, tag: str, dockerfile: str = "Dockerfile") -> dict:
    """Build a Docker image from a context directory."""
    return _run(
        ["docker", "build", "-t", f"{image_name}:{tag}", "-f", dockerfile, "."],
        cwd=context_dir,
        timeout=600,
    )


@tool
def docker_push(image_name: str, tag: str) -> dict:
    """Push a Docker image to its registry."""
    return _run(["docker", "push", f"{image_name}:{tag}"])


@tool
def docker_run_tests(image_name: str, tag: str, test_command: str) -> dict:
    """Run a command inside a Docker container (e.g. pytest)."""
    return _run([
        "docker", "run", "--rm",
        f"{image_name}:{tag}",
        "sh", "-c", test_command,
    ], timeout=300)


# ── Security tools ────────────────────────────────────────────────────────────

@tool
def trivy_scan_image(image: str, severity: str = "HIGH,CRITICAL") -> dict:
    """Scan a container image for CVEs using Trivy. Returns JSON report."""
    result = _run([
        "trivy", "image",
        "--exit-code", "0",
        "--severity", severity,
        "--format", "json",
        "--quiet",
        image,
    ], timeout=180)
    if result["success"] and result["stdout"]:
        try:
            result["parsed"] = json.loads(result["stdout"])
        except json.JSONDecodeError:
            result["parsed"] = {}
    return result


@tool
def trivy_scan_filesystem(path: str, severity: str = "HIGH,CRITICAL") -> dict:
    """Scan a local filesystem / repo for vulnerabilities using Trivy."""
    result = _run([
        "trivy", "fs",
        "--exit-code", "0",
        "--severity", severity,
        "--format", "json",
        "--quiet",
        path,
    ], timeout=180)
    if result["success"] and result["stdout"]:
        try:
            result["parsed"] = json.loads(result["stdout"])
        except json.JSONDecodeError:
            result["parsed"] = {}
    return result


@tool
def semgrep_scan(path: str, config: str = "auto") -> dict:
    """Run Semgrep SAST scan on source code. Returns JSON findings."""
    result = _run([
        "semgrep", "--config", config,
        "--json", "--quiet",
        path,
    ], timeout=300)
    if result["stdout"]:
        try:
            result["parsed"] = json.loads(result["stdout"])
        except json.JSONDecodeError:
            result["parsed"] = {}
    return result


@tool
def gitleaks_scan(repo_path: str) -> dict:
    """Scan a git repo for leaked secrets using gitleaks."""
    return _run([
        "gitleaks", "detect",
        "--source", repo_path,
        "--report-format", "json",
        "--report-path", "/tmp/gitleaks-report.json",
        "--no-git",
    ], timeout=120)


@tool
def checkov_scan_k8s(manifest_dir: str) -> dict:
    """Run Checkov IaC security scan on Kubernetes manifests."""
    result = _run([
        "checkov", "-d", manifest_dir,
        "--framework", "kubernetes",
        "--output", "json",
        "--quiet",
    ], timeout=120)
    if result["stdout"]:
        try:
            result["parsed"] = json.loads(result["stdout"])
        except json.JSONDecodeError:
            result["parsed"] = {}
    return result


# ── Kubernetes tools ──────────────────────────────────────────────────────────

@tool
def kubectl_apply(manifest_path: str, namespace: str, dry_run: bool = False) -> dict:
    """Apply a Kubernetes manifest. Set dry_run=True to validate without applying."""
    cmd = ["kubectl", "apply", "-f", manifest_path, "-n", namespace]
    if dry_run:
        cmd += ["--dry-run=client"]
    return _run(cmd)


@tool
def kubectl_get_pods(namespace: str, label_selector: str = "") -> dict:
    """Get running pods in a namespace, optionally filtered by label."""
    cmd = ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
    if label_selector:
        cmd += ["-l", label_selector]
    result = _run(cmd)
    if result["success"] and result["stdout"]:
        try:
            result["parsed"] = json.loads(result["stdout"])
        except json.JSONDecodeError:
            result["parsed"] = {}
    return result


@tool
def kubectl_rollout_status(deployment: str, namespace: str, timeout: str = "120s") -> dict:
    """Wait for a Kubernetes rollout to complete."""
    return _run([
        "kubectl", "rollout", "status",
        f"deployment/{deployment}",
        "-n", namespace,
        f"--timeout={timeout}",
    ])


@tool
def kubectl_rollback(deployment: str, namespace: str) -> dict:
    """Roll back a deployment to its previous revision."""
    return _run(["kubectl", "rollout", "undo", f"deployment/{deployment}", "-n", namespace])


@tool
def kubectl_get_events(namespace: str, since: str = "10m") -> dict:
    """Fetch recent Kubernetes events from a namespace."""
    return _run([
        "kubectl", "get", "events",
        "-n", namespace,
        "--sort-by=.lastTimestamp",
        f"--field-selector=type!=Normal",
    ])


@tool
def kubectl_validate_manifest(manifest_path: str) -> dict:
    """Validate a Kubernetes manifest using kubectl --dry-run=client."""
    return _run(["kubectl", "apply", "--dry-run=client", "-f", manifest_path])


@tool
def kubectl_get_resource_usage(namespace: str) -> dict:
    """Get CPU and memory usage of pods via kubectl top."""
    return _run(["kubectl", "top", "pods", "-n", namespace, "--no-headers"])


# ── ArgoCD tools ──────────────────────────────────────────────────────────────

@tool
def argocd_sync_app(app_name: str, server: str, force: bool = False) -> dict:
    """Trigger an ArgoCD application sync."""
    cmd = ["argocd", "app", "sync", app_name, "--server", server, "--insecure"]
    if force:
        cmd.append("--force")
    return _run(cmd)


@tool
def argocd_get_app_status(app_name: str, server: str) -> dict:
    """Get the current sync and health status of an ArgoCD application."""
    result = _run([
        "argocd", "app", "get", app_name,
        "--server", server, "--insecure",
        "-o", "json",
    ])
    if result["success"] and result["stdout"]:
        try:
            result["parsed"] = json.loads(result["stdout"])
        except json.JSONDecodeError:
            result["parsed"] = {}
    return result


@tool
def argocd_diff_app(app_name: str, server: str) -> dict:
    """Show diff between live state and desired state in ArgoCD."""
    return _run([
        "argocd", "app", "diff", app_name,
        "--server", server, "--insecure",
    ])


@tool
def argocd_rollback_app(app_name: str, server: str, revision: int) -> dict:
    """Roll back an ArgoCD application to a specific git revision."""
    return _run([
        "argocd", "app", "rollback", app_name,
        "--server", server, "--insecure",
        str(revision),
    ])


@tool
def argocd_list_apps(server: str) -> dict:
    """List all ArgoCD applications."""
    result = _run(["argocd", "app", "list", "--server", server, "--insecure", "-o", "json"])
    if result["success"] and result["stdout"]:
        try:
            result["parsed"] = json.loads(result["stdout"])
        except json.JSONDecodeError:
            result["parsed"] = {}
    return result
