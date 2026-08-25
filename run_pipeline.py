#!/usr/bin/env python3
"""
End-to-end orchestrator for the MalWhere pipeline.

Single entry point chaining every stage that, until now, had to be run by
hand as separate commands (see README.md's "Resubmitting dropped files"
section for the manual version this replaces):

  1. Static analysis on the primary sample (malwhere-static container)
  2. Submission to CAPE for dynamic detonation
  3. Poll until the CAPE task reaches a terminal state
  4. Parse the CAPE report, queuing every dropped file for resubmission
  5. Statically analyze every queued dropped file (malwhere-static)
  6. Normalize + map each resubmitted file independently (host, pure-stdlib)
  7. Normalize + map the primary sample (static+dynamic merged)
  8. Export STIX 2.1 (and, opt-in, push to MISP)

This orchestrator itself runs on the host, same as
normalize.py/map_attck.py/parse_cape.py/process_resubmissions.py (all
pure-stdlib). Individual stages delegate into whichever container has
their real dependencies: static analysis into malwhere-static
(pefile/YARA/FLOSS/Ghidra), STIX/MISP export into malwhere-pipeline
(stix2/pymisp) -- neither needs anything installed on the bare host.

Requires: docker + the compose CLI, and this repo's docker/.env already
set up per docker/README.md (host-prereqs.sh, the guest VM, MISP_API_KEY
if --misp is used). It does NOT bootstrap MISP or the guest VM themselves
-- those are one-time setup, out of scope for a per-sample run.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
DOCKER_DIR = REPO_ROOT / "docker"
COMPOSE_FILE = DOCKER_DIR / "docker-compose.yml"

CAPE_API = "http://127.0.0.1:8000/apiv2"
CAPE_TERMINAL_OK = {"reported"}
CAPE_TERMINAL_FAIL = {"banned", "failed_analysis", "failed_processing", "failed_reporting"}


def log(msg: str) -> None:
    print(f"[run_pipeline] {msg}", flush=True)


def banner(msg: str) -> None:
    print(f"\n{'=' * 70}\n{msg}\n{'=' * 70}", flush=True)


def run(cmd, **kw) -> subprocess.CompletedProcess:
    """subprocess.run with echo + non-zero-exit abort, since a half-run
    pipeline with no clear indication of which stage broke is worse than
    stopping immediately.

    Args:
        cmd: Command and arguments to run.
        **kw: Passed through to subprocess.run.

    Returns:
        The completed process.
    """
    log("+ " + " ".join(str(c) for c in cmd))
    result = subprocess.run(cmd, **kw)
    if result.returncode != 0:
        log(f"FAILED (exit {result.returncode}): {' '.join(str(c) for c in cmd)}")
        sys.exit(result.returncode)
    return result


def run_capture(cmd, **kw) -> str:
    """Run a command via run() and return its stdout.

    Args:
        cmd: Command and arguments to run.
        **kw: Passed through to run().

    Returns:
        The command's stdout.
    """
    result = run(cmd, capture_output=True, text=True, **kw)
    return result.stdout


def compose(*args, **kw):
    """Run `docker compose -f COMPOSE_FILE <args>` via run().

    Args:
        *args: Arguments to pass to `docker compose`.
        **kw: Passed through to run().

    Returns:
        The completed process.
    """
    return run(["docker", "compose", "-f", str(COMPOSE_FILE)] + list(args), cwd=DOCKER_DIR, **kw)


def compose_capture(*args, **kw) -> str:
    """Run `docker compose -f COMPOSE_FILE <args>` via run_capture().

    Args:
        *args: Arguments to pass to `docker compose`.
        **kw: Passed through to run_capture().

    Returns:
        The command's stdout.
    """
    return run_capture(["docker", "compose", "-f", str(COMPOSE_FILE)] + list(args), cwd=DOCKER_DIR, **kw)


def load_env_file(path: Path) -> dict:
    """Parse a simple KEY=VALUE .env file.

    Args:
        path: Path to the .env file; missing file returns an empty dict.

    Returns:
        Dict of parsed key/value pairs.
    """
    env = {}
    if not path.exists():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def container_running(name: str) -> bool:
    """Check if a docker-compose service is currently running.

    Args:
        name: Service name.

    Returns:
        True if the service appears in the running-services list.
    """
    out = run_capture(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "ps", "--status", "running", "--format", "{{.Service}}"],
        cwd=DOCKER_DIR,
    )
    return name in out.splitlines()


def ensure_containers(need_dynamic: bool) -> None:
    """Start (if not already running) the static container, and the sandbox containers if needed.

    Args:
        need_dynamic: Also ensure inetsim/cape are up and wait for cape.service to become active.
    """
    banner("Ensuring required containers are up")

    # docker/resubmit_queue is a bind mount (static's `./resubmit_queue:/resubmit:ro`,
    # docker-compose.yml), entirely gitignored -- nothing pre-creates it. On a fresh
    # clone, the FIRST thing to ever touch that path is Docker itself auto-creating
    # the missing bind-mount source, which it does as root. Every later host-side
    # write into it (resubmit_writer.py's manifest_dir/artifacts_dir mkdir, running as
    # the invoking user, not root) then fails with PermissionError. Confirmed hitting
    # this for real on a fresh clone. host-prereqs.sh now creates this ahead of time
    # (as root, so it can also reclaim ownership if Docker already got there first --
    # this run_pipeline.py step alone can't, since a root-owned parent blocks the
    # non-root mkdir below too). Kept here as a backup for the case where this
    # directory genuinely doesn't exist yet.
    for sub in ("manifest", "artifacts"):
        (DOCKER_DIR / "resubmit_queue" / sub).mkdir(parents=True, exist_ok=True)

    if not container_running("static"):
        compose("--profile", "core", "up", "-d", "static")
    else:
        log("static: already running")

    if not container_running("pipeline"):
        compose("--profile", "core", "up", "-d", "pipeline")
    else:
        log("pipeline: already running")

    if need_dynamic:
        for svc in ("inetsim", "cape"):
            if not container_running(svc):
                compose("--profile", "sandbox", "up", "-d", svc)
            else:
                log(f"{svc}: already running")

        log("waiting for CAPE's scheduler to come up...")
        for attempt in range(30):
            out = run_capture(
                ["docker", "compose", "-f", str(COMPOSE_FILE), "exec", "cape",
                 "systemctl", "is-active", "cape.service"],
                cwd=DOCKER_DIR,
            ).strip()
            if out == "active":
                break
            time.sleep(5)
        else:
            log("ERROR: cape.service did not become active in time")
            sys.exit(1)


def run_static_analysis(exe_container_path: str, family: str) -> None:
    """Run static analysis on the sample inside the `static` container.

    Args:
        exe_container_path: Sample path as seen inside the container (/samples/...).
        family: Family label, used as the output subdirectory under /reports.
    """
    banner(f"Static analysis: {exe_container_path}")
    compose("exec", "static", "python3", "/scripts/analyze.py",
            "--sample", exe_container_path, "--output", f"/reports/{family}", "--verbose")


def find_static_report(family: str, sha256: str) -> Path:
    """analyze.py names its output after the input file's stem, not a
    fixed name -- our samples are always named by hash already, so this
    just locates whichever *_static.json landed in the family's report
    dir, rather than assuming one specific filename.

    Args:
        family: Family label, used to locate static/reports/<family>/.
        sha256: Expected sample hash, used to disambiguate multiple reports.

    Returns:
        Path to the matching static report. Exits the process if none is found.
    """
    reports_dir = REPO_ROOT / "static" / "reports" / family
    candidates = sorted(reports_dir.glob("*_static.json"))
    for c in candidates:
        try:
            if json.loads(c.read_text()).get("sha256") == sha256:
                return c
        except Exception:
            continue
    if len(candidates) == 1:
        return candidates[0]
    log(f"ERROR: could not find static report for {sha256} in {reports_dir}")
    sys.exit(1)


def get_env_for_cape() -> dict:
    """Load docker/.env and verify the CAPE-required libvirt/guest-VM variables are set.

    Returns:
        Dict with at least LIBVIRT_GATEWAY, LIBVIRT_BRIDGE, and GUEST_VM_IP.
        Exits the process if any are missing.
    """
    env = load_env_file(DOCKER_DIR / ".env")
    required = ("LIBVIRT_GATEWAY", "LIBVIRT_BRIDGE", "GUEST_VM_IP")
    missing = [k for k in required if not env.get(k)]
    if missing:
        log(f"ERROR: docker/.env is missing {missing} -- run docker/scripts/host-prereqs.sh "
            "and set GUEST_VM_IP first (see docker/README.md)")
        sys.exit(1)
    return env


def submit_to_cape(exe_container_path: str, analysis_timeout: int, env: dict) -> int:
    """Submit the sample to CAPE for detonation via submit.py, run as the cape user.

    Args:
        exe_container_path: Sample path as seen inside the cape container (/samples/...).
        analysis_timeout: CAPE detonation window in seconds.
        env: Dict with LIBVIRT_GATEWAY, LIBVIRT_BRIDGE, GUEST_VM_IP (from get_env_for_cape).

    Returns:
        The new CAPE task ID. Exits the process if the ID can't be parsed from submit.py's output.
    """
    banner(f"Submitting to CAPE: {exe_container_path}")
    whitelist = ",".join(("LIBVIRT_GATEWAY", "LIBVIRT_BRIDGE", "GUEST_VM_IP"))
    # `su - cape` drops the container's own environment (where these three
    # vars already live via the cape service's env_file:), so they're
    # re-injected via `docker compose exec -e` and then explicitly
    # whitelisted through su with -w -- see get_env_for_cape's docstring
    # context in README.md's CAPE section for why su needs this at all.
    exec_flags = []
    for k in ("LIBVIRT_GATEWAY", "LIBVIRT_BRIDGE", "GUEST_VM_IP"):
        exec_flags += ["-e", f"{k}={env[k]}"]
    cape_cmd = (
        f"cd /opt/CAPEv2/utils && poetry run python3 submit.py "
        f"--timeout {analysis_timeout} --enforce-timeout {exe_container_path}"
    )
    out = compose_capture(
        "exec", *exec_flags, "cape",
        "su", "-", "cape", "-w", whitelist, "-c", cape_cmd,
    )
    print(out)
    m = re.search(r"added as task with ID (\d+)", out)
    if not m:
        log("ERROR: could not parse task ID from submit.py output")
        sys.exit(1)
    task_id = int(m.group(1))
    log(f"CAPE task ID: {task_id}")
    return task_id


def cape_task_status(task_id: int) -> str:
    """Query CAPE's REST API for a task's current status.

    Args:
        task_id: CAPE task ID.

    Returns:
        The task's status string, or '' if the API response wasn't valid JSON.
    """
    out = run_capture(["curl", "-s", f"{CAPE_API}/tasks/status/{task_id}/"])
    try:
        return json.loads(out).get("data", "")
    except json.JSONDecodeError:
        return ""


def wait_for_cape_task(task_id: int, timeout_min: int, poll_sec: int) -> None:
    """Poll a CAPE task's status until it reaches a terminal state or times out.

    Args:
        task_id: CAPE task ID to poll.
        timeout_min: Maximum minutes to wait before giving up.
        poll_sec: Seconds between status checks.
    """
    banner(f"Waiting for CAPE task #{task_id} (timeout {timeout_min}m, polling every {poll_sec}s)")
    deadline = time.time() + timeout_min * 60
    last_status = None
    while time.time() < deadline:
        status = cape_task_status(task_id)
        if status != last_status:
            log(f"task #{task_id} status: {status or '(unknown)'}")
            last_status = status
        if status in CAPE_TERMINAL_OK:
            return
        if status in CAPE_TERMINAL_FAIL:
            log(f"ERROR: task #{task_id} ended in failure state: {status}")
            sys.exit(1)
        time.sleep(poll_sec)
    log(f"ERROR: task #{task_id} did not reach a terminal state within {timeout_min} minutes")
    sys.exit(1)


def parse_dynamic_report(task_id: int, family: str, skip_resubmit: bool) -> Path:
    """Parse a completed CAPE task into dynamic_report.json, optionally queuing dropped files for resubmission.

    Args:
        task_id: Completed CAPE task ID to parse.
        family: Family label, used as the output subdirectory under dynamic/reports.
        skip_resubmit: If True, don't pass --resubmit-dir (skip queuing dropped files).

    Returns:
        Path to the written dynamic_report.json.
    """
    banner(f"Parsing CAPE task #{task_id} into dynamic_report.json")
    out_dir = REPO_ROOT / "dynamic" / "reports" / family
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, str(REPO_ROOT / "dynamic" / "scripts" / "parse_cape.py"),
        "--task-id", str(task_id), "--output", str(out_dir), "--family", family, "--verbose",
    ]
    if not skip_resubmit:
        cmd += ["--resubmit-dir", str(DOCKER_DIR / "resubmit_queue")]
    run(cmd)
    return out_dir / "dynamic_report.json"


def process_resubmissions_static() -> None:
    """Run the resubmission loop's static half: analyze every queued dropped file inside the `static` container."""
    banner("Resubmission loop, static half (malwhere-static)")
    compose("exec", "static", "python3", "/scripts/process_resubmissions.py", "--verbose")


def process_resubmissions_merge() -> None:
    """Run the resubmission loop's merge half: normalize + map each dropped file's static report on the host."""
    banner("Resubmission loop, merge half (normalize + map each dropped file)")
    run([sys.executable, str(REPO_ROOT / "pipeline" / "process_resubmissions.py"), "--verbose"])


def normalize_and_map(family: str, static_report: Path, dynamic_report: Path | None) -> Path:
    """Normalize the primary sample's static+dynamic reports and map them to ATT&CK techniques.

    Args:
        family: Family label, used for the output directories.
        static_report: Path to the sample's static analysis report.
        dynamic_report: Path to the sample's dynamic_report.json, or None if dynamic analysis was skipped.

    Returns:
        Path to the written attck_mapping.json.
    """
    banner(f"Normalizing + mapping the primary sample ({family})")
    iocs_dir = REPO_ROOT / "results" / family / "iocs"
    attck_dir = REPO_ROOT / "results" / family / "attck"
    cmd = [
        sys.executable, str(REPO_ROOT / "pipeline" / "normalizer" / "normalize.py"),
        "--static", str(static_report), "--output", str(iocs_dir), "--verbose",
    ]
    if dynamic_report is not None:
        cmd += ["--dynamic", str(dynamic_report)]
    run(cmd)
    run([
        sys.executable, str(REPO_ROOT / "pipeline" / "mapper" / "map_attck.py"),
        "--iocs", str(iocs_dir / "normalized_iocs.json"), "--output", str(attck_dir), "--verbose",
    ])
    return attck_dir / "attck_mapping.json"


def to_container_results_path(host_path: Path) -> str:
    """Translate a host results/ path to its path inside the pipeline
    container, which bind-mounts ../results:/results (see docker-compose.yml).

    Args:
        host_path: Path under REPO_ROOT / "results" on the host.

    Returns:
        The equivalent /results/... path as seen inside the pipeline container.
    """
    return "/results/" + str(host_path.relative_to(REPO_ROOT / "results"))


def export_stix(family: str, mapping_path: Path) -> Path:
    """Export the reconciled ATT&CK mapping as a STIX 2.1 bundle, run inside
    the pipeline container (stix2 lives there, see docker/pipeline/Dockerfile
    -- no host venv needed).

    Args:
        family: Family label, used for the output directory.
        mapping_path: Path to the family's attck_mapping.json.

    Returns:
        Path to the written bundle.stix2.
    """
    banner(f"Exporting STIX 2.1 bundle ({family})")
    stix_dir = REPO_ROOT / "results" / family / "stix"
    compose(
        "exec", "pipeline", "python3", "/app/exporter/export_stix.py",
        "--mapping", to_container_results_path(mapping_path),
        "--output", to_container_results_path(stix_dir), "--verbose",
    )
    return stix_dir / "bundle.stix2"


def export_misp(family: str, mapping_path: Path, publish: bool) -> None:
    """Push the reconciled ATT&CK mapping into MISP as an event, run inside
    the pipeline container (pymisp lives there, see docker/pipeline/Dockerfile
    -- no host venv needed).

    Args:
        family: Family label, used in the MISP event's title.
        mapping_path: Path to the family's attck_mapping.json.
        publish: Publish the event rather than leaving it as a draft.
    """
    banner(f"Pushing to MISP ({family})")
    cmd = [
        "exec", "pipeline", "python3", "/app/exporter/export_misp.py",
        "--mapping", to_container_results_path(mapping_path), "--verbose",
    ]
    if publish:
        cmd.append("--publish")
    compose(*cmd)


def main() -> int:
    """Run the full MalWhere pipeline end-to-end for one sample: static -> dynamic -> resubmission -> ATT&CK mapping -> STIX/MISP export.

    Returns:
        Process exit code (0 on success, 1 on a handled error; unhandled failures exit via sys.exit in helpers).
    """
    parser = argparse.ArgumentParser(
        description="Run the full MalWhere pipeline end-to-end: static -> dynamic -> "
                    "resubmission -> ATT&CK mapping -> STIX/MISP export.",
    )
    parser.add_argument("--sample", required=True, help="Path to the sample file (on the host, under samples/)")
    parser.add_argument("--family", required=True, help="Family label for output directories")
    parser.add_argument("--task-id", type=int, default=None,
                         help="Reuse an existing, already-completed CAPE task instead of "
                              "re-running static analysis and detonation (skips straight to "
                              "parsing + resubmission + export)")
    parser.add_argument("--skip-dynamic", action="store_true",
                         help="Static analysis only, no CAPE submission (no resubmission either, "
                              "since dropped files only exist after detonation)")
    parser.add_argument("--skip-resubmit", action="store_true", help="Skip the resubmission loop")
    parser.add_argument("--misp", action="store_true", help="Also push the result to MISP")
    parser.add_argument("--misp-publish", action="store_true",
                         help="Publish the MISP event rather than leaving it as a draft (implies --misp)")
    parser.add_argument("--analysis-timeout", type=int, default=200,
                         help="CAPE detonation window in seconds (default: 200)")
    parser.add_argument("--cape-timeout-min", type=int, default=20,
                         help="Max minutes to wait for the CAPE task to finish (default: 20)")
    parser.add_argument("--poll-interval", type=int, default=15,
                         help="Seconds between CAPE task status checks (default: 15)")
    args = parser.parse_args()

    if args.misp_publish:
        args.misp = True

    sample_path = Path(args.sample).resolve()
    if not sample_path.exists():
        log(f"ERROR: sample not found: {sample_path}")
        return 1
    try:
        sample_path.relative_to(REPO_ROOT / "samples")
    except ValueError:
        log(f"ERROR: --sample must live under {REPO_ROOT / 'samples'} "
            "(that's what's bind-mounted into the containers as /samples)")
        return 1
    sha256 = run_capture(["sha256sum", str(sample_path)]).split()[0]
    exe_container_path = f"/samples/{sample_path.name}"

    # Detonation (needing cape/inetsim) only applies to a *fresh* submission
    # -- --task-id reuses an already-completed one, so it only ever needs
    # the static container, same as --skip-dynamic.
    need_dynamic = args.task_id is None and not args.skip_dynamic
    ensure_containers(need_dynamic=need_dynamic)

    dynamic_report = None
    if args.task_id is not None:
        task_id = args.task_id
        static_report = find_static_report(args.family, sha256)
        # Always parse the dynamic report when reusing a real, already-
        # completed task -- --skip-resubmit means "don't queue dropped
        # files," not "pretend this sample was never detonated." Only
        # --resubmit-dir is conditional on it.
        dynamic_report = parse_dynamic_report(task_id, args.family, args.skip_resubmit)
    elif args.skip_dynamic:
        run_static_analysis(exe_container_path, args.family)
        static_report = find_static_report(args.family, sha256)
    else:
        run_static_analysis(exe_container_path, args.family)
        static_report = find_static_report(args.family, sha256)
        env = get_env_for_cape()
        task_id = submit_to_cape(exe_container_path, args.analysis_timeout, env)
        wait_for_cape_task(task_id, args.cape_timeout_min, args.poll_interval)
        dynamic_report = parse_dynamic_report(task_id, args.family, args.skip_resubmit)

    if dynamic_report is not None and not args.skip_resubmit:
        process_resubmissions_static()
        process_resubmissions_merge()

    mapping_path = normalize_and_map(args.family, static_report, dynamic_report)
    export_stix(args.family, mapping_path)
    if args.misp:
        export_misp(args.family, mapping_path, publish=args.misp_publish)

    banner(f"DONE: {args.family}")
    log(f"ATT&CK mapping:  results/{args.family}/attck/attck_mapping.json")
    log(f"Navigator layer: results/{args.family}/attck/navigator_layer.json")
    log(f"STIX bundle:     results/{args.family}/stix/bundle.stix2")
    if not args.skip_resubmit and dynamic_report is not None:
        log(f"Resubmitted components: results/{args.family}/resubmitted/*/attck/attck_mapping.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
