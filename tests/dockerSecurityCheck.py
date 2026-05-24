#!/usr/bin/env python3
import subprocess
import json
import os


def _cmd(args):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"Príkaz nenájdený: {args[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def _docker_available():
    rc, _, _ = _cmd(["docker", "info"])
    return rc == 0


def _podman_available():
    rc, _, _ = _cmd(["podman", "info"])
    return rc == 0


def _get_running_containers(runtime="docker"):
    rc, out, _ = _cmd([runtime, "ps", "-q"])
    if rc != 0 or not out:
        return []
    return [cid.strip() for cid in out.splitlines() if cid.strip()]


def _inspect_container(container_id, runtime="docker"):
    rc, out, _ = _cmd([runtime, "inspect", container_id])
    if rc != 0 or not out:
        return None
    try:
        data = json.loads(out)
        return data[0] if isinstance(data, list) and data else None
    except json.JSONDecodeError:
        return None


def _check_daemon_config(findings):
    daemon_path = "/etc/docker/daemon.json"
    recommendations = {
        "no-new-privileges": (True, "zabraňuje procesom získať nové privilégiá"),
        "userns-remap":      (None, "user namespace remapping — izoluje UID kontajnerov"),
        "live-restore":      (True, "kontajnery prežijú reštart démona"),
        "icc":               (False, "zakáže priamu komunikáciu medzi kontajnermi"),
    }

    if not os.path.exists(daemon_path):
        findings.append(
            "WARNING: /etc/docker/daemon.json neexistuje — démon beží s predvolenými nastaveniami"
        )
        return

    try:
        with open(daemon_path) as f:
            cfg = json.load(f)
    except Exception as e:
        findings.append(f"WARNING: Nepodarilo sa načítať daemon.json: {e}")
        return

    for key, (expected, desc) in recommendations.items():
        if key not in cfg:
            findings.append(f"WARNING: daemon.json neobsahuje '{key}' ({desc})")
        elif expected is not None and cfg[key] != expected:
            findings.append(
                f"WARNING: daemon.json má '{key}' = {cfg[key]}, odporúčané: {expected} ({desc})"
            )


def _check_container(container_id, inspect_data, findings, runtime):
    name = inspect_data.get("Name", container_id).lstrip("/")
    host_config = inspect_data.get("HostConfig", {})

    if host_config.get("Privileged", False):
        findings.append(
            f"CRITICAL: Kontajner '{name}' beží v privilegovanom režime "
            f"— má plný prístup k hostiteľskému kernelu"
        )

    binds = host_config.get("Binds") or []
    for bind in binds:
        if "/var/run/docker.sock" in bind:
            findings.append(
                f"CRITICAL: Kontajner '{name}' má pripojený Docker socket "
                f"— umožňuje úplný únik z kontajnera"
            )

    if host_config.get("NetworkMode", "") == "host":
        findings.append(
            f"FAIL: Kontajner '{name}' zdieľa hostiteľský network namespace (NetworkMode=host)"
        )

    if host_config.get("PidMode", "") == "host":
        findings.append(
            f"FAIL: Kontajner '{name}' zdieľa hostiteľský PID namespace (PidMode=host)"
        )

    if host_config.get("IpcMode", "") == "host":
        findings.append(
            f"FAIL: Kontajner '{name}' zdieľa hostiteľský IPC namespace (IpcMode=host)"
        )

    mem_limit = host_config.get("Memory", 0)
    cpu_quota = host_config.get("CpuQuota", 0)
    if mem_limit == 0:
        findings.append(f"WARNING: Kontajner '{name}' nemá nastavený limit pamäte")
    if cpu_quota == 0:
        findings.append(f"WARNING: Kontajner '{name}' nemá nastavený limit CPU")

    if not host_config.get("ReadonlyRootfs", False):
        findings.append(
            f"INFO: Kontajner '{name}' nemá ReadOnly root filesystem — odporúčané pre produkciu"
        )


def run(params=None):
    if params is None:
        params = {}

    check_podman = params.get("check_podman", True)

    findings = []
    containers_checked = []
    runtime_found = None

    if _docker_available():
        runtime_found = "docker"
        findings.append("INFO: Docker démon je dostupný a beží")
        _check_daemon_config(findings)
    elif check_podman and _podman_available():
        runtime_found = "podman"
        findings.append("INFO: Podman je dostupný (rootless/rootful)")
    else:
        return {
            "test_name": "Docker/Container Security Check",
            "status": "OK",
            "message": "Docker ani Podman nie sú na systéme nainštalované — test preskočený",
            "findings": ["INFO: Žiadny kontajnerový runtime nebol nájdený"],
            "recommendation": "Žiadna akcia nie je potrebná",
        }

    container_ids = _get_running_containers(runtime_found)

    if not container_ids:
        findings.append("INFO: Žiadne bežiace kontajnery nenájdené")
    else:
        findings.append(f"INFO: Nájdených {len(container_ids)} bežiacich kontajnerov")
        for cid in container_ids:
            data = _inspect_container(cid, runtime_found)
            if data is None:
                findings.append(f"WARNING: Nepodarilo sa získať inspect pre kontajner {cid}")
                continue
            _check_container(cid, data, findings, runtime_found)
            containers_checked.append(cid)

    critical = [f for f in findings if f.startswith("CRITICAL")]
    fails    = [f for f in findings if f.startswith("FAIL")]
    warnings = [f for f in findings if f.startswith("WARNING")]

    if critical:
        status = "CRITICAL"
        message = f"Kritické bezpečnostné problémy v kontajnerovom prostredí: {len(critical)} nálezov"
    elif fails:
        status = "FAIL"
        message = f"Vážne problémy s izoláciou kontajnerov: {len(fails)} nálezov"
    elif warnings:
        status = "WARNING"
        message = f"Odporúčané nastavenia kontajnerov nie sú splnené: {len(warnings)} upozornení"
    else:
        status = "OK"
        message = "Kontajnerové prostredie je nakonfigurované bezpečne"

    return {
        "test_name": "Docker/Container Security Check",
        "status": status,
        "message": message,
        "runtime": runtime_found,
        "containers_checked": len(containers_checked),
        "findings": findings,
        "recommendation": (
            "Odstráňte privilegované kontajnery, namontované Docker sockety a zdieľané namespaces. "
            "Nastavte limity zdrojov a použite read-only root filesystem tam kde je to možné. "
            "Skontrolujte a doplňte /etc/docker/daemon.json podľa CIS Docker Benchmark."
        ) if status != "OK" else "Žiadna akcia nie je potrebná",
    }


if __name__ == "__main__":
    import json as _json
    result = run({})
    print(_json.dumps(result, indent=2, ensure_ascii=False))
