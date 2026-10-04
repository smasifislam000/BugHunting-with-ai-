"""
modules/docker_k8s_check.py
---------------------------
Docker / Kubernetes misconfiguration detection.

Finds:
  - Unauthenticated Docker API (port 2375/2376)
  - Kubernetes API server (port 6443, 8080)
  - Exposed kubelet (10250, 10255)
  - etcd (2379, 2380)
  - Common K8s dashboards
"""

import socket
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines, run_command
from core.tool_checker import has_tool
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("docker_k8s")


# ─────────────────────────────────────────
# Ports to check
# ─────────────────────────────────────────
DOCKER_PORTS = [
    (2375, "Docker API (HTTP)"),
    (2376, "Docker API (HTTPS)"),
    (4243, "Docker API alt"),
]

K8S_PORTS = [
    (6443, "Kubernetes API"),
    (8080, "Kubernetes insecure API"),
    (8443, "Kubernetes alt"),
    (10250, "Kubelet"),
    (10255, "Kubelet read-only"),
    (10256, "Kubelet health"),
    (2379, "etcd"),
    (2380, "etcd peer"),
    (3000, "Grafana"),
    (9090, "Prometheus"),
]


# ─────────────────────────────────────────
# Port scan helper
# ─────────────────────────────────────────
def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ─────────────────────────────────────────
# Docker checks
# ─────────────────────────────────────────
def check_docker_api(host: str, port: int = 2375) -> Optional[Dict]:
    """
    Check if Docker API is unauthenticated.
    """
    url = f"http://{host}:{port}/version"
    r = safe_request(url, timeout=6)
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    if "Version" in data or "ApiVersion" in data:
        return {
            "type": "docker_api_exposed",
            "url": url,
            "evidence": f"Docker API: {data.get('Version')} (API {data.get('ApiVersion')})",
            "severity": "critical",
            "confidence": 95,
        }
    return None


def check_docker_containers(host: str, port: int = 2375) -> Optional[Dict]:
    """
    Check if containers are listable.
    """
    url = f"http://{host}:{port}/containers/json"
    r = safe_request(url, timeout=6)
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    if isinstance(data, list):
        return {
            "type": "docker_containers_listable",
            "url": url,
            "evidence": f"{len(data)} containers exposed unauthenticated",
            "severity": "critical",
            "confidence": 95,
        }
    return None


# ─────────────────────────────────────────
# Kubernetes checks
# ─────────────────────────────────────────
def check_k8s_api(host: str, port: int) -> Optional[Dict]:
    """
    Check for unauthenticated K8s API.
    """
    url = f"https://{host}:{port}/api"
    r = safe_request(url, timeout=6, verify=False)
    if not r:
        return None
    if r.status_code == 200:
        try:
            data = r.json()
            versions = [v for v in data.get("versions", []) if v]
            if versions:
                return {
                    "type": "k8s_api_unauthenticated",
                    "url": url,
                    "evidence": f"K8s API accessible: {versions}",
                    "severity": "critical",
                    "confidence": 90,
                }
        except Exception:
            pass
    elif r.status_code == 403:
        return {
            "type": "k8s_api_restricted",
            "url": url,
            "evidence": "K8s API present but auth required",
            "severity": "info",
            "confidence": 70,
        }
    return None


def check_kubelet(host: str, port: int = 10255) -> Optional[Dict]:
    """
    Check for unauthenticated kubelet read-only endpoint.
    """
    url = f"http://{host}:{port}/pods"
    r = safe_request(url, timeout=6)
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    if "items" in data:
        return {
            "type": "kubelet_pods_exposed",
            "url": url,
            "evidence": f"Kubelet exposes {len(data['items'])} pods unauthenticated",
            "severity": "critical",
            "confidence": 95,
        }
    return None


def check_etcd(host: str, port: int = 2379) -> Optional[Dict]:
    """
    Check etcd /version.
    """
    url = f"http://{host}:{port}/version"
    r = safe_request(url, timeout=6)
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    if "etcdserver" in data or "etcdcluster" in data:
        return {
            "type": "etcd_exposed",
            "url": url,
            "evidence": f"etcd version: {data.get('etcdserver')}",
            "severity": "critical",
            "confidence": 90,
        }
    return None


def check_common_dashboards(host: str) -> List[Dict]:
    """
    Check for Grafana, Prometheus, K8s dashboard.
    """
    findings: List[Dict] = []
    candidates = [
        ("http://{}:3000/login", "grafana"),
        ("http://{}:9090/graph", "prometheus"),
        ("https://{}/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/", "k8s_dashboard"),
        ("http://{}/dashboard/", "kubernetes_dashboard"),
    ]
    for tmpl, kind in candidates:
        url = tmpl.format(host)
        r = safe_request(url, timeout=5, verify=False)
        if r and r.status_code in (200, 302):
            findings.append({
                "type": f"{kind}_exposed",
                "url": url,
                "evidence": f"{kind} dashboard reachable (status {r.status_code})",
                "severity": "high",
                "confidence": 60,
            })
    return findings


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def _hosts_from_urls(urls: List[str]) -> List[str]:
    hosts = set()
    for u in urls:
        try:
            p = urlparse(u)
            h = p.hostname
            if h:
                hosts.add(h)
        except Exception:
            continue
    return sorted(hosts)


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "docker_k8s_check", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        info("No URLs to derive hosts from")
        return {"count": 0, "findings": []}

    hosts = _hosts_from_urls(urls)
    if not hosts:
        return {"count": 0, "findings": []}

    info(f"Checking {len(hosts[:10])} hosts for Docker/K8s endpoints")
    findings: List[Dict] = []

    for host in hosts[:10]:
        # Docker ports
        for port, label in DOCKER_PORTS:
            if not _port_open(host, port):
                continue
            try:
                f = check_docker_api(host, port)
                if f:
                    findings.append(f)
                f = check_docker_containers(host, port)
                if f:
                    findings.append(f)
            except Exception as e:
                log.debug(f"docker check failed {host}:{port}: {e}")

        # K8s ports
        for port, label in K8S_PORTS:
            if not _port_open(host, port):
                continue
            try:
                if port in (6443, 8080, 8443):
                    f = check_k8s_api(host, port)
                    if f:
                        findings.append(f)
                elif port in (10250, 10255):
                    f = check_kubelet(host, port)
                    if f:
                        findings.append(f)
                elif port in (2379, 2380):
                    f = check_etcd(host, port)
                    if f:
                        findings.append(f)
            except Exception as e:
                log.debug(f"k8s check failed {host}:{port}: {e}")

        # Dashboards on standard ports
        try:
            findings.extend(check_common_dashboards(host))
        except Exception as e:
            log.debug(f"dashboard check failed {host}: {e}")

    # Save
    for f in findings:
        save_finding(domain, "docker_k8s_check", f["type"], f["severity"],
                     f["url"], evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "docker_k8s_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}"
                     for f in findings])
        ok(f"Found {len(findings)} Docker/K8s finding(s)")
    else:
        info("No Docker/K8s exposures detected")

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Docker/K8s scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "docker_k8s_check", run, args.output)