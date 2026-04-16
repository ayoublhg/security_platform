#!/usr/bin/env python3
"""
Script complet pour scanner et rémédier
"""

import subprocess
import json
import requests
import os
import uuid
import tempfile
import shutil
from datetime import datetime

API_URL = "http://localhost:8000/api/v1"  # Utiliser l'orchestrateur directement
TENANT_ID = "default"
REPO_URL = "https://github.com/juice-shop/juice-shop.git"

def clone_repo():
    """Cloner le dépôt"""
    repo_path = tempfile.mkdtemp()
    subprocess.run(["git", "clone", "--depth", "1", REPO_URL, repo_path], capture_output=True)
    return repo_path

def run_semgrep(repo_path):
    """Scanner avec Semgrep"""
    print("🔍 Scan SAST avec Semgrep...")
    try:
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", repo_path],
            capture_output=True, text=True, timeout=300
        )
        if result.stdout:
            data = json.loads(result.stdout)
            findings = []
            for r in data.get("results", []):
                findings.append({
                    "title": r.get("check_id", "Unknown"),
                    "description": r.get("extra", {}).get("message", ""),
                    "severity": r.get("extra", {}).get("severity", "medium").lower(),
                    "scanner": "semgrep",
                    "type": "sast",
                    "file": r.get("path", ""),
                    "line": r.get("start", {}).get("line", 0)
                })
            print(f"   ✅ {len(findings)} vulnérabilités trouvées")
            return findings
    except Exception as e:
        print(f"   ❌ Erreur: {e}")
    return []

def run_gitleaks(repo_path):
    """Scanner avec Gitleaks"""
    print("🔐 Scan Secrets avec Gitleaks...")
    try:
        result = subprocess.run(
            ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--no-git"],
            capture_output=True, text=True, timeout=180
        )
        if result.stdout:
            data = json.loads(result.stdout)
            findings = []
            items = data if isinstance(data, list) else data.get("findings", [])
            for f in items:
                findings.append({
                    "title": f"Secret: {f.get('RuleID', 'unknown')}",
                    "description": f.get("Description", ""),
                    "severity": "critical",
                    "scanner": "gitleaks",
                    "type": "secret",
                    "file": f.get("File", ""),
                    "line": f.get("StartLine", 0)
                })
            print(f"   ✅ {len(findings)} secrets trouvés")
            return findings
    except Exception as e:
        print(f"   ❌ Erreur: {e}")
    return []

def create_scan():
    """Créer un scan dans la plateforme"""
    scan_data = {
        "repo_url": REPO_URL,
        "scan_types": ["sast", "secrets"],  # ← Seulement les scanners autorisés
        "tenant_id": TENANT_ID
    }
    try:
        response = requests.post(f"{API_URL}/scans", json=scan_data)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            return response.json().get("scan_id")
        print(f"   Response: {response.text}")
        return None
    except Exception as e:
        print(f"   Exception: {e}")
        return None

def add_finding(scan_id, finding):
    """Ajouter un finding à la plateforme"""
    finding_data = {
        "finding_id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "tenant_id": TENANT_ID,
        "title": finding["title"],
        "description": finding["description"],
        "severity": finding["severity"],
        "scanner_name": finding["scanner"],
        "finding_type": finding["type"],
        "file_path": finding["file"],
        "line_number": finding["line"],
        "status": "open"
    }
    try:
        response = requests.post(f"{API_URL}/findings", json=finding_data)
        return response.status_code in [200, 201]
    except Exception as e:
        print(f"   Error: {e}")
        return False

def main():
    print("=" * 60)
    print("🔒 SCAN DE SÉCURITÉ - JUICE SHOP")
    print("=" * 60)
    
    # 1. Cloner
    print("\n📁 Clonage du dépôt...")
    repo_path = clone_repo()
    
    # 2. Créer scan
    print("\n📝 Création du scan...")
    scan_id = create_scan()
    if not scan_id:
        print("❌ Impossible de créer le scan")
        shutil.rmtree(repo_path, ignore_errors=True)
        return
    print(f"   Scan ID: {scan_id}")
    
    # 3. Scanner
    all_findings = []
    all_findings.extend(run_semgrep(repo_path))
    all_findings.extend(run_gitleaks(repo_path))
    
    # 4. Ajouter findings
    print(f"\n📤 Ajout de {len(all_findings)} findings...")
    for finding in all_findings:
        if add_finding(scan_id, finding):
            print(f"   ✅ {finding['title'][:50]}...")
    
    # 5. Nettoyer
    shutil.rmtree(repo_path, ignore_errors=True)
    
    print("\n" + "=" * 60)
    print(f"🎉 Scan terminé !")
    print(f"📊 Dashboard: http://localhost:5000")
    print(f"📈 Findings ajoutés: {len(all_findings)}")
    print("=" * 60)

if __name__ == "__main__":
    main()