#!/usr/bin/env python3
"""
Script pour scanner plusieurs dépôts et ajouter automatiquement les findings
"""

import subprocess
import json
import requests
import os
import uuid
import tempfile
import shutil
from datetime import datetime

# CHANGEMENT ICI : Utiliser le dashboard au lieu de l'orchestrateur
API_URL = "http://localhost:5000/api/v1"
TENANT_ID = "default"

# Liste des dépôts vulnérables à scanner
REPOS = [
    {
        "name": "juice-shop",
        "url": "https://github.com/juice-shop/juice-shop.git",
        "scan_types": ["sast", "secrets"]
    },
    {
        "name": "dvwa",
        "url": "https://github.com/digininja/DVWA.git",
        "scan_types": ["sast", "secrets"]
    },
    {
        "name": "webgoat",
        "url": "https://github.com/WebGoat/WebGoat.git",
        "scan_types": ["sast", "secrets"]
    },
    {
        "name": "vulnerable-node",
        "url": "https://github.com/cr0hn/vulnerable-node.git",
        "scan_types": ["sast", "secrets"]
    },
    {
        "name": "sqli-labs",
        "url": "https://github.com/Audi-1/sqli-labs.git",
        "scan_types": ["sast"]
    }
]

def clone_repo(repo_url):
    """Cloner le dépôt"""
    repo_path = tempfile.mkdtemp()
    result = subprocess.run(["git", "clone", "--depth", "1", repo_url, repo_path], 
                           capture_output=True, text=True, encoding='utf-8', errors='ignore')
    if result.returncode != 0:
        print(f"   ❌ Erreur de clonage: {result.stderr}")
        return None
    return repo_path

def run_semgrep(repo_path, repo_name):
    """Scanner avec Semgrep - règles complètes"""
    print(f"   🔍 Scan SAST avec Semgrep...")
    findings = []
    try:
        cmd = [
            "semgrep", 
            "--config", "p/owasp-top-ten",
            "--config", "p/security-audit",
            "--json", 
            repo_path
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                               encoding='utf-8', errors='ignore')
        
        if result.stdout:
            data = json.loads(result.stdout)
            for r in data.get("results", []):
                severity = r.get("extra", {}).get("severity", "medium").lower()
                if severity == "error":
                    severity = "high"
                elif severity == "warning":
                    severity = "medium"
                
                findings.append({
                    "title": r.get("check_id", "Unknown").replace(".", " - ")[:200],
                    "description": r.get("extra", {}).get("message", "")[:500],
                    "severity": severity,
                    "scanner": "semgrep",
                    "type": "sast",
                    "file": r.get("path", "")[:200],
                    "line": r.get("start", {}).get("line", 0),
                    "repo_name": repo_name
                })
        print(f"      ✅ {len(findings)} vulnérabilités trouvées")
    except subprocess.TimeoutExpired:
        print(f"      ⏰ Semgrep a pris trop de temps")
    except Exception as e:
        print(f"      ❌ Erreur Semgrep: {e}")
    return findings

def run_gitleaks(repo_path, repo_name):
    """Scanner avec Gitleaks"""
    print(f"   🔐 Scan Secrets avec Gitleaks...")
    findings = []
    try:
        result = subprocess.run(
            ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--no-git"],
            capture_output=True, text=True, timeout=180, encoding='utf-8', errors='ignore'
        )
        if result.stdout:
            data = json.loads(result.stdout)
            items = data if isinstance(data, list) else data.get("findings", [])
            for f in items:
                findings.append({
                    "title": f"Secret exposé: {f.get('RuleID', 'unknown')}",
                    "description": f.get("Description", "Un secret a été trouvé dans le code"),
                    "severity": "critical",
                    "scanner": "gitleaks",
                    "type": "secret",
                    "file": f.get("File", ""),
                    "line": f.get("StartLine", 0),
                    "repo_name": repo_name
                })
        print(f"      ✅ {len(findings)} secrets trouvés")
    except Exception as e:
        print(f"      ❌ Erreur Gitleaks: {e}")
    return findings

def create_scan(repo_url, scan_types):
    """Créer un scan dans la plateforme"""
    scan_data = {
        "repo_url": repo_url,
        "scan_types": scan_types,
        "tenant_id": TENANT_ID
    }
    try:
        # Utiliser l'orchestrateur pour créer le scan
        response = requests.post("http://localhost:8000/api/v1/scans", json=scan_data, timeout=10)
        if response.status_code == 200:
            return response.json().get("scan_id")
        return None
    except Exception as e:
        print(f"      ❌ Erreur création scan: {e}")
        return None

def add_finding(scan_id, finding):
    """Ajouter un finding à la plateforme via le dashboard"""
    finding_data = {
        "finding_id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "tenant_id": TENANT_ID,
        "title": finding["title"][:500],
        "description": finding["description"][:1000],
        "severity": finding["severity"],
        "scanner_name": finding["scanner"],
        "finding_type": finding["type"],
        "file_path": finding["file"][:500],
        "line_number": finding["line"],
        "status": "open"
    }
    try:
        # CHANGEMENT ICI : Utiliser le dashboard (port 5000)
        response = requests.post(f"http://localhost:5000/api/v1/findings", json=finding_data, timeout=10)
        return response.status_code in [200, 201]
    except Exception as e:
        print(f"      ❌ Erreur ajout finding: {e}")
        return False

def main():
    print("=" * 70)
    print("🔒 SCAN DE SÉCURITÉ - MULTIPLES DÉPÔTS")
    print("=" * 70)
    
    total_findings = 0
    total_repos = 0
    
    for repo in REPOS:
        total_repos += 1
        print(f"\n📦 {repo['name'].upper()}")
        print(f"   URL: {repo['url']}")
        
        # Cloner
        print(f"   📁 Clonage...")
        repo_path = clone_repo(repo['url'])
        if not repo_path:
            continue
        
        # Créer scan
        print(f"   📝 Création du scan...")
        scan_id = create_scan(repo['url'], repo['scan_types'])
        if not scan_id:
            print(f"   ❌ Impossible de créer le scan")
            shutil.rmtree(repo_path, ignore_errors=True)
            continue
        print(f"      ✅ Scan ID: {scan_id[:8]}...")
        
        # Scanner
        all_findings = []
        
        if "sast" in repo['scan_types']:
            all_findings.extend(run_semgrep(repo_path, repo['name']))
        
        if "secrets" in repo['scan_types']:
            all_findings.extend(run_gitleaks(repo_path, repo['name']))
        
        # Ajouter findings
        print(f"   📤 Ajout de {len(all_findings)} findings...")
        for finding in all_findings:
            if add_finding(scan_id, finding):
                print(f"      ✅ [{finding['severity'].upper()}] {finding['title'][:60]}...")
                total_findings += 1
        
        # Nettoyer
        shutil.rmtree(repo_path, ignore_errors=True)
    
    print("\n" + "=" * 70)
    print(f"🎉 SCAN TERMINÉ !")
    print(f"📦 Dépôts scannés: {total_repos}")
    print(f"🔍 Findings trouvés: {total_findings}")
    print(f"📊 Dashboard: http://localhost:5000")
    print("=" * 70)

if __name__ == "__main__":
    main()