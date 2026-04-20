#!/usr/bin/env python3
import asyncio
import asyncpg
import random
from datetime import datetime

async def add_findings():
    conn = await asyncpg.connect(
        user='postgres',
        password='secure_password',
        database='security_platform',
        host='localhost',
        port=5432
    )
    
    # Récupérer un scan_id existant
    scan_id = await conn.fetchval("SELECT scan_id FROM scans LIMIT 1")
    
    findings = [
        {
            'title': 'Cross-Site Scripting (XSS) dans le champ recherche',
            'description': 'Le champ de recherche est vulnérable aux attaques XSS. Un attaquant pourrait exécuter du JavaScript malveillant.',
            'severity': 'high',
            'scanner': 'semgrep',
            'type': 'sast',
            'file': 'src/views/search.html',
            'line': 45,
            'cvss': 7.4,
            'exploit': True,
            'cisa': False
        },
        {
            'title': 'Informations de débogage exposées',
            'description': 'Le mode debug est activé en production, exposant des informations sensibles.',
            'severity': 'medium',
            'scanner': 'checkov',
            'type': 'iac',
            'file': 'config/production.yaml',
            'line': 23,
            'cvss': 5.3,
            'exploit': False,
            'cisa': False
        },
        {
            'title': 'CSRF Token manquant',
            'description': 'Les formulaires ne sont pas protégés contre les attaques CSRF.',
            'severity': 'medium',
            'scanner': 'semgrep',
            'type': 'sast',
            'file': 'src/forms/login.html',
            'line': 12,
            'cvss': 6.5,
            'exploit': True,
            'cisa': False
        },
        {
            'title': 'Mot de passe faible autorisé',
            'description': 'La politique de mot de passe permet des mots de passe trop faibles (< 8 caractères).',
            'severity': 'low',
            'scanner': 'tfsec',
            'type': 'iac',
            'file': 'terraform/iam.tf',
            'line': 30,
            'cvss': 4.0,
            'exploit': False,
            'cisa': False
        },
        {
            'title': 'Version de Node.js obsolète',
            'description': 'Node.js 14.x est utilisé mais n\'est plus supporté. Mettez à jour vers la version 18.x LTS.',
            'severity': 'low',
            'scanner': 'trivy',
            'type': 'container',
            'file': 'Dockerfile',
            'line': 1,
            'cvss': 3.7,
            'exploit': False,
            'cisa': False
        }
    ]
    
    for f in findings:
        await conn.execute("""
            INSERT INTO findings (
                finding_id, scan_id, tenant_id, title, description,
                severity, scanner_name, finding_type, file_path, line_start,
                cvss_score, exploit_available, cisa_kev, status, detected_at
            ) VALUES (
                gen_random_uuid(), $1, 'default', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'open', NOW()
            )
        """, scan_id, f['title'], f['description'], f['severity'], 
           f['scanner'], f['type'], f['file'], f['line'], 
           f['cvss'], f['exploit'], f['cisa'])
        print(f"✅ Ajouté: {f['title']}")
    
    await conn.close()
    print("\n🎉 Tous les findings ont été ajoutés !")

if __name__ == "__main__":
    asyncio.run(add_findings())