#!/usr/bin/env python3
"""
Générateur de rapports PDF professionnels pour les scans de sécurité
"""

import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import seaborn as sns
import pandas as pd
import logging

logger = logging.getLogger(__name__)

class PDFReportGenerator:
    """Génère des rapports PDF professionnels de haute qualité"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_professional_styles()
        
    def _setup_professional_styles(self):
        """Configurer les styles professionnels"""
        
        # Style pour le titre principal
        self.title_style = ParagraphStyle(
            'MainTitle',
            parent=self.styles['Title'],
            fontSize=28,
            textColor=colors.HexColor('#1a1e24'),
            alignment=TA_CENTER,
            spaceAfter=30,
            fontName='Helvetica-Bold'
        )
        
        # Style pour le sous-titre
        self.subtitle_style = ParagraphStyle(
            'SubTitle',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#667eea'),
            alignment=TA_CENTER,
            spaceAfter=40,
            fontName='Helvetica'
        )
        
        # Style pour les titres de section
        self.section_title_style = ParagraphStyle(
            'SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=18,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=15,
            spaceBefore=15,
            fontName='Helvetica-Bold',
            borderPadding=5,
            backColor=colors.HexColor('#ecf0f1')
        )
        
        # Style pour les en-têtes de tableau
        self.table_header_style = ParagraphStyle(
            'TableHeader',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.white,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # Style pour les cellules de tableau
        self.table_cell_style = ParagraphStyle(
            'TableCell',
            parent=self.styles['Normal'],
            fontSize=9,
            alignment=TA_LEFT,
            fontName='Helvetica'
        )
        
        # Styles par sévérité
        self.critical_style = ParagraphStyle(
            'CriticalStyle',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#dc3545'),
            fontSize=10,
            fontName='Helvetica-Bold'
        )
        
        self.high_style = ParagraphStyle(
            'HighStyle',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#fd7e14'),
            fontSize=10,
            fontName='Helvetica-Bold'
        )
        
        self.medium_style = ParagraphStyle(
            'MediumStyle',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#ffc107'),
            fontSize=10
        )
        
        self.low_style = ParagraphStyle(
            'LowStyle',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#28a745'),
            fontSize=10
        )

    def create_header(self, story):
        """Créer l'en-tête professionnel du rapport"""
        
        # Logo ou titre principal
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph("ENTERPRISE SECURITY PLATFORM", self.title_style))
        story.append(Paragraph("Rapport d'Analyse de Sécurité", self.subtitle_style))
        
        # Ligne de séparation
        separator_data = [[""]]
        separator_table = Table(separator_data, colWidths=[7*inch])
        separator_table.setStyle(TableStyle([
            ('LINEBELOW', (0, 0), (-1, -1), 2, colors.HexColor('#667eea')),
        ]))
        story.append(separator_table)
        story.append(Spacer(1, 0.3*inch))

    def create_metadata_section(self, story, scan_data, tenant_info):
        """Créer la section des métadonnées"""
        
        story.append(Paragraph("INFORMATIONS GÉNÉRALES", self.section_title_style))
        
        # Formatage des données
        scan_date = scan_data.get('created_at', 'N/A')
        if hasattr(scan_date, 'strftime'):
            scan_date = scan_date.strftime('%d %B %Y à %H:%M:%S')
        
        # Tableau des métadonnées
        metadata = [
            ["📦 Dépôt scanné", scan_data.get('repo_url', 'N/A')],
            ["📅 Date du scan", scan_date],
            ["⏱️ Durée", f"{scan_data.get('duration_seconds', 0)} secondes"],
            ["📊 Statut", scan_data.get('status', 'N/A').upper()],
            ["🏢 Tenant", tenant_info.get('name', 'Default') if tenant_info else 'Default']
        ]
        
        metadata_table = Table(metadata, colWidths=[2.5*inch, 4.5*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#2c3e50')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(metadata_table)
        story.append(Spacer(1, 0.3*inch))

    def create_summary_section(self, story, summary):
        """Créer la section récapitulative avec graphiques"""
        
        story.append(Paragraph("ANALYSE DES VULNÉRABILITÉS", self.section_title_style))
        
        # Créer les graphiques
        summary_data = self._create_summary_charts(summary)
        
        if summary_data:
            # Graphique de répartition
            story.append(Image(summary_data['severity_chart'], width=6*inch, height=3*inch))
            story.append(Spacer(1, 0.2*inch))
        
        # Tableau des métriques
        total = max(summary.get('total', 1), 1)
        metrics = [
            ["Critique", str(summary.get('critical', 0)), f"{summary.get('critical', 0)/total*100:.1f}%"],
            ["Élevée", str(summary.get('high', 0)), f"{summary.get('high', 0)/total*100:.1f}%"],
            ["Moyenne", str(summary.get('medium', 0)), f"{summary.get('medium', 0)/total*100:.1f}%"],
            ["Faible", str(summary.get('low', 0)), f"{summary.get('low', 0)/total*100:.1f}%"],
            ["Total", str(summary.get('total', 0)), "100%"]
        ]
        
        metrics_table = Table([["Sévérité", "Nombre", "Pourcentage"]] + metrics, 
                              colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
        
        # Style pour l'en-tête
        for i in range(3):
            metrics_table.setStyle(TableStyle([
                ('BACKGROUND', (i, 0), (i, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (i, 0), (i, 0), colors.white),
                ('ALIGN', (i, 0), (i, 0), 'CENTER'),
                ('FONTNAME', (i, 0), (i, 0), 'Helvetica-Bold'),
            ]))
        
        # Style pour les cellules
        for row in range(1, len(metrics) + 1):
            severity = metrics[row-1][0].lower()
            if severity == 'critique':
                metrics_table.setStyle(TableStyle([
                    ('TEXTCOLOR', (0, row), (0, row), colors.HexColor('#dc3545')),
                    ('FONTNAME', (0, row), (0, row), 'Helvetica-Bold'),
                ]))
            elif severity == 'élevée':
                metrics_table.setStyle(TableStyle([
                    ('TEXTCOLOR', (0, row), (0, row), colors.HexColor('#fd7e14')),
                    ('FONTNAME', (0, row), (0, row), 'Helvetica-Bold'),
                ]))
        
        metrics_table.setStyle(TableStyle([
            ('ALIGN', (1, 1), (2, -1), 'CENTER'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(metrics_table)
        story.append(Spacer(1, 0.3*inch))

    def _create_summary_charts(self, summary):
        """Créer des graphiques professionnels"""
        
        try:
            # Style professionnel seaborn
            sns.set_style("whitegrid")
            sns.set_palette(["#dc3545", "#fd7e14", "#ffc107", "#28a745"])
            
            # Graphique en barres
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
            
            # Graphique 1: Barres
            severities = ['Critical', 'High', 'Medium', 'Low']
            counts = [summary.get('critical', 0), summary.get('high', 0), 
                     summary.get('medium', 0), summary.get('low', 0)]
            colors_bar = ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
            
            bars = ax1.bar(severities, counts, color=colors_bar, edgecolor='black', linewidth=1.5)
            ax1.set_ylabel('Nombre de vulnérabilités', fontsize=12, fontweight='bold')
            ax1.set_title('Distribution par Sévérité', fontsize=14, fontweight='bold', pad=15)
            
            for bar, count in zip(bars, counts):
                if count > 0:
                    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                            str(count), ha='center', va='bottom', fontsize=11, fontweight='bold')
            
            # Graphique 2: Camembert
            if sum(counts) > 0:
                wedges, texts, autotexts = ax2.pie(counts, labels=severities, autopct='%1.1f%%',
                                                   startangle=90, explode=(0.05, 0.05, 0.05, 0.05))
                ax2.set_title('Répartition en Pourcentage', fontsize=14, fontweight='bold', pad=15)
                
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_fontsize(11)
                    autotext.set_fontweight('bold')
            
            plt.suptitle(f"Analyse des Vulnérabilités - Total: {summary.get('total', 0)}", 
                        fontsize=16, fontweight='bold', y=1.05)
            plt.tight_layout()
            
            # Sauvegarder
            img_data = io.BytesIO()
            plt.savefig(img_data, format='png', dpi=200, bbox_inches='tight', facecolor='white')
            plt.close()
            img_data.seek(0)
            
            return {'severity_chart': img_data}
            
        except Exception as e:
            logger.error(f"Chart generation error: {e}")
            return None

    def create_findings_table(self, story, findings):
        """Créer le tableau des vulnérabilités"""
        
        story.append(Paragraph("LISTE DES VULNÉRABILITÉS", self.section_title_style))
        
        # Filtrer les vulnérabilités critiques et élevées
        critical_findings = [f for f in findings if f.get('severity') in ['critical', 'high']]
        
        if critical_findings:
            # En-tête du tableau
            data = [["#", "Sévérité", "Titre", "Fichier", "Ligne"]]
            
            for i, finding in enumerate(critical_findings[:25], 1):
                severity = finding.get('severity', 'medium').upper()
                data.append([
                    str(i),
                    severity,
                    finding.get('title', 'N/A')[:60],
                    finding.get('file_path', 'N/A').split('/')[-1],
                    str(finding.get('line_start', 0))
                ])
            
            # Créer le tableau
            findings_table = Table(data, colWidths=[0.5*inch, 0.8*inch, 3.5*inch, 1.5*inch, 0.5*inch])
            
            # Style pour l'en-tête
            for i in range(5):
                findings_table.setStyle(TableStyle([
                    ('BACKGROUND', (i, 0), (i, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (i, 0), (i, 0), colors.white),
                    ('ALIGN', (i, 0), (i, 0), 'CENTER'),
                    ('FONTNAME', (i, 0), (i, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (i, 0), (i, 0), 10),
                ]))
            
            # Style pour les lignes
            for row in range(1, len(data)):
                severity = data[row][1].lower()
                if severity == 'critical':
                    findings_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, row), (-1, row), colors.HexColor('#fff5f5')),
                        ('TEXTCOLOR', (1, row), (1, row), colors.HexColor('#dc3545')),
                        ('FONTNAME', (1, row), (1, row), 'Helvetica-Bold'),
                    ]))
                elif severity == 'high':
                    findings_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, row), (-1, row), colors.HexColor('#fff8f0')),
                        ('TEXTCOLOR', (1, row), (1, row), colors.HexColor('#fd7e14')),
                        ('FONTNAME', (1, row), (1, row), 'Helvetica-Bold'),
                    ]))
            
            findings_table.setStyle(TableStyle([
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('ALIGN', (0, 1), (0, -1), 'CENTER'),
                ('ALIGN', (4, 1), (4, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            
            story.append(findings_table)
            
            if len(critical_findings) > 25:
                story.append(Paragraph(f"* Seulement les 25 premières vulnérabilités sont affichées sur {len(critical_findings)} totales.", 
                                      self.styles['Italic']))
        else:
            story.append(Paragraph("✅ Aucune vulnérabilité critique ou élevée détectée.", 
                                  self.styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))

    def create_recommendations(self, story, summary):
        """Créer la section des recommandations"""
        
        story.append(Paragraph("RECOMMANDATIONS", self.section_title_style))
        
        recommendations = []
        
        if summary.get('critical', 0) > 0:
            recommendations.append(("🔴 CRITIQUE", "Corriger IMMÉDIATEMENT les vulnérabilités critiques (sous 24h)"))
        if summary.get('high', 0) > 0:
            recommendations.append(("🟠 HAUTE", "Corriger sous 72 heures les vulnérabilités élevées"))
        if summary.get('medium', 0) > 0:
            recommendations.append(("🟡 MOYENNE", "Planifier la correction des vulnérabilités moyennes"))
        
        recommendations.extend([
            ("📦 DÉPENDANCES", "Mettre à jour les dépendances vulnérables vers les versions sécurisées"),
            ("🔄 RÉÉVALUATION", "Re-scanner après correction pour valider les correctifs"),
            ("📚 FORMATION", "Former les développeurs aux bonnes pratiques de sécurité"),
            ("📊 MONITORING", "Mettre en place une surveillance continue des vulnérabilités")
        ])
        
        # Créer le tableau des recommandations
        rec_data = [["Priorité", "Action Recommandée"]] + recommendations
        rec_table = Table(rec_data, colWidths=[1.5*inch, 5.5*inch])
        
        # Style pour l'en-tête
        for i in range(2):
            rec_table.setStyle(TableStyle([
                ('BACKGROUND', (i, 0), (i, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (i, 0), (i, 0), colors.white),
                ('ALIGN', (i, 0), (i, 0), 'CENTER'),
                ('FONTNAME', (i, 0), (i, 0), 'Helvetica-Bold'),
            ]))
        
        rec_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(rec_table)
        story.append(Spacer(1, 0.3*inch))

    def create_footer(self, story):
        """Créer le pied de page"""
        
        story.append(Spacer(1, 0.5*inch))
        
        footer_text = f"""
        <font size=8 color="#7f8c8d">
        Rapport généré automatiquement par Enterprise Security Platform<br/>
        Document confidentiel - {datetime.now().year}
        </font>
        """
        
        story.append(Paragraph(footer_text, self.styles['Normal']))

    def generate_report(self, scan_id, scan_data, findings, summary, tenant_info):
        """Générer un rapport PDF complet et professionnel"""
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=0.75*inch, leftMargin=0.75*inch,
                               topMargin=0.75*inch, bottomMargin=0.75*inch,
                               title=f"Security_Report_{scan_id[:8]}")
        
        story = []
        
        # Construction du rapport
        self.create_header(story)
        self.create_metadata_section(story, scan_data, tenant_info)
        self.create_summary_section(story, summary)
        self.create_findings_table(story, findings)
        self.create_recommendations(story, summary)
        self.create_footer(story)
        
        # Génération du PDF
        doc.build(story)
        buffer.seek(0)
        
        return buffer