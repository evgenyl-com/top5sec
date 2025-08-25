import os
import re

def generate_html_report(results_summary, output_path=None, account_id=None, region=None, report_date=None):
    """
    Generate a static HTML report for the top 5 findings in results_summary.
    Each block shows severity, details, impact, and highlights recommendations (remediation).
    Only show blocks for findings that are not None and not 'No data available.'
    Avoid duplicate recommendations.
    Do not show block titles.
    """
    def extract_impact(text):
        # Match 'IMPACT:' at the start, possibly with leading whitespace
        lines = str(text).split('\n')
        impacts = [l.strip() for l in lines if re.search(r'^\s*IMPACT:', l)]
        # Remove duplicates while preserving order (ignore whitespace differences)
        seen = set()
        unique_impacts = []
        for imp in impacts:
            norm = re.sub(r'\s+', ' ', imp)
            if norm not in seen:
                unique_impacts.append(imp)
                seen.add(norm)
        return unique_impacts
    def extract_recommendations(text):
        lines = str(text).split('\n')
        recs = [l for l in lines if re.search(r'remediation recommended', l, re.I)]
        seen = set()
        unique_recs = []
        for rec in recs:
            if rec not in seen:
                unique_recs.append(rec)
                seen.add(rec)
        return unique_recs
    issue_blocks = []
    for i in range(1, 6):
        details = results_summary.get(i)
        if not details or details == "No data available.":
            continue
        detail_lines = [l for l in str(details).split('\n') if not re.search(r'^\s*IMPACT:', l)]
        impacts = extract_impact(details)
        recs = extract_recommendations(details)
        details_html = ''
        for idx, line in enumerate(detail_lines):
            cls = ''
            if idx >= 15:
                cls = ' style="display:none;" class="extra-detail"'
            details_html += f'<div{cls}>{line}</div>'
        show_more_btn = ''
        if len(detail_lines) > 15:
            show_more_btn = f'''<button class="show-more-btn" onclick="this.parentNode.querySelectorAll('.extra-detail').forEach(r=>r.style.display='block');this.style.display='none';">Show more</button>'''
        block = f'''<div class="issue-card severity-{i}">
            <div class="severity-label">Severity {i}</div>
            <div class="details">{details_html}</div>
            {show_more_btn}
            {''.join(f'<div class="impact">{imp}</div>' for imp in impacts)}
        </div>'''
        issue_blocks.append(block)
    html_out = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Top5Sec AWS Security Report</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f7f8fa; margin: 0; padding: 0; }}
        .container {{ max-width: 900px; margin: 40px auto; background: #fff; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); padding: 32px 24px; }}
        h1 {{ text-align: center; color: #2d3748; margin-bottom: 8px; }}
        .subtitle {{ text-align: center; color: #4a5568; margin-bottom: 32px; }}
        .logo {{ display: block; margin: 0 auto 16px auto; max-width: 120px; }}
        .meta-info {{ text-align: center; color: #4a5568; margin-bottom: 18px; font-size: 1.05em; }}
        .meta-info span {{ margin: 0 12px; }}
        .print-btn {{ background: #38b2ac; color: #fff; border: none; border-radius: 5px; padding: 8px 22px; font-size: 1em; cursor: pointer; margin: 0 auto 18px auto; display: block; }}
        .issue-list {{ display: flex; flex-direction: column; gap: 32px; }}
        .issue-card {{ border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.04); padding: 24px 20px; background: #f9fafb; border-left: 8px solid #e53e3e; transition: border-color 0.2s; }}
        .issue-card.severity-1 {{ border-color: #e53e3e; }}
        .issue-card.severity-2 {{ border-color: #ed8936; }}
        .issue-card.severity-3 {{ border-color: #ecc94b; }}
        .issue-card.severity-4 {{ border-color: #38b2ac; }}
        .issue-card.severity-5 {{ border-color: #4299e1; }}
        .severity-label {{ font-weight: bold; font-size: 1.1em; padding: 4px 12px; border-radius: 6px; color: #fff; display: inline-block; margin-bottom: 10px; }}
        .severity-1 .severity-label {{ background: #e53e3e; }}
        .severity-2 .severity-label {{ background: #ed8936; }}
        .severity-3 .severity-label {{ background: #ecc94b; color: #2d3748; }}
        .severity-4 .severity-label {{ background: #38b2ac; }}
        .severity-5 .severity-label {{ background: #4299e1; }}
        .details-table {{ width: 100%; border-collapse: collapse; margin-bottom: 8px; }}
        .details-table td {{ border: 1px solid #eee; padding: 6px 10px; font-size: 1em; color: #4a5568; background: #fff; }}
        .details-table tr.hidden {{ display: none; }}
        .show-more-btn {{ background: #3182ce; color: #fff; border: none; border-radius: 5px; padding: 6px 16px; font-size: 0.95em; cursor: pointer; margin-top: 8px; }}
        .impact {{ background: #ffe4e1; border-left: 4px solid #e53e3e; color: #a94442; padding: 10px 14px; margin: 12px 0; border-radius: 7px; font-weight: 500; }}
        .recommendation {{ background: #fffbea; border-left: 4px solid #ecc94b; color: #744210; padding: 10px 14px; margin: 12px 0; border-radius: 7px; font-weight: 500; }}
        @media (max-width: 600px) {{
            .container {{ padding: 8px 2px; }}
            h1 {{ font-size: 1.2em; }}
            .logo {{ max-width: 80px; }}
            .meta-info {{ font-size: 0.95em; margin-bottom: 10px; }}
            .issue-card {{ padding: 10px 2px; font-size: 0.95em; }}
            .subtitle {{ font-size: 1em; margin-bottom: 18px; }}
            .print-btn {{ padding: 6px 12px; font-size: 0.95em; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/9/93/Amazon_Web_Services_Logo.svg/2560px-Amazon_Web_Services_Logo.svg.png" alt="AWS Logo" class="logo" />
        <button class="print-btn" onclick="window.print()">Print Report</button>
        <h1>AWS Security Report</h1>
        <div class="meta-info">
            <span><b>Date:</b> {report_date or ''}</span>
            <span><b>Account ID:</b> {account_id or ''}</span>
            <span><b>Region:</b> {region or ''}</span>
        </div>
        <div class="subtitle">Your Top Most Critical AWS Security Issues</div>
        <div class="issue-list">
            {''.join(issue_blocks)}
        </div>
    </div>
</body>
</html>'''
    output_path = output_path or os.path.join(os.path.dirname(__file__), '..', 'top5sec_report.html')
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_out)
    print(f"HTML report generated: {output_path}")
