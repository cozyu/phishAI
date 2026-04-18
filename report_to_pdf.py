#!/usr/bin/env python3
"""phishAI 보고서 PDF 변환 에이전트

마크다운 분석 보고서를 PDF로 변환한다.
Chrome headless를 사용하여 한국어 렌더링을 지원한다.

사용법:
    python3 report_to_pdf.py reports/ppxxzz.com_2026-04-16_report.md
    python3 report_to_pdf.py reports/ppxxzz.com_2026-04-16_report.md -o output.pdf
"""

import argparse
import html
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def md_to_html(md_text: str) -> str:
    """마크다운을 HTML로 변환 (외부 라이브러리 없이). ```mermaid 블록은 mermaid.js용 div로 변환."""
    lines = md_text.split("\n")
    out = []
    in_code = False
    in_mermaid = False
    in_table = False
    in_ul = False
    in_ol = False
    in_blockquote = False

    for line in lines:
        # 코드 블록 시작/종료
        if line.strip().startswith("```"):
            if in_mermaid:
                out.append("</div>")
                in_mermaid = False
            elif in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                lang = line.strip().replace("```", "").strip().lower()
                if lang == "mermaid":
                    out.append('<div class="mermaid">')
                    in_mermaid = True
                else:
                    out.append(f'<pre class="code-block"><code>')
                    in_code = True
            continue
        if in_mermaid:
            # mermaid 문법은 escape하지 않고 그대로 (mermaid.js가 파싱)
            out.append(line)
            continue
        if in_code:
            out.append(html.escape(line))
            continue

        # 빈 줄
        if not line.strip():
            if in_table:
                out.append("</tbody></table>")
                in_table = False
            if in_ul:
                out.append("</ul>")
                in_ul = False
            if in_ol:
                out.append("</ol>")
                in_ol = False
            if in_blockquote:
                out.append("</blockquote>")
                in_blockquote = False
            out.append("")
            continue

        # 테이블
        if "|" in line and not line.strip().startswith("```"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            # 구분선 건너뛰기
            if all(re.match(r'^[-:]+$', c) for c in cells):
                continue
            if not in_table:
                out.append('<table><thead><tr>')
                for c in cells:
                    out.append(f"<th>{process_inline(c)}</th>")
                out.append("</tr></thead><tbody>")
                in_table = True
            else:
                out.append("<tr>")
                for c in cells:
                    out.append(f"<td>{process_inline(c)}</td>")
                out.append("</tr>")
            continue

        # 헤딩
        m = re.match(r'^(#{1,6})\s+(.*)', line)
        if m:
            level = len(m.group(1))
            text = process_inline(m.group(2))
            cls = "section-title" if level <= 2 else ""
            out.append(f'<h{level} class="{cls}">{text}</h{level}>')
            continue

        # 리스트
        m = re.match(r'^(\s*)[-*]\s+(.*)', line)
        if m:
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{process_inline(m.group(2))}</li>")
            continue

        # 번호 리스트
        m = re.match(r'^(\s*)\d+\.\s+(.*)', line)
        if m:
            if not in_ol:
                out.append("<ol>")
                in_ol = True
            out.append(f"<li>{process_inline(m.group(2))}</li>")
            continue

        # blockquote
        m = re.match(r'^>\s?(.*)', line)
        if m:
            if not in_blockquote:
                out.append("<blockquote>")
                in_blockquote = True
            out.append(f"<p>{process_inline(m.group(1))}</p>")
            continue

        # 수평선
        if re.match(r'^---+$', line.strip()):
            out.append("<hr>")
            continue

        # 일반 텍스트
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False
        if in_blockquote:
            out.append("</blockquote>")
            in_blockquote = False
        out.append(f"<p>{process_inline(line)}</p>")

    if in_table:
        out.append("</tbody></table>")
    if in_ul:
        out.append("</ul>")
    if in_ol:
        out.append("</ol>")
    if in_blockquote:
        out.append("</blockquote>")

    return "\n".join(out)


def process_inline(text: str) -> str:
    """인라인 마크다운 처리 (볼드, 이탤릭, 코드, 링크)"""
    text = html.escape(text)
    text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    text = re.sub(r'`([^`]+)`', r'<code class="inline">\1</code>', text)
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', text)
    return text


CSS = """
@page {
    size: A4;
    margin: 20mm 18mm 25mm 18mm;
    @bottom-center {
        content: counter(page) " / " counter(pages);
        font-size: 9px;
        color: #888;
    }
}
body {
    font-family: "Noto Sans CJK KR", "Noto Sans KR", "Malgun Gothic", sans-serif;
    font-size: 11px;
    line-height: 1.65;
    color: #1a1a1a;
    max-width: 100%;
}
h1 {
    font-size: 22px;
    border-bottom: 3px solid #c0392b;
    padding-bottom: 8px;
    margin-top: 30px;
    color: #c0392b;
}
h2 {
    font-size: 16px;
    border-bottom: 2px solid #2c3e50;
    padding-bottom: 5px;
    margin-top: 25px;
    color: #2c3e50;
    page-break-after: avoid;
}
h3 {
    font-size: 13px;
    color: #34495e;
    margin-top: 18px;
    page-break-after: avoid;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0;
    font-size: 10px;
    page-break-inside: avoid;
}
th {
    background: #2c3e50;
    color: white;
    padding: 6px 8px;
    text-align: left;
    font-weight: 600;
}
td {
    padding: 5px 8px;
    border-bottom: 1px solid #ddd;
}
tr:nth-child(even) { background: #f8f9fa; }
tr:hover { background: #eef2f7; }
pre.code-block {
    background: #1e1e1e;
    color: #d4d4d4;
    padding: 12px;
    border-radius: 6px;
    font-size: 9.5px;
    line-height: 1.5;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    page-break-inside: avoid;
}
code.inline {
    background: #f0f0f0;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 10px;
    color: #c0392b;
}
hr {
    border: none;
    border-top: 1px solid #ccc;
    margin: 20px 0;
}
ul, ol { padding-left: 20px; }
li { margin: 3px 0; }
blockquote {
    border-left: 4px solid #bdc3c7;
    margin: 10px 0;
    padding: 8px 15px;
    background: #f9f9f9;
    color: #555;
}
strong { color: #c0392b; }
a { color: #2980b9; text-decoration: none; }
.list-item { margin: 2px 0; padding-left: 15px; }
.mermaid {
    text-align: center;
    margin: 20px 0;
    page-break-inside: avoid;
    background: #fafafa;
    padding: 15px;
    border-radius: 6px;
}
.mermaid svg { max-width: 100%; height: auto; }
"""


def convert(md_path: str, output_path: str = None) -> str:
    """마크다운 파일을 PDF로 변환"""
    md_path = Path(md_path)
    if not md_path.exists():
        print(f"[!] 파일 없음: {md_path}")
        sys.exit(1)

    if not output_path:
        output_path = str(md_path.with_suffix(".pdf"))

    md_text = md_path.read_text(encoding="utf-8")
    body_html = md_to_html(md_text)

    full_html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<style>{CSS}</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>
  window.addEventListener('DOMContentLoaded', () => {{
    if (window.mermaid) {{
      mermaid.initialize({{
        startOnLoad: true,
        theme: 'default',
        flowchart: {{ htmlLabels: true, curve: 'linear' }},
        securityLevel: 'loose',
      }});
      // 렌더 완료 신호 (Chrome이 idle로 판단하도록)
      window.mermaidReady = true;
    }}
  }});
</script>
</head>
<body>
{body_html}
</body>
</html>"""

    # 임시 HTML 파일 생성
    with tempfile.NamedTemporaryFile(suffix=".html", mode="w", encoding="utf-8", delete=False) as f:
        f.write(full_html)
        html_path = f.name

    # Chrome headless로 PDF 생성
    chrome = None
    for candidate in ["google-chrome", "google-chrome-stable", "chromium-browser", "chromium"]:
        try:
            subprocess.run([candidate, "--version"], capture_output=True, timeout=5)
            chrome = candidate
            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    if not chrome:
        print("[!] Chrome/Chromium을 찾을 수 없습니다")
        sys.exit(1)

    print(f"[*] PDF 변환 중... ({chrome})")
    # mermaid.js 비동기 렌더 완료를 기다리기 위해 virtual-time-budget 사용
    result = subprocess.run([
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-software-rasterizer",
        "--run-all-compositor-stages-before-draw",
        "--virtual-time-budget=10000",
        f"--print-to-pdf={output_path}",
        "--print-to-pdf-no-header",
        html_path,
    ], capture_output=True, text=True, timeout=60)

    # 임시 파일 정리
    Path(html_path).unlink(missing_ok=True)

    if Path(output_path).exists():
        size = Path(output_path).stat().st_size
        print(f"[*] PDF 생성 완료: {output_path} ({size:,} bytes)")
        return output_path
    else:
        print(f"[!] PDF 생성 실패")
        if result.stderr:
            print(result.stderr[:500])
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="phishAI 보고서 MD → PDF 변환")
    parser.add_argument("input", help="입력 마크다운 파일 경로")
    parser.add_argument("-o", "--output", help="출력 PDF 파일 경로 (기본: 입력파일명.pdf)")
    args = parser.parse_args()

    from ti_clients.api_logger import setup_run_logger
    from pathlib import Path as _P
    log_path = setup_run_logger("report_to_pdf", _P(args.input).stem)
    print(f"[*] 실행 로그: {log_path}")

    convert(args.input, args.output)


if __name__ == "__main__":
    main()
