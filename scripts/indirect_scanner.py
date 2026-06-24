#!/usr/bin/env python3
"""
间接提示注入扫描器
扫描网页、文档、API 响应等外部数据源中的隐藏注入指令

用法:
  python scripts/indirect_scanner.py --url "https://example.com"
  python scripts/indirect_scanner.py --text "外部内容..."
  python scripts/indirect_scanner.py --url "https://github.com/..." --github
"""
import argparse, json, re, sys
from urllib.request import Request

# SSRF 防护统一收敛到 netsec：限 http/https、拒云元数据端点（含编码 IP 绕过）、重定向拦截内网。
from netsec import validate_url, safe_urlopen

MAX_RESPONSE_BYTES = 5_000_000  # 响应大小上限，防内存炸弹


def _validate_scan_url(url: str) -> str:
    """SSRF 校验：委托 netsec.validate_url（限 http/https、拒云元数据含编码 IP 绕过）。返回去尾斜杠 url。"""
    return validate_url(url)

# 隐藏 CSS 模式
HIDDEN_CSS = [
    r'display\s*:\s*none',
    r'visibility\s*:\s*hidden',
    r'font-size\s*:\s*0\s*px?',
    r'color\s*:\s*white.*background.*white',
    r'opacity\s*:\s*0',
    r'position\s*:\s*absolute.*left\s*:\s*-9999',
]

# 注入关键词
INJECTION_KW = [
    r'ignore\s+(all\s+)?(previous|prior)\s+(instructions?|rules?)',
    r'you\s+are\s+now\s+',
    r'output\s+(your\s+)?(system\s+)?prompt',
    r'you\s+must\s+respond',
    r'new\s+(directive|instruction|rule)',
    r'disregard\s+(all\s+)?(previous|prior)',
    r'#MOST IMPORTANT DIRECTIVE#',
    r'\{reminder\}', r'\{/reminder\}',
]

# Leet 关键词 (解码后)
LEET_PATTERNS = [
    r'[0157]{3,}[a-z]{2,}[0157]{2,}', r'5h1f7', r'1gn0r3', r'byp4ss',
]

def scan_html(html: str, source: str = "") -> list:
    findings = []
    for pattern in HIDDEN_CSS:
        for m in re.finditer(pattern, html, re.IGNORECASE):
            findings.append({"type": "hidden_css", "pattern": pattern,
                           "match": m.group()[:50], "source": source})
    for pattern in INJECTION_KW:
        for m in re.finditer(pattern, html, re.IGNORECASE):
            findings.append({"type": "injection_kw", "pattern": pattern,
                           "match": m.group()[:50], "source": source})
    for pattern in LEET_PATTERNS:
        for m in re.finditer(pattern, html, re.IGNORECASE):
            findings.append({"type": "leet_code", "pattern": pattern,
                           "match": m.group()[:50], "source": source})
    return findings

def fetch_url(url: str, timeout: int = 15, max_bytes: int = MAX_RESPONSE_BYTES) -> str:
    """获取 URL 内容。SSRF 防护：校验 scheme/主机，限制响应大小。"""
    url = _validate_scan_url(url)  # 不合法则抛 ValueError
    req = Request(url, headers={"User-Agent": "PI-Scanner/1.0"})
    with safe_urlopen(req, timeout=timeout) as resp:  # 拦截重定向到内网/元数据
        # 限量读取，防止超大响应耗尽内存
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"响应超过 {max_bytes} 字节上限，已中止")
        return data.decode("utf-8", errors="replace")

def main():
    parser = argparse.ArgumentParser(description="间接注入扫描器")
    parser.add_argument("--url", "-u", help="扫描目标 URL")
    parser.add_argument("--text", "-t", help="直接提供文本")
    parser.add_argument("--file", "-f", help="扫描本地文件")
    parser.add_argument("--github", action="store_true", help="GitHub README 模式")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    args = parser.parse_args()

    content = None
    source = ""
    if args.url:
        source = args.url
        try:
            content = fetch_url(args.url)
            print(f"获取: {args.url} ({len(content)} bytes)")
        except Exception as e:
            print(f"ERROR: {e}"); sys.exit(1)
    elif args.file:
        source = args.file
        with open(args.file, encoding="utf-8") as f: content = f.read()
    elif args.text:
        source = "text"
        content = args.text
    else:
        parser.print_help(); sys.exit(1)

    findings = scan_html(content, source)

    if args.json:
        print(json.dumps({"source": source, "findings": findings,
                         "total": len(findings)}, indent=2, ensure_ascii=False))
    else:
        print(f"\n扫描源: {source}")
        print(f"发现: {len(findings)} 个问题\n")
        if not findings:
            print("  SAFE - 未发现可疑内容")
        for f in findings:
            print(f"  [{f['type']}] {f['match']}")
        print()

if __name__ == "__main__":
    main()
