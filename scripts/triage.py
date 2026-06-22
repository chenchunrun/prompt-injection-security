#!/usr/bin/env python3
"""
提示注入快速分诊脚本
对输入进行快速分类和优先级排序，适用于 SOC/安全运营场景

用法:
  python scripts/triage.py "可疑输入文本"
  python scripts/triage.py --file inputs.txt --batch
  python scripts/triage.py --pipe  # 从 stdin 读取
"""
import argparse, json, re, sys
from datetime import datetime

TRIAGE_RULES = [
    {
        "id": "PI-001", "name": "直接指令覆盖", "severity": "critical",
        "patterns": [r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)",
                     r"disregard\s+(all\s+)?(previous|prior)",
                     r"forget\s+(everything|all)"],
        "recommendation": "立即拦截"
    },
    {
        "id": "PI-002", "name": "角色注入越狱", "severity": "critical",
        "patterns": [r"you\s+are\s+now\s+", r"pretend\s+(you\s+are|to\s+be)",
                     r"\b(DAN|STAN|DUDE|AIM)\b", r"(jail)?break", r"developer\s+mode"],
        "recommendation": "立即拦截"
    },
    {
        "id": "PI-003", "name": "系统提示提取", "severity": "high",
        "patterns": [r"(show|reveal|output|repeat)\s+(your|the)\s+(system\s+)?(prompt|instructions?)",
                     r"what\s+(are|is)\s+your\s+(system|initial)\s+(prompt|instructions?)"],
        "recommendation": "拦截并告警"
    },
    {
        "id": "PI-004", "name": "编码绕过嫌疑", "severity": "high",
        "patterns": [r"[A-Za-z0-9+/]{40,}={0,2}", r"(5h1f7|1gn0r3|byp4ss|3xpl01t)",
                     r"decode\s+(base64|hex|rot13)", r"\b(vtaber|shacnf)\b"],
        "recommendation": "解码分析"
    },
    {
        "id": "PI-005", "name": "伪系统标签", "severity": "high",
        "patterns": [r"\{reminder\}", r"\{/reminder\}", r"\{critical_reminders\}",
                     r"#MOST IMPORTANT DIRECTIVE#"],
        "recommendation": "拦截并告警"
    },
    {
        "id": "PI-006", "name": "权限提升", "severity": "high",
        "patterns": [r"(as\s+)?(admin|root|sudo)\b.*(disable|bypass|override)",
                     r"disable\s+(safety|filter|restriction|guard)"],
        "recommendation": "拦截"
    },
    {
        "id": "PI-007", "name": "多语言注入", "severity": "medium",
        "patterns": [r"忽略|无视|绕过", r"無視|制限なし", r"Игнорируй"],
        "recommendation": "标记并审核"
    },
    {
        "id": "PI-008", "name": "上下文伪装", "severity": "medium",
        "patterns": [r"hypothetically", r"fictional scenario", r"roleplay",
                     r"in a story where", r"creative writing"],
        "recommendation": "上下文分析"
    },
]

def triage(text: str) -> dict:
    findings = []
    max_severity = "safe"
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "safe": 4}

    for rule in TRIAGE_RULES:
        matches = []
        for p in rule["patterns"]:
            for m in re.finditer(p, text, re.IGNORECASE):
                matches.append(m.group()[:40])
        if matches:
            findings.append({
                "id": rule["id"], "name": rule["name"],
                "severity": rule["severity"], "matches": list(set(matches))[:3],
                "recommendation": rule["recommendation"]
            })
            if severity_order.get(rule["severity"], 99) < severity_order.get(max_severity, 99):
                max_severity = rule["severity"]

    if max_severity == "safe":
        total_safe_rules = sum(1 for f in findings)
    return {
        "text": text[:100],
        "length": len(text),
        "severity": max_severity,
        "findings_count": len(findings),
        "findings": findings,
        "recommendation": "安全" if not findings else findings[0]["recommendation"]
    }

def main():
    parser = argparse.ArgumentParser(description="提示注入快速分诊")
    parser.add_argument("input", nargs="?", help="要检测的文本")
    parser.add_argument("--file", "-f", help="输入文件（一行一条）")
    parser.add_argument("--batch", action="store_true", help="批量模式")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    args = parser.parse_args()

    inputs = []
    if args.file:
        with open(args.file) as f:
            inputs.extend(line.strip() for line in f if line.strip())
    elif args.input:
        inputs.append(args.input)
    elif not sys.stdin.isatty():
        inputs.extend(line.strip() for line in sys.stdin if line.strip())
    else:
        parser.print_help(); return

    results = [triage(t) for t in inputs]

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        severity_icon = {"critical": "CRIT", "high": "HIGH", "medium": "MED",
                        "low": "LOW", "safe": "SAFE"}
        for r in results:
            icon = severity_icon.get(r["severity"], "????")
            print(f"[{icon}] ({r['severity']}) {r['text']}")
            for f in r["findings"]:
                print(f"       -> {f['name']}: {', '.join(f['matches'])}")
            print()

if __name__ == "__main__":
    main()
