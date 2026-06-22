#!/usr/bin/env python3
"""回归测试 —— #5 报告对比器 compare.py 的数据函数。"""
import sys
from compare import risk_label, overview_row, layer_vuln_counts, find_flips, _fmt_table



def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}" + ("" if cond else f"  {detail}"))
    else:
        msg = f"{name}" + (f"  {detail}" if detail else "")
        print(f"  FAIL  {msg}")
        raise AssertionError(msg)


def case(cid, status):
    return {"id": cid, "name": cid, "status": status, "reason": "", "response": ""}


def mkreport(model, layers, severity=None, weighted=0.5, seed="0x00000001", target="chatbot"):
    severity = severity or {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    results, total, vuln = [], 0, 0
    for cases in layers.values():
        for c in cases:
            results.append(c)
            total += 1
            if c["status"] == "VULN":
                vuln += 1
    return {
        "model": model, "target": target, "target_label": "x", "seed": seed,
        "marker": "FLAG-X", "canary": None,
        "summary": {"total": total, "vuln": vuln, "safe": total - vuln, "unclear": 0, "error": 0},
        "severity": severity, "weighted_score": weighted,
        "layers": layers, "results": results,
    }


def test_risk_label():
    print("\n[#5] risk_label")
    check("2+ CRITICAL -> RED", risk_label(mkreport("m", {}, severity={"CRITICAL": 2}, weighted=0)) == "RED")
    check("1 CRITICAL -> YELLOW", risk_label(mkreport("m", {}, severity={"CRITICAL": 1}, weighted=0)) == "YELLOW")
    check("ws>=1.0 -> RED", risk_label(mkreport("m", {}, weighted=1.2)) == "RED")
    check("ws 0.5 无 crit -> YELLOW", risk_label(mkreport("m", {}, weighted=0.5)) == "YELLOW")
    check("ws 0.1 -> GREEN", risk_label(mkreport("m", {}, weighted=0.1)) == "GREEN")
    check("ws 0 -> OK", risk_label(mkreport("m", {}, weighted=0)) == "OK")


def test_overview_row():
    print("\n[#5] overview_row")
    r = mkreport("qwen", {"L": [case("C-01", "VULN"), case("C-02", "SAFE")]},
                 severity={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "NONE": 1}, weighted=0.5)
    row = overview_row(r)
    check("model", row["model"] == "qwen")
    check("vuln_pct 50%", abs(row["vuln_pct"] - 50.0) < 0.01, row["vuln_pct"])
    check("risk YELLOW", row["risk"] == "YELLOW")


def test_layer_vuln_counts():
    print("\n[#5] layer_vuln_counts")
    layers = {
        "指令覆盖": [case("C-01", "VULN"), case("C-02", "VULN"), case("C-03", "SAFE")],
        "系统提取": [case("E-01", "SAFE"), case("E-02", "SAFE")],
    }
    r = mkreport("m", layers)
    counts = layer_vuln_counts(r)
    check("指令覆盖 2/3", counts["指令覆盖"] == (2, 3), counts.get("指令覆盖"))
    check("系统提取 0/2", counts["系统提取"] == (0, 2), counts.get("系统提取"))


def test_find_flips():
    print("\n[#5] find_flips（同 target+seed 的两份报告）")
    r1 = mkreport("base", {"L": [case("C-01", "VULN"), case("C-02", "VULN"), case("C-03", "VULN")]})
    r2 = mkreport("fortified", {"L": [case("C-01", "VULN"), case("C-02", "SAFE"), case("C-03", "SAFE")]})
    flips = find_flips(r1, r2)
    ids = {f["id"] for f in flips}
    check("C-01 未变（不在 flips）", "C-01" not in ids, ids)
    check("C-02 翻转", "C-02" in ids, ids)
    check("C-03 翻转", "C-03" in ids, ids)


def test_find_flips_different_seed_returns_empty():
    print("\n[#5] find_flips（不同 seed → 不对比，返回空）")
    r1 = mkreport("a", {"L": [case("C-01", "VULN")]}, seed="0x00000001")
    r2 = mkreport("b", {"L": [case("C-01", "SAFE")]}, seed="0x00000002")
    check("不同 seed 不对比", find_flips(r1, r2) == [], find_flips(r1, r2))


def test_fmt_table():
    print("\n[#5] _fmt_table 渲染")
    out = _fmt_table(["模型", "漏洞率"], [["alpha", "1/2"], ["beta", "0/2"]])
    lines = out.split("\n")
    check("3 行（表头+分隔+数据起点）", len(lines) >= 4, f"got {len(lines)}")
    check("含表头'模型'", "模型" in out)
    check("含数据'alpha'", "alpha" in out)
    check("含分隔线", any(set(l) <= set("- ") and "-" in l for l in lines))


_TESTS = [test_risk_label, test_overview_row, test_layer_vuln_counts,
          test_find_flips, test_find_flips_different_seed_returns_empty, test_fmt_table]

if __name__ == "__main__":
    failed = 0
    for t in _TESTS:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  !! {t.__name__}: {e}")
    print("\n" + "=" * 50)
    print("结果:", "全部通过 ✅" if not failed else f"{failed} 个测试函数失败")
    sys.exit(1 if failed else 0)
