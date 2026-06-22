#!/usr/bin/env python3
"""回归测试 —— #6 多种子聚合 aggregate_reports。"""
import sys
import math
from test_llm import aggregate_reports



def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        msg = f"{name}" + (f"  {detail}" if detail else "")
        print(f"  FAIL  {msg}")
        raise AssertionError(msg)


def case(cid, status):
    return {"id": cid, "name": cid, "status": status, "reason": "", "response": ""}


def mkreport(seed, layers_vuln, weighted=0.5):
    """layers_vuln: {layer: (vuln_count, total_count)}"""
    layers, results = {}, []
    for layer, (v, t) in layers_vuln.items():
        cs = []
        for i in range(t):
            c = case(f"{layer}-{i}", "VULN" if i < v else "SAFE")
            cs.append(c)
            results.append(c)
        layers[layer] = cs
    total = sum(t for _, t in layers_vuln.values())
    vuln = sum(v for v, _ in layers_vuln.values())
    return {
        "seed": seed,
        "summary": {"total": total, "vuln": vuln, "safe": total - vuln, "unclear": 0, "error": 0},
        "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": vuln, "NONE": total - vuln},
        "weighted_score": weighted,
        "layers": layers, "results": results,
    }


def near(a, b, eps=0.01):
    return abs(a - b) < eps


def test_aggregate_basic():
    print("\n[#6] aggregate_reports 基础")
    reps = [mkreport("0x01", {"L": (3, 5)}), mkreport("0x02", {"L": (3, 5)}), mkreport("0x03", {"L": (3, 5)})]
    agg = aggregate_reports(reps)
    check("n=3", agg["n"] == 3)
    check("vuln_rate_mean 60%", near(agg["vuln_rate_mean"], 0.6), agg["vuln_rate_mean"])
    check("layer L mean 3", near(agg["layers"]["L"]["vuln_mean"], 3))
    check("layer L stdev 0（一致）", near(agg["layers"]["L"]["vuln_stdev"], 0))


def test_aggregate_variance():
    print("\n[#6] aggregate_reports 方差（[1,3,5] of 5）")
    reps = [mkreport("0x01", {"L": (1, 5)}), mkreport("0x02", {"L": (3, 5)}), mkreport("0x03", {"L": (5, 5)})]
    agg = aggregate_reports(reps)
    # 总体标准差 pstdev([1,3,5]) = sqrt(8/3) ≈ 1.633
    check("mean 3", near(agg["layers"]["L"]["vuln_mean"], 3))
    check("pstdev ≈1.633", near(agg["layers"]["L"]["vuln_stdev"], math.sqrt(8 / 3)), agg["layers"]["L"]["vuln_stdev"])
    check("vuln_rate_mean 60%", near(agg["vuln_rate_mean"], 0.6))


def test_aggregate_severity_mean():
    print("\n[#6] aggregate_reports 严重度均值")
    reps = [
        mkreport("0x01", {"L": (2, 4)}, weighted=0.4),
        mkreport("0x02", {"L": (4, 4)}, weighted=0.8),
    ]
    agg = aggregate_reports(reps)
    check("LOW 均值 3", near(agg["severity_mean"]["LOW"], 3.0), agg["severity_mean"]["LOW"])
    check("weighted 均值 0.6", near(agg["weighted_score_mean"], 0.6), agg["weighted_score_mean"])


def test_aggregate_multi_layer():
    print("\n[#6] aggregate_reports 多层面")
    reps = [mkreport("0x01", {"指令覆盖": (5, 5), "系统提取": (0, 4)}),
            mkreport("0x02", {"指令覆盖": (3, 5), "系统提取": (2, 4)})]
    agg = aggregate_reports(reps)
    check("指令覆盖 mean 4", near(agg["layers"]["指令覆盖"]["vuln_mean"], 4))
    check("系统提取 mean 1", near(agg["layers"]["系统提取"]["vuln_mean"], 1))
    check("两个层面都在", set(agg["layers"]) == {"指令覆盖", "系统提取"})


_TESTS = [test_aggregate_basic, test_aggregate_variance, test_aggregate_severity_mean, test_aggregate_multi_layer]

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
