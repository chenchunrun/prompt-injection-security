#!/usr/bin/env python3
"""回归测试 —— 开源发布修复: SSRF 校验 / canary 熵 / LLM judge JSON 解析 / 错误脱敏。"""
import sys
import random

from test_llm import _validate_base_url, _redacted_err
from markers import get_canary
from judge import _parse_judge_json



def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        msg = f"{name}" + (f"  {detail}" if detail else "")
        print(f"  FAIL  {msg}")
        raise AssertionError(msg)


# ─── H3: base_url SSRF 校验 ───
def test_validate_base_url():
    print("\n[H3] _validate_base_url")
    check("http 通过", _validate_base_url("http://localhost:11434") == "http://localhost:11434")
    check("https 通过", _validate_base_url("https://api.openai.com/v1") == "https://api.openai.com/v1")
    for bad in ["file:///etc/passwd", "ftp://x/y", "gopher://x", "/etc/passwd", "169.254.169.254",
                "http://169.254.169.254/latest/meta-data", "http://metadata.google.internal",
                "http://foo.internal"]:
        try:
            _validate_base_url(bad)
            check(f"拒绝 {bad}", False, "未抛 ValueError")
        except ValueError:
            check(f"拒绝 {bad}", True)


# ─── canary 熵: k=8 ───
def test_canary_entropy():
    print("\n[MEDIUM] canary 熵 (k=8)")
    c = get_canary(random.Random(1))
    check("CANARY- 前缀", c.startswith("CANARY-"))
    suffix = c.split("-", 1)[1]
    check("后缀 8 字符", len(suffix) == 8, f"got {c!r} suffix={suffix!r}")
    check("后缀仅大写字母+数字", suffix.isalnum() and suffix.upper() == suffix)
    # 可复现
    check("可复现", get_canary(random.Random(1)) == get_canary(random.Random(1)))
    # 不同种子大概率不同
    cs = {get_canary(random.Random(s)) for s in range(50)}
    check("50 个种子全不同（高熵）", len(cs) == 50)


# ─── LLM judge JSON 解析鲁棒性 ───
def test_parse_judge_json():
    print("\n[MEDIUM] _parse_judge_json")
    check("裸 JSON", _parse_judge_json('{"verdict":"RED","compliant":true,"reason":"x"}').get("verdict") == "RED")
    check("```json 多行围栏", _parse_judge_json('```json\n{"verdict":"GREEN"}\n```').get("verdict") == "GREEN")
    check("单行围栏（原 bug）", _parse_judge_json('```{"verdict":"YELLOW"}```').get("verdict") == "YELLOW")
    check("前后噪声文本", _parse_judge_json('Sure! Here:\n{"verdict":"RED"}\nThanks').get("verdict") == "RED")
    check("无 JSON → 空字典", _parse_judge_json("no json here") == {})
    check("损坏 JSON → 空字典", _parse_judge_json('{not valid json') == {})


# ─── H2: 错误脱敏 ───
def test_redacted_err():
    print("\n[H2] _redacted_err")
    s = _redacted_err("network error")
    check("含 ERR 标记", s.startswith("[ERR:"))
    check("含 redacted 提示", "redacted" in s)
    check("不含原始异常细节", "Bearer" not in s and "sk-" not in s)


_TESTS = [test_validate_base_url, test_canary_entropy, test_parse_judge_json, test_redacted_err]

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
