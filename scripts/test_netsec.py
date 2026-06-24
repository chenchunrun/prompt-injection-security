#!/usr/bin/env python3
"""回归测试 —— SSRF 防护加固：编码 IP 元数据绕过 / 重定向内网拦截 / netsec 原语。

纯标准库，运行：python3 test_netsec.py
"""
import sys
from netsec import (validate_url, is_safe_initial_url, is_safe_redirect_target,
                    decode_ip_literal)


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        msg = f"{name}" + (f"  {detail}" if detail else "")
        print(f"  FAIL  {msg}")
        raise AssertionError(msg)


def test_initial_url():
    print("\n[SSRF] 初始 URL（允许 localhost/私网/公网；拒云元数据含编码 IP 绕过）")
    for ok in ["http://localhost:11434", "http://127.0.0.1:11434", "https://api.openai.com/v1",
               "http://192.168.1.10:8080", "http://example.com"]:
        check(f"通过 {ok}", is_safe_initial_url(ok), "应放行")
    for bad in ["http://169.254.169.254/latest/meta-data", "http://metadata.google.internal",
                "http://metadata.azure.com", "http://169.254.170.2",   # AWS ECS metadata
                "http://2852039166",       # 十进制整数 = 169.254.169.254
                "http://0xa9fea9fe",       # 十六进制 = 169.254.169.254
                "http://169.254.123.45",   # 链路本地段
                "http://foo.internal", "http://foo.local",
                "file:///etc/passwd", "ftp://x", "gopher://x"]:
        check(f"拒绝 {bad}", not is_safe_initial_url(bad), "应拦截")


def test_redirect_target():
    print("\n[SSRF] 重定向目标（拒全部内网/环回/链路本地/元数据）")
    for bad in ["http://127.0.0.1", "http://10.0.0.1", "http://192.168.1.1",
                "http://172.16.0.1", "http://169.254.169.254", "http://0.0.0.0",
                "http://[::1]"]:
        check(f"拒绝重定向 {bad}", not is_safe_redirect_target(bad), "应拦截")
    # 公网 IP 字面量应放行
    check("放行公网 IP 重定向", is_safe_redirect_target("http://93.184.216.34"))


def test_decode_ip_literal():
    print("\n[SSRF] 编码 IP 解码")
    check("十进制 2852039166 → 169.254.169.254", str(decode_ip_literal("2852039166")) == "169.254.169.254")
    check("十六进制 0x7f000001 → 127.0.0.1", str(decode_ip_literal("0x7f000001")) == "127.0.0.1")
    check("明文 IP 10.1.2.3 不变", str(decode_ip_literal("10.1.2.3")) == "10.1.2.3")
    check("主机名 example.com → None", decode_ip_literal("example.com") is None)
    check("空串 → None", decode_ip_literal("") is None)


def test_validate_url_raises_and_passes():
    print("\n[SSRF] validate_url 行为")
    for bad in ["http://169.254.169.254", "http://2852039166", "file:///etc/passwd"]:
        try:
            validate_url(bad)
            check(f"抛错 {bad}", False, "未抛 ValueError")
        except ValueError:
            check(f"抛错 {bad}", True)
    check("放行 localhost 且去尾斜杠", validate_url("http://localhost:11434/") == "http://localhost:11434")
    check("放行 example.com", validate_url("https://example.com") == "https://example.com")


_TESTS = [test_initial_url, test_redirect_target, test_decode_ip_literal, test_validate_url_raises_and_passes]

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
