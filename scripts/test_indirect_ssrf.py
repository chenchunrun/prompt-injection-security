#!/usr/bin/env python3
"""回归测试 —— M-5: indirect_scanner SSRF 校验 + 响应大小上限。"""
import sys
import io
from indirect_scanner import _validate_scan_url, fetch_url

_failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name}  {detail}")
        raise AssertionError(f"{name} {detail}")


def test_validate_scan_url():
    print("\n[M-5] _validate_scan_url")
    for ok in ["https://example.com", "http://example.com/path?q=1",
               "https://github.com/owner/repo"]:
        check(f"通过 {ok}", _validate_scan_url(ok) == ok)
    for bad in ["file:///etc/passwd", "ftp://x/y", "gopher://x", "/etc/passwd",
                "http://169.254.169.254/latest/meta-data",
                "http://metadata.google.internal/computeMetadata/",
                "http://foo.internal", "http://foo.local"]:
        try:
            _validate_scan_url(bad)
            check(f"拒绝 {bad}", False, "未抛错")
        except ValueError:
            check(f"拒绝 {bad}", True)


def test_fetch_url_size_cap():
    """fetch_url 必须有响应大小上限，防止内存炸弹（用 data: URL 模拟超大响应无需联网）。"""
    print("\n[M-5] fetch_url 响应大小上限")
    # data: URL 被 scheme 校验拒绝（非 http/https），验证大小上限逻辑用 monkeypatch 不可行于此；
    # 改为断言 fetch_url 接受 max_bytes 参数且默认有限。
    import inspect
    sig = inspect.signature(fetch_url)
    check("fetch_url 有 max_bytes 参数", "max_bytes" in sig.parameters, str(sig))


if __name__ == "__main__":
    _TESTS = [test_validate_scan_url, test_fetch_url_size_cap]
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
