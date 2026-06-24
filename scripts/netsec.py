#!/usr/bin/env python3
"""网络安全原语：SSRF 防护（URL 校验 + 拦截内网重定向的 opener）。

设计要点（威胁模型）：
- 本工具的主用例就是测试**本地或内网**模型（Ollama@localhost、家庭/办公网内的部署），
  故**初始 URL（用户显式指定）只拦截云元数据端点**（无任何合法用途），允许 localhost/私网。
- 真正的 SSRF 绕过在于**重定向**：一个外部 API 不应把请求重定向到内网/元数据地址。
  故**重定向目标**拦截全部私网/环回/链路本地/元数据地址。
- 对**编码 IP**（十进制 `2852039166`、十六进制 `0x7f000001` 等）做归一化后再判，堵住字面量绕过。

已知局限（防御纵深，非绝对）：
- 主机名经 DNS 解析后判定，存在 TOCTOU/DNS-rebinding 理论窗口；IP 字面量判定无此问题。
- 解析失败的主机名（重定向目标）默认放行，避免误伤瞬时 DNS 故障下的合法重定向。
"""
import ipaddress
import socket
import urllib.parse
import urllib.request
import urllib.error

# 云元数据端点（各大云厂商）——任何情况下都拒绝
METADATA_HOSTS = {
    "169.254.169.254",   # AWS / GCP / Azure IMDS
    "169.254.170.2",     # AWS ECS task metadata
    "169.254.169.253",   # Azure wire server
    "metadata.google.internal",
    "metadata.azure.com",
    "100.100.100.200",   # Alibaba Cloud
}
# 视为元数据风险的域名后缀
METADATA_SUFFIXES = (".internal", ".local", ".compute.internal")
# 重定向目标需拒绝的内网段（IPv4）
_INTERNAL_V4_NETS = [
    ipaddress.ip_network(n) for n in
    ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
     "169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10")
]
_INTERNAL_V6_NETS = [
    ipaddress.ip_network(n) for n in ("::1/128", "fc00::/7", "fe80::/10")
]


def decode_ip_literal(host: str):
    """把 IPv4 字面量（含十进制/十六进制编码）归一化为 IPv4Address；非 IP 字面量返回 None。"""
    if not host:
        return None
    # 直接是 IP（v4/v6）
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # 纯十进制整数编码（如 2852039166 = 169.254.169.254）
    if host.isdigit() and not host.startswith("0"):
        try:
            n = int(host)
            if 0 < n <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(n)
        except (ValueError, ipaddress.AddressValueError):
            pass
    # 十六进制 0x... 编码（如 0x7f000001 = 127.0.0.1）
    if host.lower().startswith("0x"):
        try:
            return ipaddress.IPv4Address(int(host[2:], 16))
        except (ValueError, ipaddress.AddressValueError):
            pass
    return None


def _is_metadata(host: str) -> bool:
    """主机/IP 是否为云元数据端点（含编码 IP 归一化后判定）。"""
    h = (host or "").lower()
    if h in METADATA_HOSTS or any(h.endswith(s) for s in METADATA_SUFFIXES):
        return True
    ip = decode_ip_literal(h)
    if ip is not None:
        s = str(ip)
        if s in METADATA_HOSTS:
            return True
        # 169.254.0.0/16 链路本地段整体视为元数据风险
        if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("169.254.0.0/16"):
            return True
    return False


def _is_internal(ip) -> bool:
    """IP 是否属内网/环回/链路本地/ULA（用于重定向拦截）。"""
    nets = _INTERNAL_V4_NETS if isinstance(ip, ipaddress.IPv4Address) else _INTERNAL_V6_NETS
    return any(ip in net for net in nets)


def _resolve_all(host: str):
    """解析主机名为 IP 列表；失败返回空列表。"""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    ips = []
    for _fam, _ty, _pro, _cn, sa in infos:
        try:
            ips.append(ipaddress.ip_address(sa[0]))
        except (ValueError, OSError):
            continue
    return ips


def is_safe_initial_url(url: str) -> bool:
    """初始 URL 校验：scheme 限 http/https，且非云元数据端点（允许 localhost/私网）。"""
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").lower()
    if _is_metadata(host):
        return False
    return True


def is_safe_redirect_target(url: str) -> bool:
    """重定向目标校验：拒绝所有内网/环回/链路本地/元数据地址。

    外部 API 不应把请求重定向到内网；命中即视为 SSRF 信号。
    """
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").lower()
    if _is_metadata(host):
        return False
    # 直接 IP 字面量（含编码）→ 直接判定
    ip = decode_ip_literal(host)
    if ip is not None:
        return not _is_internal(ip)
    # 主机名 → 解析后逐 IP 判定；任一解析到内网/元数据即拒绝
    for r in _resolve_all(host):
        if _is_internal(r):
            return False
    return True


def validate_url(url: str, *, redirect: bool = False) -> str:
    """校验 URL；redirect=True 用更严格的重定向规则。返回去尾斜杠的 url，非法抛 ValueError。"""
    ok = is_safe_redirect_target(url) if redirect else is_safe_initial_url(url)
    if not ok:
        kind = "重定向目标" if redirect else "URL"
        raise ValueError(f"{kind} 指向被拦截的地址（云元数据/内网），已拒绝")
    return url.rstrip("/")


class _ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """重定向时对每个 Location 重新做 SSRF 校验；非法则中止（抛 HTTPError）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_safe_redirect_target(newurl):
            raise urllib.error.HTTPError(
                newurl, code, "blocked redirect to internal/metadata host", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_safe_opener() -> urllib.request.OpenerDirector:
    """构造一个拦截内网/元数据重定向的 opener。"""
    return urllib.request.build_opener(_ValidatingRedirectHandler)


def safe_urlopen(req, timeout=None):
    """用安全 opener 打开请求（拦截内网重定向）。"""
    opener = build_safe_opener()
    return opener.open(req, timeout=timeout) if timeout is not None else opener.open(req)
