#!/usr/bin/env python3
"""Provider 网络层 —— Ollama / OpenAI 兼容 / Anthropic 调用 + SSRF 防护 + 重试。

从 test_llm.py 抽离（H5 模块拆分）。所有出站 HTTP 经 netsec.safe_urlopen（拦截内网/元数据重定向），
base_url 经 _validate_base_url 校验（限 http/https、拒云元数据含编码 IP 绕过、剥离 userinfo）。
"""
import json
import sys
import time
import hashlib
import urllib.request
import urllib.error

from netsec import validate_url as _netsec_validate_url, safe_urlopen as _safe_urlopen


# ─── 提供商 ───
PROVIDERS = {
    "ollama":    {"label":"Ollama (本地)","default_url":"http://localhost:11434","path":"/api/chat","needs_key":False},
    "openai":    {"label":"OpenAI 兼容","default_url":"https://api.openai.com/v1","path":"/chat/completions","needs_key":True},
    "anthropic": {"label":"Anthropic","default_url":"https://api.anthropic.com/v1","path":"/messages","needs_key":True},
}

# ─── 网络层默认值（C1 可复现性 / H4 重试） ───
DEFAULT_TEMPERATURE = 0.0   # seed 复现输入编排；temperature=0 复现模型输出（推理模型可改 --temperature 0.01）
DEFAULT_MAX_TOKENS = 4096
RETRYABLE_STATUS = {429, 500, 502, 503, 504}  # 这些状态码触发指数退避重试


class _TransientStatus(Exception):
    """provider 内部抛出：HTTP 非 200，.code 为状态码，供 call_api 决定是否重试。"""
    def __init__(self, code):
        super().__init__(f"HTTP {code}")
        self.code = code


def _validate_base_url(base_url):
    """SSRF 防护：委托 netsec —— 限 http/https、拒绝云元数据端点（含十进制/十六进制编码 IP 绕过）。
    初始 URL 允许 localhost/私网（本地/内网模型是本工具主用例）；重定向拦截见 netsec.safe_urlopen。
    顺带剥离 userinfo，避免凭据写进 report/stdout。"""
    from urllib.parse import urlparse, urlunparse
    validated = _netsec_validate_url(base_url)  # 非法抛 ValueError
    p = urlparse(validated)
    if p.username or p.password:
        netloc = p.hostname + (f":{p.port}" if p.port else "")
        validated = urlunparse(p._replace(netloc=netloc))
    return validated


def _redacted_err(label):
    """统一脱敏错误串：避免异常文本（可能含凭据/header）被写进 report。"""
    return f"[ERR: {label} (details redacted)]"


def _hash_secret(secret):
    """在 report/stdout 中以哈希引用机密（如 --secret-canary 的真实值、canary），
    避免明文落盘或随报告外泄。运行时检测仍用内存中的真实值。"""
    if not secret:
        return None
    return "sha256:" + hashlib.sha256(str(secret).encode()).hexdigest()[:12]


def call_api(provider, model, messages, api_key, base_url, timeout=60,
             temperature=DEFAULT_TEMPERATURE, max_tokens=DEFAULT_MAX_TOKENS,
             retries=0, backoff=1.0):
    if not base_url:
        base_url = PROVIDERS[provider]["default_url"]
    try:
        base_url = _validate_base_url(base_url)
    except ValueError as e:
        return f"[ERR: {e}]"
    for attempt in range(retries + 1):
        try:
            if provider == "ollama":
                return _ollama(model, messages, base_url, timeout, temperature)
            elif provider == "openai":
                return _openai(model, messages, api_key, base_url, timeout, temperature, max_tokens)
            elif provider == "anthropic":
                return _anthropic(model, messages, api_key, base_url, timeout, temperature, max_tokens)
            return _redacted_err("unknown provider")
        except (urllib.error.HTTPError, _TransientStatus) as e:
            code = getattr(e, "code", None)
            if code in RETRYABLE_STATUS and attempt < retries:
                time.sleep(backoff * (2 ** attempt)); continue
            return _redacted_err(f"HTTP {code}" if code else "http error")
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
            if attempt < retries:
                time.sleep(backoff * (2 ** attempt)); continue
            return _redacted_err("network error")
        except (ValueError, KeyError, IndexError, TypeError) as e:
            # 响应解析错误（空 choices/content、字段缺失等）——与网络错误区分，便于排障
            print(f"[call_api] 响应解析失败: {e}", file=sys.stderr)
            return _redacted_err("malformed response")
        except Exception as e:
            print(f"[call_api] 请求异常: {type(e).__name__}: {e}", file=sys.stderr)
            return _redacted_err("request failed")
    return _redacted_err(f"failed after {retries + 1} attempts")


def _ollama(model, msgs, url, timeout, temperature=DEFAULT_TEMPERATURE):
    """调用 Ollama API。用 http.client 直连以绕过系统代理。temperature 默认 0 保证可复现。"""
    import http.client, urllib.parse
    parsed = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 11434, timeout=timeout)
    d = json.dumps({"model": model, "messages": msgs, "stream": False,
                     "options": {"temperature": temperature}}).encode()
    conn.request("POST", "/api/chat", body=d, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    body = resp.read()
    if resp.status != 200:
        raise _TransientStatus(resp.status)
    data = json.loads(body)
    msg = data.get("message") or {}
    content = msg.get("content")
    if content is None:
        raise ValueError("ollama 响应无 message.content")
    return content


def _openai(model, msgs, key, url, timeout, temperature=DEFAULT_TEMPERATURE, max_tokens=DEFAULT_MAX_TOKENS):
    d = json.dumps({"model": model, "messages": msgs, "stream": False,
                    "temperature": temperature, "max_tokens": max_tokens}).encode()
    # safe_urlopen 拦截重定向到内网/元数据（SSRF 防护）
    r = _safe_urlopen(urllib.request.Request(
        f"{url}/chat/completions", data=d,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"}), timeout=timeout)
    with r:
        data = json.loads(r.read())
    choices = data.get("choices") or []
    if not choices:
        raise ValueError("openai 响应无 choices（可能被内容过滤）")
    msg = choices[0].get("message") or {}
    content = msg.get("content") or ""
    # 推理模型兼容：如果 content 为空但有 reasoning_content，使用 reasoning_content
    if not content and msg.get("reasoning_content"):
        content = msg["reasoning_content"]
    return content


def _anthropic(model, msgs, key, url, timeout, temperature=DEFAULT_TEMPERATURE, max_tokens=DEFAULT_MAX_TOKENS):
    # Anthropic 用顶层 system 字段传系统提示（#4 canary 注入依赖此）
    system_text = "\n\n".join(m["content"] for m in msgs if m["role"] == "system")
    msgs2 = [{"role": m["role"], "content": m["content"]} for m in msgs if m["role"] != "system"]
    body = {"model": model, "messages": msgs2 or [{"role": "user", "content": "Hello"}],
            "max_tokens": max_tokens, "temperature": temperature}
    if system_text:
        body["system"] = system_text
    d = json.dumps(body).encode()
    r = _safe_urlopen(urllib.request.Request(
        f"{url}/messages", data=d,
        headers={"Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"}), timeout=timeout)
    with r:
        data = json.loads(r.read())
    blocks = data.get("content") or []
    if not blocks:
        raise ValueError("anthropic 响应无 content")
    texts = [b.get("text", "") for b in blocks
             if isinstance(b, dict) and b.get("type") == "text" and b.get("text")]
    if not texts:
        raise ValueError("anthropic 响应无 text 内容块")
    return texts[0]


def get_models(provider, base_url):
    if provider != "ollama":
        return []
    try:
        base_url = _validate_base_url(base_url or PROVIDERS[provider]["default_url"])
        import http.client, urllib.parse
        parsed = urllib.parse.urlparse(base_url)
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 11434, timeout=10)
        conn.request("GET", "/api/tags")
        return [m["name"] for m in json.loads(conn.getresponse().read()).get("models", [])]
    except (ValueError, OSError) as e:
        print(f"[get_models] {e}", file=sys.stderr)
        return []
