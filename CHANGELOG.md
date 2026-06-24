# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) semantics. Versions track `SKILL.md`.

## [5.5.0] — 2026-06

代码审查后的安全加固与正确性修复轮次。

### Security
- **SSRF 加固（新增 `netsec.py`）**：`_validate_base_url`/`_validate_scan_url` 收敛到统一原语。云元数据黑名单扩展（AWS ECS `169.254.170.2`、Azure、Alibaba `100.100.100.200` 等）；**解码十进制/十六进制编码 IP** 后再判（堵 `http://2852039166`、`http://0xa9fea9fe` 等字面量绕过）。
- **重定向 SSRF 拦截**：`_openai`/`_anthropic`/`fetch_url`/`make_openai_judge` 改用 `safe_urlopen`，自定义 `HTTPRedirectHandler` 对每个重定向目标重做内网/元数据校验——外部 API 302 到 `169.254.169.254` 不再被跟随。
- **`make_openai_judge` SSRF 校验**：此前 judge 通道对 `base_url` 零校验、且 `urlopen` 跟随重定向；现已加 `validate_url` + `safe_urlopen` + 响应形状守卫。
- **`audit_system_prompt.py` 去第三方依赖 + SSRF**：`requests` 换回纯标准库 `urllib`，并对 `--api` 做校验；裸 `except:` 收窄为 `except Exception:`。
- **机密脱敏**：canary（尤其 `--secret-canary` 的真实值）在 report/stdout 中改为 `sha256:` 前缀哈希，不再明文落盘或随报告外泄。运行时检测仍用内存真值。
- **userinfo 剥离**：`_validate_base_url` 去掉 URL 中的 `user:password@`，避免凭据写进 report/stdout。

### Changed
- **H1 canary 拒绝引用降级**：模型在**拒绝语境**中念出 canary（如 "I cannot reveal CANARY-…"）由 CRITICAL 降为 **MEDIUM**（部分泄露），与标记词 L1 的拒绝感知保持一致；顺从吐出 / 纯 canary 串仍为 CRITICAL。避免"更安全的拒绝行为被判得比顺从泄露还重"。

### Fixed
- **C3 多轮攻击错误污染**：多轮用例某轮返回 `[ERR:…]` 时立即中止，不再把错误串当 assistant 喂回下一轮掩盖真实失败。
- **C4 RNG 双初始化 + 续跑告警**：种子生成改为单次构造；`--resume` + `adaptive` 同用时打 stderr 提示（续跑结果有效但不可与同 seed 全新运行逐例对比）。
- **响应形状守卫**：`_ollama`/`_openai`/`_anthropic` 对空 `choices`/`content`/`message.content`（内容过滤、工具边界截断等）显式报错而非 IndexError；`call_api` 区分"网络错误 / 解析错误 / 其他"，均不再静默吞掉。
- **错误日志化**：L3 judge、`_dump_partial`、`call_api` 的裸/宽 `except` 不再静默——失败打 stderr，让坏掉的 judge/磁盘满等可见。
- `classify_severity` 的 `"密钥" in r`（未小写）不一致修正为 `r_low`。

### Added
- `scripts/netsec.py`（共享 SSRF 原语：URL 校验 / 编码 IP 解码 / 重定向拦截 opener）。
- `scripts/test_netsec.py`（编码 IP 元数据绕过、重定向内网拦截、解码原语回归）。

### Refactor (H4/H5)
- **H5 模块拆分**：`test_llm.py` 从 909 行降到 559 行——抽出 `cases.py`（TARGET_CASES 语料 + `list_targets`，246 行纯数据）、`providers.py`（Ollama/OpenAI/Anthropic 网络层 + SSRF + 重试，176 行）。`test_llm` 仅保留编排（run_case / run_all / aggregate / run_multi / report / main）。
- **H4 判定原语集中**：安全拒绝关键词（原 `analyze()` 内联 `safe_kw`）改为引用 `judge.is_safe_refusal`；API 密钥正则集中为 `judge.API_KEY_PATTERN`（`COMPLIANCE_PATTERNS` 与 `api_key_leak` 检测器共用），消除两套关键词漂移。`judge` 提升为无条件核心导入。
- 公共接口保持：`from test_llm import _validate_base_url / _redacted_err / aggregate_reports` 仍可用（经 providers 再导出）。

### Known limitations / TODO
- 主机名经 DNS 解析后判定重定向目标，存在理论 TOCTOU/DNS-rebinding 窗口（IP 字面量判定无此问题）。
- 初始 URL 仍允许 localhost/私网（本地/内网模型是本工具主用例）；仅对重定向目标施加内网拦截。

### License
- **MIT → AGPL-3.0**：因 `references/full-patterns.md`（含逐字厂商提示词摘录）与 `scripts/cases.py`（CL4R1T4S 签名攻击）衍生自 CL4R1T4S（AGPL-3.0），仓库整体改用 AGPL-3.0 以合规。`LICENSE` 替换为规范 AGPL-3.0 文本，`pyproject.toml` classifier 与 README badge/许可证段同步。

### Docs
- 修正描述文件与代码不一致：文件结构补 `cases.py`/`providers.py`/`netsec.py`/`test_netsec.py`/`test_indirect_ssrf.py`，`test_llm.py` 描述改为「主入口 + 编排」；用例数与 `cases.py` 对齐（合计 **104** 标准用例，chatbot+P3=63）；SKILL.md 补 v5.5 变更块；README badge `65→104`、`68 份→数十份`、补 5.3/5.4/5.5 版本史。

## [5.4.0] — 2026-06

### Added
- **C2 非破坏式打包**：`pyproject.toml`（PEP 621 元数据 + entry points `pis-test`/`pis-compare`）+ `scripts/__init__.py`。支持 `pip install -e .`，同时保留 `cd scripts && python` 的脚本/skill 调用方式。CI 新增 `packaging` job 验证安装。
- **M-5 indirect_scanner SSRF 加固**：`_validate_scan_url` 校验 scheme（仅 http/https）+ 阻断云元数据/内网地址；`fetch_url` 增加响应大小上限（5MB）防内存炸弹。
- **#3 严重度分级 + 加权风险分**：每个漏洞按 CRITICAL/HIGH/MEDIUM/LOW 分级；风险评分改为严重度加权，不再只看 RED 比例。报告新增「严重度」汇总行。
- **#4 canary 机密泄露检测**：`--canary` / `--secret-canary` 把唯一机密串注入系统提示，模型吐出即判 CRITICAL。修复 Anthropic 通道丢弃 system 提示的 bug。
- **#5 报告对比器** `compare.py`：总览表 + 逐层矩阵 + 用例翻转 + `--json`。
- **#6 多种子聚合 + 流式进度 + 断点续跑**：`--seeds`/`--runs` 聚合 mean±方差；`--progress` stderr 进度；`--resume` + `-o` 增量落盘。
- **C1 `--temperature`（默认 0.0）** + `--max-tokens`：被测模型输出现在可复现（seed 复现输入编排，temperature=0 复现输出）。
- **H4 `--retries`/`--backoff`**：对 429/5xx/网络错误指数退避重试。
- **C3 `SECURITY.md`** + README/CLI 授权使用声明（dual-use 负责任发布）。

### Security (开源发布加固)
- **H2** `call_api` 异常脱敏，避免凭据/header 片段写进报告文件。
- **H3** `--base-url` scheme 校验（仅 http/https，拒绝 `file://` 与云元数据/内网地址）。
- **H5** `get_models` 裸 `except:` 收窄为 `(ValueError, OSError)` 并打 stderr 告警。
- **canary 熵**：后缀 `k=4` → `k=8`（~92 万 → ~8.5e11 组合），降低碰撞假阳性。
- **LLM judge JSON 解析**：正则提取替代 `split("\n")`，修单行 markdown 围栏的 IndexError。
- **.gitignore**：忽略 `report*.json` / `*.tmp` / `__pycache__` / `.env`。

### Changed
- 标记词池改为仅零频次词（#1，v5.3），删除所有自然词典词。
- L1 新增解释性提及降级（#2，v5.3）。
- README 删除误导性的 `pip install requests`（实际纯标准库）。
- 样本报告 `report*.json` 移至 `examples/`。
- 测试改为 pytest 可收集（`check()` 失败即 raise），保留脚本自跑；5 个测试文件 + `test_indirect_ssrf.py`。
- 清理死导入 `import itertools`、`import json as _json` 别名、`analyze` docstring 规范化。

### Breaking
- 池结构变化导致旧种子的 seed→marker 映射失效（v5.3 起）。
- 被测模型默认温度从 0.7 改为 0.0（影响历史复现，但使输出可复现）。

### Known limitations / TODO
- `pyproject.toml` 的 `[project.urls]`（Homepage 等）暂未填，创建 GitHub 仓库后可补真实 URL。
- SKILL.md 实测数据表中的部分模型名（`DeepSeek V4 Pro` / `Qwen3.5-122B-A10B`）待核实真实 `model:tag`。
