# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) semantics. Versions track `SKILL.md`.

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
