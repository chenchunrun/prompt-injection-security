# 合规标准与技术映射

## OWASP LLM Top 10 (2025) 映射

| OWASP ID | 威胁类别 | 覆盖 | 对应防御/检测 |
|----------|----------|------|--------------|
| LLM01 | Prompt Injection | ✅ | test_llm (全部23用例), triage (8条规则), indirect_scanner |
| LLM02 | Insecure Output Handling | ✅ | audit_system_prompt (输出控制检查) |
| LLM03 | Training Data Poisoning | ⚠️ | indirect_scanner (数据源污染检测) |
| LLM04 | Model DoS | ❌ | 超出范围 |
| LLM05 | Supply Chain | ✅ | indirect_scanner (GitHub README 模式) |
| LLM06 | Sensitive Info Disclosure | ✅ | test_llm (系统提取检测), audit (泄露检查) |
| LLM07 | Insecure Plugin Design | ⚠️ | 间接注入覆盖 |
| LLM08 | Excessive Agency | ⚠️ | 行为分析覆盖 |
| LLM09 | Overreliance | ❌ | 超出范围 |
| LLM10 | Model Theft | ❌ | 超出范围 |

## MITRE ATT&CK 技术映射

| ATT&CK ID | 技术名 | 注入类型 | 检测方法 |
|-----------|--------|----------|----------|
| T1059.006 | Python 命令执行 | 直接注入 | triage PI-001, detector |
| T1204.002 | 恶意文件执行 | 间接注入 | indirect_scanner |
| T1190 | 公网应用利用 | 直接注入 | 输入点注入检测 |
| T1552.001 | 文件凭据泄露 | 系统提取 | triage PI-003 |
| T1027 | 混淆信息 | 编码绕过 | triage PI-004, l33t 解码 |
| T1036 | 伪装 | 伪标签注入 | triage PI-005, Sigma 规则4 |
| T1098 | 账户操纵 | 权限提升 | triage PI-006 |
| T1566 | 钓鱼 | 间接注入 | indirect_scanner |

## 合规标准

| 标准 | 相关条款 | 要求 |
|------|----------|------|
| GDPR | Art. 5(1)(f), Art. 32 | 数据安全措施需覆盖 AI 系统输入 |
| PIPL (中国个保法) | 第51条 | 防止个人信息泄露的技术措施 |
| ISO/IEC 27001:2022 | A.5.7 | 威胁情报驱动的安全防护 |
| ISO/IEC 42001:2023 | A.7.2 | AI 系统安全测试要求 |
| NIST AI RMF 1.0 | Manage 4.1 | AI 系统输入验证和过滤 |
| EU AI Act | Art. 15, Art. 55 | 高风险 AI 系统的网络安全要求 |
| PCI DSS 4.0 | Req. 6.2.4 | 公网应用安全测试 |

## IOC 采集指引

| IOC 类型 | 来源 | 格式 | 用途 |
|----------|------|------|------|
| 恶意 Prompt 指纹 | 检测器日志 | SHA256(prompt) | 攻击模式追踪 |
| 注入来源 URL | 间接注入扫描 | URL + domain | 威胁情报关联 |
| 编码 Payload | 检测器输出 | decoded_base64 | 载荷分析 |
| 多语言模式 | 检测器输出 | language + pattern | 跨语言攻击追踪 |
| 伪标签指纹 | triage | tag_format + vendor | 伪造模式追踪 |
| README 注入指纹 | indirect_scanner | repo + payload_hash | 供应链注入追踪 |
