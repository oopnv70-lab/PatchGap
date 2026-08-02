# PatchGap

Android 漏洞扫描器 —— 多源 CVE 查询引擎，读取设备安全补丁级别，自动对比并显示未修补漏洞数量。

## 功能

- 🔍 **自动读取**设备型号、Android 版本、安全补丁级别、内核版本
- 📡 **多源查询** 3 个 CVE 数据源自动切换（一个挂掉自动换下一个）：
  - NVD 官方 API 2.0 (`services.nvd.nist.gov`) — 美国 NIST
  - CVE.org / MITRE API 2.0 (`cveawg.mitre.org`) — CVE 计划官方
- 📊 **对比展示**未修补漏洞数、CVSS 严重度、落后天数、补丁级别
- 🌗 Material 3 设计，支持浅色/深色主题
- ⚡ 自动速率限制（NVD 无 API key 时每 6 秒 1 次）

## 构建

GitHub Actions 自动构建（push main 触发），产出 `PatchGap-debug.apk`。

## 技术栈

- Java 21 + AGP 9.3 + Gradle 9.6.1
- OkHttp 4.12 + Gson 2.11
- NVD / CVE.org API 2.0（均免费、无需认证）
- Material 3

## 许可

GPL-3.0
