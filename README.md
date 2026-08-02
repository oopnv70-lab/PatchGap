# VulnScanner

Android 漏洞扫描器 —— 自动通过 NVD 数据库查询设备安全补丁级别之后的已知漏洞，对比并显示未修补漏洞列表。

## 功能

- 🔍 **自动读取**设备型号、Android 版本、安全补丁级别
- 📡 **在线查询** NVD (National Vulnerability Database) API，获取补丁日期之后的所有 Android 相关 CVE
- 📊 **对比展示**漏洞数量、严重度、CVSS 分数、落后天数
- 🌗 Material 3 设计，支持浅色/深色主题

## 构建

```bash
./gradlew assembleDebug
```

或通过 GitHub Actions 自动构建（push 后触发）。

## 技术栈

- Java 21 + AGP 9.3
- OkHttp + Gson
- NVD API 2.0 (无需认证)
- Material 3

## 许可

MIT License
