package com.oopnv.vulnscanner;

/**
 * 单条 CVE 数据模型。
 */
public class CveItem {
    public String cveId;          // e.g. "CVE-2025-12345"
    public String description;    // 英文描述摘要
    public double cvssScore;      // CVSS v3 分数，无数据时 -1
    public String severity;       // CRITICAL / HIGH / MEDIUM / LOW / NONE
    public String publishedDate;  // ISO 8601 e.g. "2025-06-15T12:00:00.000"

    public CveItem(String cveId, String description, double cvssScore,
                   String severity, String publishedDate) {
        this.cveId = cveId;
        this.description = description;
        this.cvssScore = cvssScore;
        this.severity = severity;
        this.publishedDate = publishedDate;
    }

    /** 从 ISO 8601 日期中提取年月日部分，用于排序和比较。 */
    public String datePart() {
        if (publishedDate != null && publishedDate.length() >= 10) {
            return publishedDate.substring(0, 10);
        }
        return publishedDate;
    }

    /** 返回 CVSS 分数格式化字符串。 */
    public String cvssDisplay() {
        if (cvssScore < 0) return "N/A";
        return String.format("%.1f", cvssScore);
    }
}
