
package com.oopnv.vulnscanner;

/**
 * CVE 数据源配置。每个源实现自动顺序切换，一个挂掉自动换下一个。
 */
public enum CveSource {

    /** NVD 官方 API 2.0（美国，慢但权威） */
    NVD(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "NVD 官方",
        false  // 国外
    ),

    /** CVE.org / MITRE API（格式与 NVD 一致，共用解析器） */
    CVEORG(
        "https://cveawg.mitre.org/api/cves/2.0",
        "CVE.org (MITRE)",
        false  // 国外
    ),

    /** NVD 的 EU 镜像（欧洲，有时比美国直连更快） */
    NVD_MIRROR(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "NVD 镜像（直连）",
        false
    );

    private final String baseUrl;
    private final String displayName;
    private final boolean domestic; // 是否国内镜像（目前无可用国内 API 镜像）

    CveSource(String baseUrl, String displayName, boolean domestic) {
        this.baseUrl = baseUrl;
        this.displayName = displayName;
        this.domestic = domestic;
    }

    public String getBaseUrl() { return baseUrl; }
    public String getDisplayName() { return displayName; }
    public boolean isDomestic() { return domestic; }

    /**
     * 返回按优先级排序的所有可用源。
     * 国内镜像优先（目前无），国外源按稳定性和速度排序。
     */
    public static CveSource[] getPrioritizedSources() {
        return values(); // [NVD, CVEORG, NVD_MIRROR]
    }
}
