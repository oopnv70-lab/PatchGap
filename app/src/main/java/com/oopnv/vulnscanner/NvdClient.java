package com.oopnv.vulnscanner;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * NVD (National Vulnerability Database) API 2.0 客户端。
 * 无认证免费使用，速率限制：无 API key 时每 6 秒 1 次请求。
 * 文档: https://nvd.nist.gov/developers/vulnerabilities
 */
public class NvdClient {

    private static final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    // 不带 API key 的严格速率限制（6 秒间隔）
    private static final long REQUEST_DELAY_MS = 6_500;

    private final OkHttpClient httpClient;
    private final Gson gson;
    private long lastRequestTime = 0;

    public NvdClient() {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build();
        this.gson = new Gson();
    }

    /**
     * 查询指定补丁日期之后发布的所有 Android 相关 CVE。
     * @param patchLevelDateStr  安全补丁级别日期字符串，如 "2025-03-05"
     * @param callback           异步回调
     */
    public void fetchCvesSince(String patchLevelDateStr, Callback callback) {
        // 构建 NVD API 请求参数：
        //   - pubStartDate: 补丁日期次日（补丁日期之后的漏洞）
        //   - keywordSearch: "Android" 关键字过滤
        //   - resultsPerPage: 最多 100 条/页
        String pubStartDate = patchLevelDateStr + "T00:00:00.000";
        String now = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS", Locale.US)
                .format(new Date());

        String url = BASE_URL
                + "?pubStartDate=" + pubStartDate
                + "&pubEndDate=" + now
                + "&keywordSearch=Android"
                + "&resultsPerPage=100";

        // 速率限制
        enforceRateLimit();

        new Thread(() -> {
            try {
                Request request = new Request.Builder()
                        .url(url)
                        .header("User-Agent", "VulnScanner/1.0 (Android)")
                        .build();

                try (Response response = httpClient.newCall(request).execute()) {
                    if (!response.isSuccessful()) {
                        callback.onError("HTTP " + response.code() + ": " + response.message());
                        return;
                    }

                    String body = response.body() != null ? response.body().string() : "";
                    List<CveItem> results = parseResponse(body);
                    callback.onSuccess(results);
                }
            } catch (IOException e) {
                callback.onError("网络错误: " + e.getMessage());
            }
        }).start();
    }

    private List<CveItem> parseResponse(String json) {
        List<CveItem> list = new ArrayList<>();
        try {
            JsonObject root = gson.fromJson(json, JsonObject.class);
            JsonArray vulnerabilities = root.getAsJsonArray("vulnerabilities");
            if (vulnerabilities == null) return list;

            for (JsonElement elem : vulnerabilities) {
                JsonObject cveObj = elem.getAsJsonObject().getAsJsonObject("cve");
                if (cveObj == null) continue;

                String cveId = getString(cveObj, "id");

                // 描述
                JsonArray descriptions = cveObj.getAsJsonArray("descriptions");
                String description = "";
                if (descriptions != null) {
                    for (JsonElement descElem : descriptions) {
                        JsonObject descObj = descElem.getAsJsonObject();
                        if ("en".equals(getString(descObj, "lang"))) {
                            description = getString(descObj, "value");
                            break;
                        }
                    }
                }

                // 发布日期
                String published = getString(cveObj, "published");

                // CVSS v3 分数
                double cvssScore = -1;
                String severity = "NONE";
                JsonObject metrics = cveObj.getAsJsonObject("metrics");
                if (metrics != null) {
                    JsonArray cvssV31 = metrics.getAsJsonArray("cvssMetricV31");
                    if (cvssV31 == null) cvssV31 = metrics.getAsJsonArray("cvssMetricV30");
                    if (cvssV31 != null && cvssV31.size() > 0) {
                        JsonObject metric = cvssV31.get(0).getAsJsonObject();
                        JsonObject cvssData = metric.getAsJsonObject("cvssData");
                        if (cvssData != null) {
                            cvssScore = cvssData.has("baseScore")
                                    ? cvssData.get("baseScore").getAsDouble() : -1;
                            severity = cvssData.has("baseSeverity")
                                    ? cvssData.get("baseSeverity").getAsString() : "NONE";
                        }
                    }
                }

                CveItem item = new CveItem(cveId, description, cvssScore, severity, published);
                list.add(item);
            }
        } catch (Exception e) {
            // 解析失败不崩溃，返回已解析的部分
        }
        return list;
    }

    private void enforceRateLimit() {
        long now = System.currentTimeMillis();
        long elapsed = now - lastRequestTime;
        if (elapsed < REQUEST_DELAY_MS && lastRequestTime > 0) {
            try {
                Thread.sleep(REQUEST_DELAY_MS - elapsed);
            } catch (InterruptedException ignored) { }
        }
        lastRequestTime = System.currentTimeMillis();
    }

    private String getString(JsonObject obj, String key) {
        JsonElement e = obj.get(key);
        return e != null && !e.isJsonNull() ? e.getAsString() : "";
    }

    public interface Callback {
        void onSuccess(List<CveItem> cveList);
        void onError(String errorMessage);
    }
}
