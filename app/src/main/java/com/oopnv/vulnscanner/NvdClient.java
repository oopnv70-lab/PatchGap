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
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * 多源 CVE 查询客户端。
 * 支持 NVD 2.0、CVE.org（MITRE）两个数据源，
 * 按优先级自动切换：一个源挂了或返回错误，自动尝试下一个。
 * 
 * 所有源统一使用 NVD_CVE 格式，共用一个 JSON 解析器。
 * 无认证免费使用，速率限制：NVD 无 key 时每 6 秒 1 次。
 */
public class NvdClient {

    // 统一速率限制（针对 NVD 官方源；MITRE 源相对宽松但共用此限制）
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
     * 多源顺序自动切换：NVD → CVE.org → 失败报错。
     * 
     * @param patchLevelDateStr  安全补丁级别日期字符串，如 "2025-03-05"
     * @param callback           异步回调（onSuccess/onError 均在主线程外）
     */
    public void fetchCvesSince(String patchLevelDateStr, Callback callback) {
        String pubStartDate = patchLevelDateStr + "T00:00:00.000";
        String now = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS", Locale.US)
                .format(new Date());

        new Thread(() -> {
            CveSource[] sources = CveSource.getPrioritizedSources();
            List<String> errors = new ArrayList<>();

            for (int i = 0; i < sources.length; i++) {
                CveSource source = sources[i];
                boolean isLast = (i == sources.length - 1);

                enforceRateLimit();

                try {
                    String url = source.getBaseUrl()
                            + "?pubStartDate=" + pubStartDate
                            + "&pubEndDate=" + now
                            + "&keywordSearch=Android"
                            + "&resultsPerPage=100";

                    Request request = new Request.Builder()
                            .url(url)
                            .header("User-Agent", "PatchGap/1.0 (Android)")
                            .build();

                    try (Response response = httpClient.newCall(request).execute()) {
                        if (!response.isSuccessful()) {
                            String err = source.getDisplayName() 
                                    + " HTTP " + response.code() + ": " + response.message();
                            errors.add(err);
                            if (!isLast) continue;
                            callback.onError(joinErrors(errors));
                            return;
                        }

                        String body = response.body() != null ? response.body().string() : "";

                        // 检查是否为 JSON 错误（如 NVD 的 error/message 响应）
                        if (body.trim().startsWith("{")) {
                            JsonObject root = gson.fromJson(body, JsonObject.class);
                            if (root.has("error")) {
                                String err = source.getDisplayName() 
                                        + " API错误: " + root.get("message");
                                errors.add(err);
                                if (!isLast) continue;
                                callback.onError(joinErrors(errors));
                                return;
                            }
                        }

                        List<CveItem> results = parseResponse(body);
                        callback.onSuccess(results, source.getDisplayName());
                        return;
                    }
                } catch (IOException e) {
                    String err = source.getDisplayName() + " 网络错误: " + e.getMessage();
                    errors.add(err);
                    if (!isLast) continue;
                    callback.onError(joinErrors(errors));
                }
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

    /** 合并多个错误信息 */
    private String joinErrors(List<String> errors) {
        StringBuilder sb = new StringBuilder("所有数据源均失败:\n");
        for (int i = 0; i < errors.size(); i++) {
            sb.append("  ").append(i + 1).append(". ").append(errors.get(i)).append("\n");
        }
        return sb.toString();
    }

    public interface Callback {
        /** @param cveList   查询结果 */
        /** @param sourceName  成功响应的数据源名称（用于 UI 显示） */
        void onSuccess(List<CveItem> cveList, String sourceName);
        void onError(String errorMessage);
    }
}
