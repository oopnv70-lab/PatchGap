package com.oopnv.vulnscanner;

import android.os.Build;

/**
 * 从设备属性读取安全补丁级别等信息。
 * 参考 AOSP: https://source.android.com/docs/security/bulletin
 */
public class DeviceInfo {

    public final String model;
    public final String manufacturer;
    public final String androidVersion;
    public final String patchLevel;       // e.g. "2025-03-05"
    public final String kernelVersion;
    public final String buildFingerprint;

    private DeviceInfo(String model, String manufacturer, String androidVersion,
                       String patchLevel, String kernelVersion, String buildFingerprint) {
        this.model = model;
        this.manufacturer = manufacturer;
        this.androidVersion = androidVersion;
        this.patchLevel = patchLevel;
        this.kernelVersion = kernelVersion;
        this.buildFingerprint = buildFingerprint;
    }

    /**
     * 从系统属性提取所有设备信息。
     * VMRuntime.getRuntime().vmLibrary() 等底层接口不在本次使用，
     * 全部从 android.os.Build 反射获取。
     */
    public static DeviceInfo collect() {
        String model = Build.MODEL;
        String manufacturer = Build.MANUFACTURER;
        String version = Build.VERSION.RELEASE;
        String sdk = String.valueOf(Build.VERSION.SDK_INT);

        // android.os.Build.VERSION.SECURITY_PATCH 返回 e.g. "2025-03-05"
        String patchLevel = Build.VERSION.SECURITY_PATCH;

        // 内核版本通过 /proc/version 获取（避免反射隐藏 API）
        String kernel = readKernelVersion();

        String fingerprint = Build.FINGERPRINT;

        return new DeviceInfo(
                model != null ? model : "unknown",
                manufacturer != null ? manufacturer : "unknown",
                "Android " + version + " (API " + sdk + ")",
                patchLevel != null ? patchLevel : "unknown",
                kernel,
                fingerprint
        );
    }

    private static String readKernelVersion() {
        try {
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(
                            new java.io.FileInputStream("/proc/version")));
            String line = br.readLine();
            br.close();
            return line != null ? line.trim() : "unknown";
        } catch (Exception e) {
            return "unavailable";
        }
    }

    public String toDisplayString() {
        return "制造商: " + manufacturer + "\n"
                + "型号: " + model + "\n"
                + "系统版本: " + androidVersion + "\n"
                + "安全补丁级别: " + patchLevel + "\n"
                + "内核: " + kernelVersion + "\n"
                + "构建指纹: " + buildFingerprint;
    }

    /**
     * 将补丁级别（如 "2025-03-05"）转为 epoch 毫秒，用于与 CVE 发布日期比较。
     */
    public long patchLevelEpochMillis() {
        try {
            String[] parts = patchLevel.split("-");
            if (parts.length >= 2) {
                int year = Integer.parseInt(parts[0]);
                int month = Integer.parseInt(parts[1]);
                int day = parts.length >= 3 ? Integer.parseInt(parts[2]) : 1;
                java.util.Calendar cal = java.util.Calendar.getInstance(
                        java.util.TimeZone.getTimeZone("UTC"));
                cal.set(year, month - 1, day, 0, 0, 0);
                cal.set(java.util.Calendar.MILLISECOND, 0);
                return cal.getTimeInMillis();
            }
        } catch (Exception ignored) { }
        return 0;
    }
}
