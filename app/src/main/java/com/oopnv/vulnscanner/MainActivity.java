package com.oopnv.vulnscanner;

import android.os.Bundle;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import java.util.Calendar;
import java.util.TimeZone;

public class MainActivity extends AppCompatActivity {

    private TextView tvDeviceInfo;
    private TextView tvVulnCount;
    private TextView tvPatchLevel;
    private TextView tvDaysBehind;
    private TextView tvEmpty;
    private ProgressBar progressBar;
    private RecyclerView rvVulns;
    private CveAdapter adapter;
    private NvdClient nvdClient;
    private DeviceInfo deviceInfo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvDeviceInfo = findViewById(R.id.tvDeviceInfo);
        tvVulnCount = findViewById(R.id.tvVulnCount);
        tvPatchLevel = findViewById(R.id.tvPatchLevel);
        tvDaysBehind = findViewById(R.id.tvDaysBehind);
        tvEmpty = findViewById(R.id.tvEmpty);
        progressBar = findViewById(R.id.progressBar);
        rvVulns = findViewById(R.id.rvVulns);

        adapter = new CveAdapter();
        rvVulns.setLayoutManager(new LinearLayoutManager(this));
        rvVulns.setAdapter(adapter);

        nvdClient = new NvdClient();

        // 加载设备信息
        deviceInfo = DeviceInfo.collect();
        tvDeviceInfo.setText(deviceInfo.toDisplayString());
        tvPatchLevel.setText(deviceInfo.patchLevel);

        // 计算并显示补丁落后天数
        updateDaysBehind();

        findViewById(R.id.btnScan).setOnClickListener(v -> startScan());
    }

    private void updateDaysBehind() {
        long patchEpoch = deviceInfo.patchLevelEpochMillis();
        if (patchEpoch <= 0) {
            tvDaysBehind.setText("?");
            return;
        }
        long now = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis();
        long days = (now - patchEpoch) / (1000 * 60 * 60 * 24);
        tvDaysBehind.setText(String.valueOf(Math.max(0, days)));
    }

    private void startScan() {
        setLoading(true);
        tvEmpty.setVisibility(View.GONE);
        rvVulns.setVisibility(View.GONE);

        nvdClient.fetchCvesSince(deviceInfo.patchLevel, new NvdClient.Callback() {
            @Override
            public void onSuccess(java.util.List<CveItem> cveList, String sourceName) {
                runOnUiThread(() -> {
                    setLoading(false);
                    // 在统计卡片上显示数据来源
                    tvPatchLevel.setText(deviceInfo.patchLevel + " (来源: " + sourceName + ")");
                    if (cveList == null || cveList.isEmpty()) {
                        tvEmpty.setVisibility(View.VISIBLE);
                        tvEmpty.setText(R.string.no_vulns);
                        tvVulnCount.setText("0");
                    } else {
                        tvEmpty.setVisibility(View.GONE);
                        rvVulns.setVisibility(View.VISIBLE);
                        adapter.setItems(cveList);
                        tvVulnCount.setText(String.valueOf(cveList.size()));
                    }
                });
            }

            @Override
            public void onError(String errorMessage) {
                runOnUiThread(() -> {
                    setLoading(false);
                    Toast.makeText(MainActivity.this, errorMessage, Toast.LENGTH_LONG).show();
                    tvEmpty.setVisibility(View.VISIBLE);
                    tvEmpty.setText("查询失败\n" + errorMessage);
                });
            }
        });
    }

    private void setLoading(boolean loading) {
        progressBar.setVisibility(loading ? View.VISIBLE : View.GONE);
        findViewById(R.id.btnScan).setEnabled(!loading);
    }
}
