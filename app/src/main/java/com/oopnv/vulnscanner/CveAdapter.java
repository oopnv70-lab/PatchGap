package com.oopnv.vulnscanner;

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.List;

public class CveAdapter extends RecyclerView.Adapter<CveAdapter.ViewHolder> {

    private final List<CveItem> items = new ArrayList<>();

    public void setItems(List<CveItem> newItems) {
        items.clear();
        if (newItems != null) items.addAll(newItems);
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_cve, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        CveItem item = items.get(position);
        holder.tvCveId.setText(item.cveId);
        holder.tvDescription.setText(item.description);
        holder.tvCvss.setText("CVSS: " + item.cvssDisplay());
        holder.tvPublished.setText(item.datePart());
        holder.tvSeverity.setText(item.severity);

        // severity badge 颜色
        int color = getSeverityColor(item.severity);
        holder.tvSeverity.setBackgroundColor(color);
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    private int getSeverityColor(String severity) {
        switch (severity != null ? severity.toUpperCase() : "NONE") {
            case "CRITICAL": return Color.parseColor("#D32F2F");
            case "HIGH":     return Color.parseColor("#F57C00");
            case "MEDIUM":   return Color.parseColor("#FBC02D");
            case "LOW":      return Color.parseColor("#388E3C");
            default:         return Color.parseColor("#9E9E9E");
        }
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvCveId, tvSeverity, tvDescription, tvCvss, tvPublished;

        ViewHolder(View itemView) {
            super(itemView);
            tvCveId = itemView.findViewById(R.id.tvCveId);
            tvSeverity = itemView.findViewById(R.id.tvSeverity);
            tvDescription = itemView.findViewById(R.id.tvDescription);
            tvCvss = itemView.findViewById(R.id.tvCvss);
            tvPublished = itemView.findViewById(R.id.tvPublished);
        }
    }
}
