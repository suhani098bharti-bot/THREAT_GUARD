"""Plotly interactive visualization charts for ThreatGuard SOC dashboard."""

from typing import Dict
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from config.settings import SEVERITY_COLORS

# SOC Dark Theme Layout Template
PLOT_THEME_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#E2E8F0", family="sans-serif", size=12),
    margin=dict(l=20, r=20, t=40, b=20),
    xaxis=dict(
        gridcolor="#1E293B",
        zerolinecolor="#1E293B",
        showgrid=True,
    ),
    yaxis=dict(
        gridcolor="#1E293B",
        zerolinecolor="#1E293B",
        showgrid=True,
    ),
    legend=dict(
        bgcolor="rgba(19, 27, 46, 0.7)",
        bordercolor="#334155",
        borderwidth=1,
    ),
)


def create_threats_timeline_chart(df: pd.DataFrame) -> go.Figure:
    """Timeline area/line chart of threats detected over time by severity."""
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No threat timeline data available",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(color="#64748B", size=14),
        )
        fig.update_layout(**PLOT_THEME_LAYOUT)
        return fig

    fig = px.bar(
        df,
        x="detection_date",
        y="count",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Threat Detections Over Time",
        labels={"detection_date": "Date", "count": "Detection Count", "severity": "Severity"},
        barmode="stack",
    )
    fig.update_layout(**PLOT_THEME_LAYOUT)
    fig.update_traces(marker_line_width=0)
    return fig


def create_severity_pie_chart(df: pd.DataFrame) -> go.Figure:
    """Donut chart showing distribution of incidents by severity tier."""
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No incident data",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(color="#64748B", size=14),
        )
        fig.update_layout(**PLOT_THEME_LAYOUT)
        return fig

    fig = px.pie(
        df,
        names="severity",
        values="count",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        hole=0.55,
        title="Threat Distribution by Severity",
    )
    fig.update_layout(**PLOT_THEME_LAYOUT)
    fig.update_traces(
        textposition="inside",
        textinfo="percent+label",
        marker=dict(line=dict(color="#0B0F19", width=2)),
    )
    return fig


def create_attack_category_chart(df: pd.DataFrame) -> go.Figure:
    """Horizontal bar chart showing detected attack categories."""
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No attack category data",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(color="#64748B", size=14),
        )
        fig.update_layout(**PLOT_THEME_LAYOUT)
        return fig

    fig = px.bar(
        df.sort_values(by="count", ascending=True),
        x="count",
        y="category",
        orientation="h",
        color="count",
        color_continuous_scale=[[0, "#3B82F6"], [1, "#00D2FF"]],
        title="Detected Threats by Attack Category",
        labels={"count": "Incident Count", "category": "Attack Category"},
    )
    fig.update_layout(**PLOT_THEME_LAYOUT, coloraxis_showscale=False)
    fig.update_traces(marker_line_width=0)
    return fig


def create_incident_status_chart(df: pd.DataFrame) -> go.Figure:
    """Donut chart showing incident lifecycle statuses."""
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No incident status data",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(color="#64748B", size=14),
        )
        fig.update_layout(**PLOT_THEME_LAYOUT)
        return fig

    status_colors = {
        "New": "#FF4B4B",
        "Investigating": "#FFA500",
        "Contained": "#9333EA",
        "Resolved": "#10B981",
        "False Positive": "#64748B",
    }

    fig = px.pie(
        df,
        names="status",
        values="count",
        color="status",
        color_discrete_map=status_colors,
        hole=0.55,
        title="Incident Resolution Status Distribution",
    )
    fig.update_layout(**PLOT_THEME_LAYOUT)
    fig.update_traces(
        textposition="inside",
        textinfo="percent+label",
        marker=dict(line=dict(color="#0B0F19", width=2)),
    )
    return fig


def create_event_activity_chart(df: pd.DataFrame) -> go.Figure:
    """Bar chart of raw security telemetry grouped by event type."""
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No log telemetry data",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(color="#64748B", size=14),
        )
        fig.update_layout(**PLOT_THEME_LAYOUT)
        return fig

    fig = px.bar(
        df,
        x="event_type",
        y="count",
        color="count",
        color_continuous_scale=[[0, "#6366F1"], [1, "#00D2FF"]],
        title="Security Telemetry Volume by Event Type",
        labels={"event_type": "Event Type", "count": "Logged Records"},
    )
    fig.update_layout(**PLOT_THEME_LAYOUT, coloraxis_showscale=False)
    fig.update_traces(marker_line_width=0)
    return fig


def create_top_ips_chart(df: pd.DataFrame) -> go.Figure:
    """Bar chart visualizing top suspicious IP addresses and their threat volumes."""
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No suspicious IPs identified yet",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(color="#64748B", size=14),
        )
        fig.update_layout(**PLOT_THEME_LAYOUT)
        return fig

    fig = px.bar(
        df.sort_values(by="threat_count", ascending=True),
        x="threat_count",
        y="source_ip",
        orientation="h",
        color="max_risk_score",
        color_continuous_scale=[[0, "#F4D03F"], [0.5, "#FFA500"], [1, "#FF4B4B"]],
        title="Top Suspicious IP Addresses (By Threat Frequency & Max Risk)",
        labels={"threat_count": "Detection Matches", "source_ip": "Source IP", "max_risk_score": "Risk Score"},
    )
    fig.update_layout(**PLOT_THEME_LAYOUT)
    fig.update_traces(marker_line_width=0)
    return fig
