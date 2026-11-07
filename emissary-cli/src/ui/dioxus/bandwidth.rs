// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::ui::{
    calculate_bandwidth,
    dioxus::{
        bandwidth_monitor::{TimeBucket, TimeRange},
        svg::*,
        AppState,
    },
};

use dioxus::prelude::*;
use std::collections::VecDeque;

/// Which bandwidth monitor to draw.
#[derive(Clone, PartialEq)]
pub enum ChartSource {
    Total,
    Transit,
}

fn status_card(title: &str, value: String, icon_svg: &str) -> Element {
    rsx! {
        div {
            class: "status-card",
            div { class: "status-card-icon",
                span { style: "display:inline-flex;width:28px;height:28px;", dangerous_inner_html: icon_svg }
            }
            div { class: "status-card-info",
                div { class: "status-card-title", "{title}" }
                div { class: "status-card-value", "{value}" }
            }
        }
    }
}

/// Format a raw byte value as a short Y-axis label.
fn format_y_label(val: f64) -> String {
    if val < 1_000.0 {
        format!("{:.0}B", val)
    } else if val < 1_000_000.0 {
        format!("{:.0}KB", val / 1_000.0)
    } else {
        format!("{:.1}MB", val / 1_000_000.0)
    }
}

// Pad start of chart values with zeroes if there isn't enough data yet.
fn zero_pad_chart_values(vals: &mut Vec<f64>, expected_size: usize) -> () {
    let actual_size = vals.len();
    if actual_size < expected_size {
        vals.splice(0..0, [0.0].repeat(expected_size - actual_size));
    }
}

// Normalize buckets.
fn normalize_buckets(buckets: &VecDeque<TimeBucket>) -> (Vec<f64>, Vec<f64>, f64) {
    let mut in_vals: Vec<f64> = buckets.iter().map(|b| b.average().0).collect();
    let mut out_vals: Vec<f64> = buckets.iter().map(|b| b.average().1).collect();

    zero_pad_chart_values(&mut in_vals, 80);
    zero_pad_chart_values(&mut out_vals, 80);

    let max_val = in_vals.iter().chain(out_vals.iter()).cloned().fold(0.0f64, f64::max);
    let max_val = if max_val == 0.0 { 1.0 } else { max_val };
    let in_norm: Vec<f64> = in_vals.iter().map(|v| v / max_val).collect();
    let out_norm: Vec<f64> = out_vals.iter().map(|v| v / max_val).collect();

    (in_norm, out_norm, max_val)
}

/// Five evenly-spaced x-axis time labels for the given time range.
fn x_axis_labels(range: TimeRange) -> [&'static str; 5] {
    match range {
        TimeRange::Live => ["", "", "", "", "now"],
        TimeRange::TenMin => ["-10m", "-7.5m", "-5m", "-2.5m", "now"],
        TimeRange::OneHour => ["-60m", "-45m", "-30m", "-15m", "now"],
        TimeRange::SixHours => ["-6h", "-4.5h", "-3h", "-1.5h", "now"],
    }
}

#[component]
pub fn BandwidthChart(source: ChartSource) -> Element {
    let state = use_context::<SyncSignal<AppState>>();

    let (buckets_in, buckets_out, show_in, show_out, max_val) = {
        let state = state.read();
        let traffic = state.traffic.lock().expect("to succeed");
        let monitor = match source {
            ChartSource::Total => &traffic.total_bandwidth,
            ChartSource::Transit => &traffic.transit_bandwidth,
        };

        let buckets: &VecDeque<TimeBucket> = match traffic.options.range {
            TimeRange::Live => monitor.get_live(),
            TimeRange::TenMin => monitor.get_10min(),
            TimeRange::OneHour => monitor.get_1hr(),
            TimeRange::SixHours => monitor.get_6hr(),
        };

        let (in_norm, out_norm, mv) = normalize_buckets(buckets);
        (
            in_norm,
            out_norm,
            traffic.options.show_inbound,
            traffic.options.show_outbound,
            mv,
        )
    };

    let y_labels: Vec<(String, u32)> = vec![
        (format_y_label(max_val), 91),
        (format_y_label(max_val * 0.75), 68),
        (format_y_label(max_val * 0.50), 46),
        (format_y_label(max_val * 0.25), 23),
    ];

    let width = 800.0f64;
    let height = 280.0f64;
    let top_pad = 24.0f64;
    let drawable = height - top_pad;

    let n = buckets_in.len();
    let x_step = if n > 1 { width / (n - 1) as f64 } else { width };

    let in_points: String = buckets_in
        .iter()
        .enumerate()
        .map(|(i, v)| format!("{:.2},{:.2} ", i as f64 * x_step, height - v * drawable))
        .collect();
    let out_points: String = buckets_out
        .iter()
        .enumerate()
        .map(|(i, v)| format!("{:.2},{:.2} ", i as f64 * x_step, height - v * drawable))
        .collect();

    let last_x = (n - 1) as f64 * x_step;
    let in_poly = format!("{in_points}{last_x:.2},{height:.2} 0,{height:.2}");
    let out_poly = format!("{out_points}{last_x:.2},{height:.2} 0,{height:.2}");

    rsx! {
        div {
            style: "position:absolute;left:0;top:0;bottom:0;width:52px;pointer-events:none;z-index:1;",
            for (label, bottom_pct) in &y_labels {
                span {
                    class: "chart-label",
                    style: "bottom:{bottom_pct}%",
                    "{label}"
                }
            }
        }
        svg {
            style: "position:absolute;left:52px;top:0;bottom:0;right:0;",
            width: "100%",
            height: "100%",
            view_box: "0 0 800 280",
            preserve_aspect_ratio: "none",

            defs {
                linearGradient { id: "grad-in", x1: "0", y1: "0", x2: "0", y2: "1",
                    stop { offset: "0%",   stop_color: "rgba(70,130,180,0.55)" }
                    stop { offset: "100%", stop_color: "rgba(70,130,180,0.0)" }
                }
                linearGradient { id: "grad-out", x1: "0", y1: "0", x2: "0", y2: "1",
                    stop { offset: "0%",   stop_color: "rgba(255,165,0,0.45)" }
                    stop { offset: "100%", stop_color: "rgba(255,165,0,0.0)" }
                }
            }

            if show_in {
                polygon { points: "{in_poly}", fill: "url(#grad-in)" }
                polyline {
                    points: "{in_points}",
                    fill: "none", stroke: "#4682b4", stroke_width: "1.5",
                    stroke_linejoin: "round", stroke_linecap: "round",
                }

                for (i, v) in buckets_in.iter().enumerate() {
                    {
                        let cx = i as f64 * x_step;
                        let cy = height - v * drawable;
                        let label = format_y_label(v * max_val);

                        rsx! {
                            circle {
                                cx: "{cx:.2}", cy: "{cy:.2}", r: "3",
                                fill: "#4682b4", opacity: "0.5",
                                title { "{label}" }
                            }
                        }
                    }
                }
            }

            if show_out {
                polygon { points: "{out_poly}", fill: "url(#grad-out)" }
                polyline {
                    points: "{out_points}",
                    fill: "none", stroke: "#ffa500", stroke_width: "1.5",
                    stroke_linejoin: "round", stroke_linecap: "round",
                }

                for (i, v) in buckets_out.iter().enumerate() {
                    {
                        let cx = i as f64 * x_step;
                        let cy = height - v * drawable;
                        let label = format_y_label(v * max_val);

                        rsx! {
                            circle {
                                cx: "{cx:.2}", cy: "{cy:.2}", r: "3",
                                fill: "#ffa500", opacity: "0.5",
                                title { "{label}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn BandwidthView() -> Element {
    let mut state = use_context::<SyncSignal<AppState>>();

    let (inbound_bw, outbound_bw, peak_traffic, uptime_secs, selected_range) = {
        let state = state.read();
        let traffic = state.traffic.lock().expect("to succeed");
        let up = state.router_state().uptime.elapsed().as_secs_f64().max(1.0);
        (
            traffic.inbound_bandwidth,
            traffic.outbound_bandwidth,
            traffic.peak_traffic,
            up,
            traffic.options.range,
        )
    };

    let (in_val, in_unit) = calculate_bandwidth(inbound_bw as f64 / uptime_secs);
    let (out_val, out_unit) = calculate_bandwidth(outbound_bw as f64 / uptime_secs);
    let (peak_val, peak_unit) = calculate_bandwidth(peak_traffic as f64);
    let (in_total_val, in_total_unit) = calculate_bandwidth(inbound_bw as f64);
    let (out_total_val, out_total_unit) = calculate_bandwidth(outbound_bw as f64);
    let x_labels = x_axis_labels(selected_range);

    rsx! {
        div {
            class: "page",
            div {
                class: "page-title",
                h1 { "Bandwidth" }
                p { "Monitor the bandwidth usage of your I2P router" }
            }

            // status cards
            div {
                class: "status-cards",
                { status_card("Inbound",        format!("{in_val:.2} {in_unit}/s"),             DOWNLOAD_SVG)     }
                { status_card("Outbound",       format!("{out_val:.2} {out_unit}/s"),           UPLOAD_SVG)       }
                { status_card("Peak",           format!("{peak_val:.2} {peak_unit}/s"),         PEAK_TRAFFIC_SVG) }
                { status_card("Total inbound",  format!("{in_total_val:.2} {in_total_unit}"),   BANDWIDTH_SVG)    }
                { status_card("Total outbound", format!("{out_total_val:.2} {out_total_unit}"), BANDWIDTH_SVG)    }
            }

            div {
                class: "bandwidth-card",
                div {
                    class: "bandwidth-controls",
                    div {
                        class: "time-buttons",
                        button {
                            class: if selected_range == TimeRange::Live     { "time-btn active" } else { "time-btn" },
                            onclick: move |_| { state.write().traffic.lock().expect("to succeed").options.range = TimeRange::Live; },
                            "Live"
                        }
                        button {
                            class: if selected_range == TimeRange::TenMin   { "time-btn active" } else { "time-btn" },
                            onclick: move |_| { state.write().traffic.lock().expect("to succeed").options.range = TimeRange::TenMin; },
                            "10 min"
                        }
                        button {
                            class: if selected_range == TimeRange::OneHour  { "time-btn active" } else { "time-btn" },
                            onclick: move |_| { state.write().traffic.lock().expect("to succeed").options.range = TimeRange::OneHour; },
                            "1 h"
                        }
                        button {
                            class: if selected_range == TimeRange::SixHours { "time-btn active" } else { "time-btn" },
                            onclick: move |_| { state.write().traffic.lock().expect("to succeed").options.range = TimeRange::SixHours; },
                            "6 h"
                        }
                    }

                    // in/out buttons
                    div {
                        class: "chart-legend",
                        button {
                            class: "chart-legend-btn",
                            style: "color:#4682b4;",
                            onclick: move |_| {
                                let app = state.write();
                                let mut traffic = app.traffic.lock().expect("to succeed");
                                traffic.options.show_outbound = !traffic.options.show_outbound;
                            },
                            "● Inbound"
                        }
                        button {
                            class: "chart-legend-btn",
                            style: "color:#ffa500;",
                            onclick: move |_| {
                                let app = state.write();
                                let mut traffic = app.traffic.lock().expect("to succeed");
                                traffic.options.show_inbound = !traffic.options.show_inbound;
                            },
                            "● Outbound"
                        }
                    }
                }

                // total bandwidth chart
                div {
                    class: "chart-title",
                    "Total"
                }
                div {
                    class: "chart-container",
                    BandwidthChart { source: ChartSource::Total }
                }
                div {
                    class: "chart-x-axis",
                    for label in x_labels { span { "{label}" } }
                }

                // transit bandwidth chart
                div {
                    class: "chart-title",
                    "Transit"
                }
                div {
                    class: "chart-container",
                    BandwidthChart { source: ChartSource::Transit }
                }
                div {
                    class: "chart-x-axis",
                    for label in x_labels { span { "{label}" } }
                }
            }
        }
    }
}
