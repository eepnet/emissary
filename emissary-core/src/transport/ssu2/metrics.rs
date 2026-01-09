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

use crate::runtime::MetricType;

use alloc::{vec, vec::Vec};

// general
pub const NUM_CONNECTIONS: &str = "ssu2_connection_count";
pub const INBOUND_BANDWIDTH: &str = "ssu2_inbound_bytes_count";
pub const OUTBOUND_BANDWIDTH: &str = "ssu2_outbound_bytes_count";
pub const HANDSHAKE_DURATION: &str = "ssu2_handshake_duration_buckets";
pub const NUM_HANDSHAKE_FAILURES: &str = "ssu2_handshake_failure_count";
pub const NUM_HANDSHAKE_SUCCESSES: &str = "ssu2_handshake_success_count";
pub const NUM_INBOUND_SSU2: &str = "ssu2_num_inbound";
pub const NUM_OUTBOUND_SSU2: &str = "ssu2_num_outbound";

// active connection
pub const INBOUND_PKT_SIZES: &str = "ssu2_ib_pkt_sizes";
pub const INBOUND_PKT_COUNT: &str = "ssu2_ib_pkt_count";
pub const OUTBOUND_PKT_COUNT: &str = "ssu2_ob_pkt_count";
pub const NUM_DROPS_CHANNEL_FULL: &str = "ssu2_chan_full_pkt_dropped_count";
pub const DUPLICATE_PKT_COUNT: &str = "ssu2_duplicate_pkt_count";
pub const EXPIRED_PKT_COUNT: &str = "ssu2_expired_pkt_count";
pub const RETRANSMISSION_COUNT: &str = "ssu2_retransmission_count";
pub const INBOUND_FRAGMENT_COUNT: &str = "ssu2_inbound_fragment_counts";
pub const OUTBOUND_FRAGMENT_COUNT: &str = "ssu2_outbound_fragment_counts";
pub const GARBAGE_COLLECTED_COUNT: &str = "ssu2_gc_fragments_count";
pub const ACK_RECEIVE_TIME: &str = "ssu2_ack_receive_times";

/// Register SSU2 metrics.
pub fn register_metrics(mut metrics: Vec<MetricType>) -> Vec<MetricType> {
    // counters
    metrics.push(MetricType::Counter {
        name: NUM_HANDSHAKE_SUCCESSES,
        description: "how many times the ssu2 handshake has succeeded",
    });
    metrics.push(MetricType::Counter {
        name: NUM_HANDSHAKE_FAILURES,
        description: "how many times the ssu2 handshake has failed",
    });
    metrics.push(MetricType::Counter {
        name: INBOUND_BANDWIDTH,
        description: "total amount of received bytes",
    });
    metrics.push(MetricType::Counter {
        name: OUTBOUND_BANDWIDTH,
        description: "total amount of sent bytes",
    });
    metrics.push(MetricType::Counter {
        name: RETRANSMISSION_COUNT,
        description: "how many packets have been resent",
    });
    metrics.push(MetricType::Counter {
        name: INBOUND_PKT_COUNT,
        description: "how many packets have been received",
    });
    metrics.push(MetricType::Counter {
        name: OUTBOUND_PKT_COUNT,
        description: "how many packets have been sent",
    });
    metrics.push(MetricType::Counter {
        name: DUPLICATE_PKT_COUNT,
        description: "how many duplicate packets have been received",
    });
    metrics.push(MetricType::Counter {
        name: EXPIRED_PKT_COUNT,
        description: "how many expired packets have been received",
    });
    metrics.push(MetricType::Counter {
        name: NUM_DROPS_CHANNEL_FULL,
        description: "how many packet have been dropped due to full channels",
    });
    metrics.push(MetricType::Counter {
        name: GARBAGE_COLLECTED_COUNT,
        description: "how many fragments have been garbage collected",
    });

    // gauges
    metrics.push(MetricType::Gauge {
        name: NUM_CONNECTIONS,
        description: "how many active ssu2 connections there are",
    });

    // histograms
    metrics.push(MetricType::Histogram {
        name: HANDSHAKE_DURATION,
        description: "how long it takes for the handshake to finish",
        buckets: vec![
            50f64, 100f64, 150f64, 200f64, 250f64, 300f64, 350f64, 400f64, 450f64, 500f64, 600f64,
            700f64, 800f64, 900f64, 1000f64, 3000f64, 5000f64, 10_000f64,
        ],
    });
    metrics.push(MetricType::Histogram {
        name: INBOUND_PKT_SIZES,
        description: "inbound packet sizes",
        buckets: vec![
            24f64, 100f64, 300f64, 500f64, 700f64, 900f64, 1100f64, 1200f64, 1300f64, 1400f64,
            1500f64,
        ],
    });
    metrics.push(MetricType::Histogram {
        name: ACK_RECEIVE_TIME,
        description: "ack times",
        buckets: vec![
            1f64, 2f64, 3f64, 4f64, 5f64, 8f64, 10f64, 15f64, 20f64, 30f64, 40f64, 50f64, 70f64,
            90f64, 110f64, 120f64, 140f64, 160f64, 180f64, 200f64, 250f64, 300f64, 350f64, 400f64,
            500f64, 800f64, 1000f64,
        ],
    });
    metrics.push(MetricType::Histogram {
        name: INBOUND_FRAGMENT_COUNT,
        description: "how many fragments outbound messages contain",
        buckets: vec![
            1f64, 2f64, 3f64, 4f64, 5f64, 6f64, 7f64, 8f64, 9f64, 10f64, 15f64, 20f64, 25f64,
            30f64, 40f64, 50f64,
        ],
    });
    metrics.push(MetricType::Histogram {
        name: OUTBOUND_FRAGMENT_COUNT,
        description: "how many fragments outbound messages contain",
        buckets: vec![
            1f64, 2f64, 3f64, 4f64, 5f64, 6f64, 7f64, 8f64, 9f64, 10f64, 15f64, 20f64, 25f64,
            30f64, 40f64, 50f64,
        ],
    });

    metrics
}
