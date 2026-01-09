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
pub const NUM_INBOUND_TUNNELS: &str = "tunnel_inbound_count";
pub const NUM_OUTBOUND_TUNNELS: &str = "tunnel_outbound_count";
pub const NUM_FRAGMENTS: &str = "tunnel_num_fragments";
pub const NUM_DROPPED_FRAGMENTS: &str = "tunnel_dropped_fragment_count";

// tunnel building
pub const NUM_PENDING_INBOUND_TUNNELS: &str = "tunnel_pending_inbound_count";
pub const NUM_PENDING_OUTBOUND_TUNNELS: &str = "tunnel_pending_outbound_count";
pub const NUM_BUILD_FAILURES: &str = "tunnel_build_failure_count";
pub const NUM_BUILD_SUCCESSES: &str = "tunnel_build_success_count";

// tunnel tests
pub const NUM_TEST_FAILURES: &str = "tunnel_test_failure_count";
pub const NUM_TEST_SUCCESSES: &str = "tunnel_test_success_count";
pub const TUNNEL_TEST_DURATIONS: &str = "tunnel_test_durations";
pub const TUNNEL_BUILD_DURATIONS: &str = "tunnel_build_durations";

// transit
pub const NUM_TRANSIT_TUNNELS: &str = "transit_tunnels_count";
pub const TOTAL_TRANSIT_TUNNELS: &str = "transit_tunnels_total_count";
pub const NUM_TRANSIT_TUNNELS_ACCEPTED: &str = "transit_tunnels_accepted_count";
pub const NUM_TRANSIT_TUNNELS_REJECTED: &str = "transit_tunnels_rejected_count";
pub const NUM_BUILD_REQUESTS: &str = "transit_build_request_count";
pub const NUM_ROUTED_MESSAGES: &str = "transit_routed_messages_count";
pub const NUM_DROPPED_MESSAGES: &str = "transit_dropped_messages_count";
pub const NUM_PARTICIPANTS: &str = "transit_num_participants";
pub const NUM_OBEPS: &str = "transit_num_obeps";
pub const NUM_IBGWS: &str = "transit_num_ibgws";

/// Register tunnel metrics.
pub fn register_metrics(mut metrics: Vec<MetricType>) -> Vec<MetricType> {
    // counters
    metrics.push(MetricType::Counter {
        name: NUM_BUILD_FAILURES,
        description: "number of tunnel build failures",
    });
    metrics.push(MetricType::Counter {
        name: NUM_BUILD_SUCCESSES,
        description: "number of tunnel build successes",
    });
    metrics.push(MetricType::Counter {
        name: NUM_TEST_FAILURES,
        description: "number of failed tunnel tests",
    });
    metrics.push(MetricType::Counter {
        name: NUM_TEST_SUCCESSES,
        description: "number of succeeded tunnel tests",
    });
    metrics.push(MetricType::Counter {
        name: NUM_TRANSIT_TUNNELS_ACCEPTED,
        description: "number of transit tunnels that were accepted",
    });
    metrics.push(MetricType::Counter {
        name: NUM_TRANSIT_TUNNELS_REJECTED,
        description: "number of transit tunnels that were rejected",
    });
    metrics.push(MetricType::Counter {
        name: NUM_ROUTED_MESSAGES,
        description: "number of successfully routed messages",
    });
    metrics.push(MetricType::Counter {
        name: NUM_DROPPED_MESSAGES,
        description: "number of dropped messages",
    });
    metrics.push(MetricType::Counter {
        name: NUM_DROPPED_FRAGMENTS,
        description: "number of dropped incomplete fragments",
    });
    metrics.push(MetricType::Counter {
        name: NUM_BUILD_REQUESTS,
        description: "number of tunnel build requests received",
    });
    metrics.push(MetricType::Counter {
        name: TOTAL_TRANSIT_TUNNELS,
        description: "total number of transit tunnels started",
    });

    // gauges
    metrics.push(MetricType::Gauge {
        name: NUM_PENDING_INBOUND_TUNNELS,
        description: "number of pending inbound tunnels",
    });
    metrics.push(MetricType::Gauge {
        name: NUM_PENDING_OUTBOUND_TUNNELS,
        description: "number of pending outbound tunnels",
    });
    metrics.push(MetricType::Gauge {
        name: NUM_INBOUND_TUNNELS,
        description: "number of inbound tunnels",
    });
    metrics.push(MetricType::Gauge {
        name: NUM_OUTBOUND_TUNNELS,
        description: "number of outbound tunnels",
    });
    metrics.push(MetricType::Gauge {
        name: NUM_TRANSIT_TUNNELS,
        description: "number of transit tunnels",
    });
    metrics.push(MetricType::Gauge {
        name: NUM_PARTICIPANTS,
        description: "number of participants",
    });
    metrics.push(MetricType::Gauge {
        name: NUM_OBEPS,
        description: "number of outbound endpoints",
    });
    metrics.push(MetricType::Gauge {
        name: NUM_IBGWS,
        description: "number of inbound gateways",
    });

    // histograms
    metrics.push(MetricType::Histogram {
        name: TUNNEL_TEST_DURATIONS,
        description: "tunnel test durations",
        buckets: vec![
            100f64, 150f64, 200f64, 250f64, 300f64, 400f64, 600f64, 800f64, 1000f64, 1500f64,
        ],
    });
    metrics.push(MetricType::Histogram {
        name: TUNNEL_BUILD_DURATIONS,
        description: "tunnel test durations",
        buckets: vec![
            200f64, 300f64, 500f64, 700f64, 900f64, 1100f64, 1300f64, 1500f64, 1700f64, 2000f64,
        ],
    });
    metrics.push(MetricType::Histogram {
        name: NUM_FRAGMENTS,
        description: "number of fragments per message",
        buckets: vec![
            1f64, 2f64, 5f64, 8f64, 10f64, 15f64, 20f64, 35f64, 30f64, 40f64, 50f64,
        ],
    });

    metrics
}
