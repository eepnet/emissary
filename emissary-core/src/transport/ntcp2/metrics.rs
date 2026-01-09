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
pub const NUM_CONNECTIONS: &str = "ntcp2_connection_count";
pub const HANDSHAKE_DURATION: &str = "ntcp2_handshake_duration_buckets";
pub const NUM_HANDSHAKE_FAILURES: &str = "ntcp2_handshake_failure_count";
pub const NUM_HANDSHAKE_SUCCESSES: &str = "ntcp2_handshake_success_count";
pub const NUM_INBOUND_NTCP2: &str = "ntcp2_inbound_count";
pub const NUM_OUTBOUND_NTCP2: &str = "ntcp2_outbound_count";

// active connection
pub const NUM_BLOCKS_PER_MSG: &str = "ntcp2_blocks_per_msg";
pub const MESSAGE_SIZES: &str = "ntcp2_msg_sizes";
pub const NUM_INBOUND_MESSAGES: &str = "ntcp2_num_inbound_msgs";
pub const NUM_OUTBOUND_MESSAGES: &str = "ntcp2_num_outbound_msgs";

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
        name: NUM_INBOUND_MESSAGES,
        description: "how many inbound ntcp2 messages have been received",
    });
    metrics.push(MetricType::Counter {
        name: NUM_OUTBOUND_MESSAGES,
        description: "how many outbound ntcp2 messages have been sent",
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
        name: NUM_BLOCKS_PER_MSG,
        description: "number of blocks per message",
        buckets: vec![1f64, 2f64, 3f64, 4f64, 5f64, 8f64, 10f64, 15f64, 20f64],
    });
    metrics.push(MetricType::Histogram {
        name: MESSAGE_SIZES,
        description: "size of ntcp2 message",
        buckets: vec![
            512f64, 1000f64, 1500f64, 2000f64, 5000f64, 10_000f64, 25_000f64, 50_000f64,
        ],
    });

    metrics
}
