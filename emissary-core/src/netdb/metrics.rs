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

pub const NUM_FLOODFILLS: &str = "netdb_floodfill_count";
pub const NUM_QUERIED: &str = "netdb_num_queried";

pub const NUM_RI_QUERY_SUCCESSES: &str = "netdb_num_router_info_query_success_count";
pub const NUM_RI_QUERY_FAILURES: &str = "netdb_num_router_info_query_failure_count";
pub const RI_NUM_QUERIED: &str = "netdb_router_info_queried";

pub const NUM_LS_QUERY_SUCCESSES: &str = "netdb_num_lease_set_query_success_count";
pub const NUM_LS_QUERY_FAILURES: &str = "netdb_num_lease_set_query_failure_count";
pub const LS_NUM_QUERIED: &str = "netdb_lease_set_queried";

pub const QUERY_DURATION_BUCKET: &str = "netdb_query_durations";
pub const ACTIVE_QUERIES: &str = "netdb_active_query_count";

/// Register NetDB metrics.
pub fn register_metrics(mut metrics: Vec<MetricType>) -> Vec<MetricType> {
    // counters
    metrics.push(MetricType::Counter {
        name: NUM_FLOODFILLS,
        description: "number of know floodfills",
    });
    metrics.push(MetricType::Counter {
        name: NUM_RI_QUERY_SUCCESSES,
        description: "number of failed router info queries",
    });
    metrics.push(MetricType::Counter {
        name: NUM_RI_QUERY_FAILURES,
        description: "number of successful router info queries",
    });
    metrics.push(MetricType::Counter {
        name: NUM_LS_QUERY_SUCCESSES,
        description: "number of failed lease set queries",
    });
    metrics.push(MetricType::Counter {
        name: NUM_LS_QUERY_FAILURES,
        description: "number of successful lease set queries",
    });

    // gauges
    metrics.push(MetricType::Gauge {
        name: ACTIVE_QUERIES,
        description: "number of active queries",
    });

    // histograms
    metrics.push(MetricType::Histogram {
        name: QUERY_DURATION_BUCKET,
        description: "how long queries take",
        buckets: vec![
            100f64, 300f64, 500f64, 1000f64, 1500f64, 2500f64, 4000f64, 6000f64, 7000f64,
        ],
    });
    metrics.push(MetricType::Histogram {
        name: RI_NUM_QUERIED,
        description: "how many routers were queried for the lookup",
        buckets: vec![1f64, 2f64, 3f64, 4f64, 5f64, 7f64, 9f64, 11f64, 15f64],
    });
    metrics.push(MetricType::Histogram {
        name: LS_NUM_QUERIED,
        description: "how many routers were queried for the lookup",
        buckets: vec![1f64, 2f64, 3f64, 4f64, 5f64, 7f64, 9f64, 11f64, 15f64],
    });
    metrics.push(MetricType::Histogram {
        name: NUM_QUERIED,
        description: "how many routers were queried for the lookup",
        buckets: vec![1f64, 2f64, 3f64, 4f64, 5f64, 7f64, 9f64, 11f64, 15f64],
    });

    metrics
}
