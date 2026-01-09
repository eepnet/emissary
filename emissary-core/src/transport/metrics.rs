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

use alloc::vec::Vec;

// connection metrics
pub const NUM_CONNECTIONS: &str = "transport_connections_count";
pub const NUM_REJECTED: &str = "transport_rejected_connections_count";
pub const NUM_ACCEPTED: &str = "transport_accepted_connections_count";
pub const NUM_INITIATED: &str = "transport_initiated_count";
pub const NUM_DIAL_FAILURES: &str = "transport_dial_failure_count";

// netdb-related metrics
pub const NUM_NETDB_QUERIES: &str = "transport_ri_query_count";
pub const NUM_NETDB_QUERY_SUCCESSES: &str = "transport_ri_query_successes";
pub const NUM_NETDB_QUERY_FAILURES: &str = "transport_ri_query_failures";

/// Register transport metrics.
pub fn register_metrics(mut metrics: Vec<MetricType>) -> Vec<MetricType> {
    // counters
    metrics.push(MetricType::Counter {
        name: NUM_INITIATED,
        description: "number of initiated connections",
    });
    metrics.push(MetricType::Counter {
        name: NUM_DIAL_FAILURES,
        description: "number of dial failures",
    });
    metrics.push(MetricType::Counter {
        name: NUM_REJECTED,
        description: "number of rejected connections",
    });
    metrics.push(MetricType::Counter {
        name: NUM_NETDB_QUERIES,
        description: "number of netdb queries",
    });
    metrics.push(MetricType::Counter {
        name: NUM_NETDB_QUERY_SUCCESSES,
        description: "number of successful netdb queries",
    });
    metrics.push(MetricType::Counter {
        name: NUM_NETDB_QUERY_FAILURES,
        description: "number of failed netdb queries",
    });

    // gauges
    metrics.push(MetricType::Gauge {
        name: NUM_CONNECTIONS,
        description: "number of active connections",
    });

    metrics
}
