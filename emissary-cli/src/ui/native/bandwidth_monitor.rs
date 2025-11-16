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

use std::collections::VecDeque;

/// A single bandwidth sample or an aggregate bucket.
#[derive(Clone, Default)]
pub struct TimeBucket {
    total_in: f64,
    total_out: f64,
    count: u32,
}

impl TimeBucket {
    fn add_sample(&mut self, bw_in: f64, bw_out: f64) {
        self.total_in += bw_in;
        self.total_out += bw_out;
        self.count += 1;
    }

    pub fn average(&self) -> (f64, f64) {
        if self.count == 1 {
            (self.total_in, self.total_out)
        } else {
            (
                self.total_in / self.count as f64,
                self.total_out / self.count as f64,
            )
        }
    }
}

/// A fixed-size ring buffer.
pub struct RingBuffer {
    data: VecDeque<TimeBucket>,
    capacity: usize,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        RingBuffer {
            data: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, bucket: TimeBucket) {
        if self.data.len() == self.capacity {
            self.data.pop_front();
        }

        self.data.push_back(bucket);
    }

    fn get(&self) -> &VecDeque<TimeBucket> {
        &self.data
    }
}

/// Holds state for one resolution (10min, 1h, 6h).
pub struct ResolutionTracker {
    interval_seconds: f64,
    accumulator: TimeBucket,
    elapsed: f64,
    buffer: RingBuffer,
}

impl ResolutionTracker {
    fn new(interval_seconds: f64) -> Self {
        ResolutionTracker {
            interval_seconds,
            accumulator: TimeBucket::default(),
            elapsed: 0.0,
            buffer: RingBuffer::new(80),
        }
    }

    fn tick(&mut self, bw_in: f64, bw_out: f64, dt: f64) {
        self.accumulator.add_sample(bw_in, bw_out);
        self.elapsed += dt;

        if self.elapsed >= self.interval_seconds {
            self.buffer.push(self.accumulator.clone());
            self.accumulator = TimeBucket::default();
            self.elapsed = 0.0;
        }
    }

    fn get_buckets(&self) -> &VecDeque<TimeBucket> {
        self.buffer.get()
    }
}

/// Main structure managing all resolutions.
pub struct BandwidthMonitor {
    live_buffer: RingBuffer,
    res_10min: ResolutionTracker,
    res_1hr: ResolutionTracker,
    res_6hr: ResolutionTracker,
}

impl BandwidthMonitor {
    pub fn new() -> Self {
        BandwidthMonitor {
            live_buffer: RingBuffer::new(80),
            res_10min: ResolutionTracker::new(7.5),
            res_1hr: ResolutionTracker::new(45.),
            res_6hr: ResolutionTracker::new(270.),
        }
    }

    /// Call this every second with a new bandwidth sample.
    pub fn update(&mut self, bw_in: f64, bw_out: f64) {
        let mut bucket = TimeBucket::default();
        bucket.add_sample(bw_in, bw_out);
        self.live_buffer.push(bucket);

        self.res_10min.tick(bw_in, bw_out, 1.0);
        self.res_1hr.tick(bw_in, bw_out, 1.0);
        self.res_6hr.tick(bw_in, bw_out, 1.0);
    }

    pub fn get_live(&self) -> &VecDeque<TimeBucket> {
        self.live_buffer.get()
    }

    pub fn get_10min(&self) -> &VecDeque<TimeBucket> {
        self.res_10min.get_buckets()
    }

    pub fn get_1hr(&self) -> &VecDeque<TimeBucket> {
        self.res_1hr.get_buckets()
    }

    pub fn get_6hr(&self) -> &VecDeque<TimeBucket> {
        self.res_6hr.get_buckets()
    }
}
