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

use crate::ui::native::{
    types::{Message, SidebarMessage, TimeRange},
    RouterUi,
};

use chrono::{Duration, Local};
use plotters::{
    prelude::*,
    style::{ShapeStyle, WHITE},
};
use plotters_iced::Chart;

impl Chart<Message> for RouterUi {
    type State = ();

    #[inline]
    fn draw<R: plotters_iced::Renderer, F: Fn(&mut iced::widget::canvas::Frame)>(
        &self,
        renderer: &R,
        bounds: iced::Size,
        draw_fn: F,
    ) -> iced::widget::canvas::Geometry {
        renderer.draw_cache(&self.cache, bounds, draw_fn)
    }

    fn build_chart<DB: DrawingBackend>(&self, _state: &Self::State, mut builder: ChartBuilder<DB>) {
        let (samples, mult) = match self.view {
            SidebarMessage::Dashboard => (self.total_bandwidth.get_live(), 1.0),
            SidebarMessage::Bandwidth => match self.selected_range {
                TimeRange::Live if self.transit_only_bandwidth =>
                    (self.transit_bandwidth.get_live(), 1.0),
                TimeRange::TenMin if self.transit_only_bandwidth =>
                    (self.transit_bandwidth.get_10min(), 7.5),
                TimeRange::OneHour if self.transit_only_bandwidth =>
                    (self.transit_bandwidth.get_1hr(), 45.),
                TimeRange::SixHours if self.transit_only_bandwidth =>
                    (self.transit_bandwidth.get_6hr(), 270.),
                TimeRange::Live => (self.total_bandwidth.get_live(), 1.0),
                TimeRange::TenMin => (self.total_bandwidth.get_10min(), 7.5),
                TimeRange::OneHour => (self.total_bandwidth.get_1hr(), 45.),
                TimeRange::SixHours => (self.total_bandwidth.get_6hr(), 270.),
            },
            _ => return,
        };

        let max_traffic = samples
            .iter()
            .map(|sample| {
                let (total_in, total_out) = sample.average();

                (if self.show_inbound {
                    total_in as f32
                } else {
                    0.0
                }) + (if self.show_outbound {
                    total_out as f32
                } else {
                    0.0
                })
            })
            .fold(0.0, f32::max)
            * 1.1; // add 10% headroom

        let mut chart = builder
            .margin(20)
            .set_left_and_bottom_label_area_size(40)
            .y_label_area_size(60)
            .x_label_area_size(20)
            .build_cartesian_2d(0f32..(samples.len() as f32), 0f32..max_traffic)
            .expect("to succeed");

        let white_text_style = TextStyle::from(
            FontDesc::new(FontFamily::SansSerif, 15.0, FontStyle::Normal).into_font(),
        )
        .color(&WHITE);

        let now = Local::now();
        let num_samples = samples.len() as f32;

        let mut chart_tmp = chart.configure_mesh();
        let chart_tmp = chart_tmp
            .y_label_style(white_text_style.clone())
            .y_label_formatter(&|value| {
                let kb = value / 1000f32;
                let mb = kb / 1000f32;

                if mb > 1f32 {
                    format!("{mb} MB/s")
                } else if kb > 1f32 {
                    format!("{kb} KB/s")
                } else {
                    format!("{value} B/s")
                }
            })
            .x_label_style(white_text_style)
            .x_label_offset(-50);

        if samples.len() >= 10 {
            chart_tmp
                .x_label_formatter(&|value| {
                    if value == &0.0 {
                        return String::from("");
                    }
                    let value = num_samples - *value;

                    let ts = now - Duration::seconds((mult * value).round() as i64);
                    ts.format("%H:%M:%S").to_string()
                })
                .draw()
                .expect("to succeed");
        } else {
            chart_tmp.x_label_formatter(&|_| String::from("")).draw().expect("to succeed");
        }

        let bar_width = 0.8;

        for (i, sample) in samples.iter().enumerate() {
            let mut base = 0.0;
            let x_center = i as f32 + 0.5;
            let x0 = x_center - bar_width / 2.0;
            let x1 = x_center + bar_width / 2.0;
            let (total_in, total_out) = sample.average();

            if self.show_inbound {
                chart
                    .draw_series(std::iter::once(Rectangle::new(
                        [(x0, 0.0), (x1, total_in as f32)],
                        ShapeStyle {
                            color: RGBAColor(70, 130, 180, 0.7),
                            filled: true,
                            stroke_width: 0,
                        },
                    )))
                    .expect("to succeed");
                base += total_in as f32;
            }

            if self.show_outbound {
                chart
                    .draw_series(std::iter::once(Rectangle::new(
                        [(x0, base), (x1, base + total_out as f32)],
                        ShapeStyle {
                            color: RGBAColor(255, 165, 0, 0.7),
                            filled: true,
                            stroke_width: 0,
                        },
                    )))
                    .expect("to succeed");
            }
        }
    }
}
