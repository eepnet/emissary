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
    native::{
        svg_util::{bandwidth, download, peak_traffic, upload},
        types::{Message, TimeRange},
        RouterUi,
    },
};

use iced::{
    advanced::widget::Text,
    border::Radius,
    widget::{button, column, container, row, Column, Container, Row},
    Border, Color, Element, Length, Theme,
};
use plotters_iced::ChartWidget;

fn time_button<'a>(
    label: &'a str,
    active: bool,
    on_press: Message,
) -> iced::widget::Button<'a, Message> {
    let btn = button(Text::new(label)).on_press(on_press);

    if active {
        btn.style(iced::widget::button::primary)
    } else {
        btn.style(iced::widget::button::secondary)
    }
}

impl RouterUi {
    pub fn bandwidth(&self) -> Element<'_, Message> {
        let title = Container::new(
            Column::new()
                .push(Text::new("Bandwidth").size(24).color(Color::WHITE))
                .push(
                    Text::new("Monitor the bandwidth usage of your I2P router")
                        .size(16)
                        .color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                )
                .spacing(5),
        );
        let (total_value, total_unit) =
            calculate_bandwidth((self.inbound_bandwidth + self.outbound_bandwidth) as f64);
        let (inbound_value, inbound_unit) = calculate_bandwidth(
            self.inbound_bandwidth as f64 / self.uptime.elapsed().as_secs_f64(),
        );
        let (outbound_value, outbound_unit) = calculate_bandwidth(
            self.outbound_bandwidth as f64 / self.uptime.elapsed().as_secs_f64(),
        );
        let (peak_value, peak_unit) = calculate_bandwidth(self.peak_traffic as f64);

        let inbound = Self::status_card(
            "Inbound traffic",
            format!("{inbound_value:.2} {inbound_unit}/s"),
            download::HANDLE.clone(),
        );
        let outbound = Self::status_card(
            "Outbound traffic",
            format!("{outbound_value:.2} {outbound_unit}/s"),
            upload::HANDLE.clone(),
        );
        let peak = Self::status_card(
            "Peak traffic",
            format!("{peak_value:.2} {peak_unit}/s"),
            peak_traffic::HANDLE.clone(),
        );
        let bandwidth = Self::status_card(
            "Total transferred",
            format!("{total_value:.2} {total_unit}"),
            bandwidth::HANDLE.clone(),
        );

        let status_cards = row![
            container(inbound).width(Length::FillPortion(1)),
            container(outbound).width(Length::FillPortion(1)),
            container(peak).width(Length::FillPortion(1)),
            container(bandwidth).width(Length::FillPortion(1)),
        ]
        .spacing(10)
        .padding(5);

        let time_buttons = row![
            time_button(
                "Live",
                matches!(self.selected_range, TimeRange::Live),
                Message::RangeSelected(TimeRange::Live)
            ),
            time_button(
                "10 min",
                matches!(self.selected_range, TimeRange::TenMin),
                Message::RangeSelected(TimeRange::TenMin)
            ),
            time_button(
                "1 h",
                matches!(self.selected_range, TimeRange::OneHour),
                Message::RangeSelected(TimeRange::OneHour)
            ),
            time_button(
                "6 h",
                matches!(self.selected_range, TimeRange::SixHours),
                Message::RangeSelected(TimeRange::SixHours)
            ),
        ]
        .spacing(8);

        let traffic_toggle = row![
            time_button(
                "Total",
                !self.transit_only_bandwidth,
                Message::BanwidthKindToggled,
            ),
            time_button(
                "Transit",
                self.transit_only_bandwidth,
                Message::BanwidthKindToggled,
            ),
        ]
        .spacing(6);

        let top_controls = row![time_buttons, traffic_toggle].spacing(20);
        let graph = ChartWidget::new(self);
        let bandwidth_graph = Container::new(
            Column::new()
                .spacing(10)
                .push(top_controls)
                .push(Container::new(graph).style(|_theme: &Theme| {
                    iced::widget::container::Style {
                        border: Border {
                            radius: Radius::from(12.0),
                            width: 1.0,
                            color: Color::from_rgb8(28, 36, 49),
                        },
                        background: Some(iced::Background::Color(Color::from_rgb8(55, 65, 81))),
                        ..Default::default()
                    }
                }))
                .push(
                    Container::new(
                        Row::new()
                            .spacing(10)
                            .push(
                                button(Text::new("Inbound").color(Color::from_rgb8(70, 130, 180)))
                                    .on_press(Message::ToggleInbound)
                                    .style(|_theme: &Theme, _status| iced::widget::button::Style {
                                        background: None,
                                        text_color: Color::from_rgb8(77, 163, 255),
                                        ..Default::default()
                                    })
                                    .padding(0),
                            )
                            .push(
                                button(Text::new("Outbound").color(Color::from_rgb8(255, 165, 0)))
                                    .on_press(Message::ToggleOutbound)
                                    .style(|_theme: &Theme, _status| iced::widget::button::Style {
                                        background: None,
                                        text_color: Color::from_rgb8(255, 165, 0),
                                        ..Default::default()
                                    })
                                    .padding(0),
                            ),
                    )
                    .center_x(Length::Fill),
                ),
        )
        .height(400)
        .padding(10)
        .width(Length::Fill)
        .style(|_theme: &Theme| iced::widget::container::Style {
            border: Border {
                radius: Radius::from(12.0),
                width: 1.0,
                color: Color::from_rgb8(28, 36, 49),
            },
            background: Some(iced::Background::Color(Color::from_rgb8(28, 36, 49))),
            ..Default::default()
        });

        // let bandwidth_settings = Container::new(
        //     Column::new()
        //         .push(Text::new("Bandwidth usage"))
        //         .push(
        //             Text::new("Maximum bandwidth (KB/s)")
        //                 .size(15)
        //                 .color(Color::from_rgb8(0x9b, 0xa2, 0xae)),
        //         )
        //         .push(
        //             TextInput::new("", "test")
        //                 .size(15)
        //                 .on_input(Message::Ntcp2PortChanged)
        //                 .padding(10)
        //                 .style(
        //                     |_theme: &Theme, _status: _| iced::widget::text_input::Style {
        //                         border: Border {
        //                             radius: Radius::from(6.0),
        //                             width: 1.0,
        //                             color: Color::from_rgb8(28, 36, 49),
        //                         },
        //                         background: iced::Background::Color(iced::Color::from_rgb8(
        //                             0x37, 0x41, 0x51,
        //                         )),
        //                         icon: Color::WHITE,
        //                         placeholder: Color::from_rgb8(0x9b, 0xa2, 0xae),
        //                         value: Color::from_rgb8(0xf3, 0xf3, 0xf2),
        //                         selection: Color::from_rgb8(0x9b, 0xa2, 0xae),
        //                     },
        //                 ),
        //         )
        //         .push(
        //             Text::new("Share percentage")
        //                 .size(15)
        //                 .color(Color::from_rgb8(0x9b, 0xa2, 0xae)),
        //         )
        //         .push(
        //             row![
        //                 Slider::new(0u32..=100u32, self.bandwidth, Message::BandwidthChanged),
        //                 Text::new(format!("{}%", self.bandwidth)),
        //             ]
        //             .spacing(10),
        //         )
        //         .spacing(5),
        // )
        // .padding(10);

        // let settings = Container::new(bandwidth_settings)
        //     .padding(10)
        //     .height(300)
        //     .style(|_theme: &Theme| iced::widget::container::Style {
        //         border: Border {
        //             radius: Radius::from(12.0),
        //             width: 1.0,
        //             color: Color::from_rgb8(28, 36, 49),
        //         },
        //         background: Some(iced::Background::Color(Color::from_rgb8(28, 36, 49))),
        //         ..Default::default()
        //     });

        column![title, status_cards, bandwidth_graph].spacing(15).padding(20).into()
    }
}
