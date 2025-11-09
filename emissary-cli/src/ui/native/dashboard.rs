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
        svg_util::{bandwidth, network_status, routers, tbsr, tunnels},
        types::Message,
        RouterUi,
    },
    Status,
};

use iced::{
    advanced::widget::Text,
    border::Radius,
    widget::{button, column, container, row, Column, Container, Row, Space},
    Border, Color, Element, Length, Theme,
};
use plotters_iced::ChartWidget;

impl RouterUi {
    pub fn dashboard(&self) -> Element<'_, Message> {
        let title = Container::new(
            Column::new()
                .push(Text::new("Dashboard").size(24).color(Color::WHITE))
                .push(
                    Text::new("Monitor your I2P router")
                        .size(16)
                        .color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                )
                .spacing(5),
        );
        let (value, unit) =
            calculate_bandwidth((self.inbound_bandwidth + self.outbound_bandwidth) as f64);

        let network_status = Self::status_card(
            "Status",
            match self.status {
                Status::Active => "Active".to_string(),
                Status::ShuttingDown(_) => "Shutting down".to_string(),
            },
            network_status::HANDLE.clone(),
        );
        let routers = Self::status_card(
            "Connected routers",
            self.num_routers.to_string(),
            routers::HANDLE.clone(),
        );
        let tunnels = Self::status_card(
            "Transit tunnels",
            self.num_transit_tunnels.to_string(),
            tunnels::HANDLE.clone(),
        );
        let bandwidth = Self::status_card(
            "Total transferred",
            format!("{value:.2} {unit}"),
            bandwidth::HANDLE.clone(),
        );
        let tunnel_build_rate = Self::status_card(
            "Tunnel success rate",
            format!(
                "{:?}%",
                ((self.num_tunnels_built as f64
                    / ((self.num_tunnels_built + self.num_tunnel_build_failures) as f64))
                    * 100f64) as usize
            ),
            tbsr::HANDLE.clone(),
        );

        macro_rules! read_field {
            ($config:expr, $field:ident) => {
                match $config {
                    Some(ref config) => Text::new(format!("Port {}", config.$field))
                        .color(Color::from_rgb(0.0, 0.8, 0.0)),
                    None => Text::new("Disabled").color(Color::from_rgb(0.9, 0.0, 0.0)),
                }
            };
        }

        let http_proxy = read_field!(self.config.http_proxy, port);
        let socks_proxy = read_field!(self.config.socks_proxy, port);
        let i2cp = read_field!(self.config.i2cp, port);
        let sam_tcp = read_field!(self.config.sam, tcp_port);
        let sam_udp = read_field!(self.config.sam, udp_port);

        let services = Container::new(
            Column::new()
                .push(
                    Container::new(Text::new("Services").size(20).color(Color::WHITE))
                        .center_x(Length::Fill),
                )
                .push(
                    Row::new()
                        .push(
                            Text::new("HTTP Proxy").color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                        )
                        .push(Space::with_width(Length::Fill))
                        .push(http_proxy)
                        .width(Length::Fill),
                )
                .push(
                    Row::new()
                        .push(
                            Text::new("SOCKS Proxy").color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                        )
                        .push(Space::with_width(Length::Fill))
                        .push(socks_proxy)
                        .width(Length::Fill),
                )
                .push(
                    Row::new()
                        .push(Text::new("I2CP").color(Color::from_rgb(0.8392, 0.8392, 0.8392)))
                        .push(Space::with_width(Length::Fill))
                        .push(i2cp)
                        .width(Length::Fill),
                )
                .push(
                    Row::new()
                        .push(Text::new("SAMv3 TCP").color(Color::from_rgb(0.8392, 0.8392, 0.8392)))
                        .push(Space::with_width(Length::Fill))
                        .push(sam_tcp)
                        .width(Length::Fill),
                )
                .push(
                    Row::new()
                        .push(Text::new("SAMv3 UDP").color(Color::from_rgb(0.8392, 0.8392, 0.8392)))
                        .push(Space::with_width(Length::Fill))
                        .push(sam_udp)
                        .width(Length::Fill),
                )
                .spacing(5)
                .width(Length::Fill),
        )
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

        let network_info = Container::new(
            Column::new()
                .push(
                    Container::new(Text::new("Router information").size(20).color(Color::WHITE))
                        .center_x(Length::Fill),
                )
                .push(
                    Row::new()
                        .push(
                            Text::new("Router version")
                                .color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                        )
                        .push(Space::with_width(Length::Fill))
                        .push(
                            Text::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                .color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                        )
                        .width(Length::Fill),
                )
                .push(
                    Row::new()
                        .push(Text::new("Router ID").color(Color::from_rgb(0.8392, 0.8392, 0.8392)))
                        .push(Space::with_width(Length::Fill))
                        .push(
                            button(if self.show_router_id {
                                Text::new("W3dwajBxt4U8xLcKr9bspbaEBwlJ4lXFEbp91E8UvUU=")
                                    .color(Color::from_rgb(0.8392, 0.8392, 0.8392))
                            } else {
                                Text::new("Click to reveal")
                                    .color(Color::from_rgb(0.8392, 0.8392, 0.8392))
                            })
                            .on_press(Message::ShowRouterId)
                            .style(|_theme: &Theme, _status| iced::widget::button::Style {
                                background: None,
                                text_color: Color::from_rgb8(77, 163, 255),
                                ..Default::default()
                            })
                            .padding(0),
                        )
                        .width(Length::Fill),
                )
                .push(
                    Row::new()
                        .push(
                            Text::new("IPv4 status").color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                        )
                        .push(Space::with_width(Length::Fill))
                        .push(Text::new("OK").color(Color::from_rgb(0.8392, 0.8392, 0.8392)))
                        .width(Length::Fill),
                )
                .push(
                    Row::new()
                        .push(
                            Text::new("IPv6 status").color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                        )
                        .push(Space::with_width(Length::Fill))
                        .push(Text::new("Disabled").color(Color::from_rgb(0.8392, 0.8392, 0.8392)))
                        .width(Length::Fill),
                )
                .push(
                    Row::new()
                        .push(Text::new("Uptime").color(Color::from_rgb(0.8392, 0.8392, 0.8392)))
                        .push(Space::with_width(Length::Fill))
                        .push({
                            let mut uptime = self.uptime.elapsed().as_secs();
                            if uptime == 0 {
                                uptime = 1;
                            }

                            Text::new(format!(
                                "{} h {} min {} s",
                                uptime / 60 / 60,
                                (uptime / 60) % 60,
                                uptime % 60,
                            ))
                            .color(Color::from_rgb(0.8392, 0.8392, 0.8392))
                        })
                        .width(Length::Fill),
                )
                .spacing(5)
                .width(Length::Fill),
        )
        .padding(10)
        .style(|_theme: &Theme| iced::widget::container::Style {
            border: Border {
                radius: Radius::from(12.0),
                width: 1.0,
                color: Color::from_rgb8(28, 36, 49),
            },
            background: Some(iced::Background::Color(Color::from_rgb8(28, 36, 49))),
            ..Default::default()
        });

        let bottom_section = row![
            container(services).width(Length::FillPortion(1)),
            container(network_info).width(Length::FillPortion(1))
        ]
        .spacing(10)
        .padding(5);

        let status_cards = row![
            container(network_status).width(Length::FillPortion(1)),
            container(routers).width(Length::FillPortion(1)),
            container(tunnels).width(Length::FillPortion(1)),
            container(tunnel_build_rate).width(Length::FillPortion(1)),
            container(bandwidth).width(Length::FillPortion(1)),
        ]
        .spacing(10)
        .padding(5);

        let graph = ChartWidget::new(self);
        let bandwidth_graph = Container::new(
            Column::new()
                .spacing(10)
                .push(
                    Container::new(Text::new("Bandwidth usage").size(20).color(Color::WHITE))
                        .center_x(Length::Fill),
                )
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

        column![title, status_cards, bandwidth_graph, bottom_section]
            .spacing(15)
            .padding(20)
            .into()
    }
}
