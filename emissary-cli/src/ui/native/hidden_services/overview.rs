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

use std::sync::Arc;

use crate::ui::native::{
    svg_util::{clipboard, delete, edit},
    types::Message,
    RouterUi,
};

use iced::{
    advanced::widget::Text,
    border::Radius,
    widget::{button, row, scrollable, svg, Column, Container},
    Border, Color, Length, Theme,
};

fn trim_name(s: &str) -> String {
    let s = s.strip_prefix("http://").unwrap_or(s);
    let s = s.strip_prefix("https://").unwrap_or(s);
    let s = s.strip_prefix("www").unwrap_or(s);

    let max_len = 50;
    if s.len() <= max_len {
        return s.to_string();
    }

    let ellipsis = "...";
    let keep = max_len - ellipsis.len();
    let front = keep / 2;
    let back = keep - front;

    format!("{}{}{}", &s[..front], ellipsis, &s[s.len() - back..])
}

impl RouterUi {
    pub fn hidden_service_overview<'a>(
        &'a self,
        mut content: Column<'a, Message>,
    ) -> Column<'a, Message> {
        let header = row![
            Text::new("Name").width(Length::FillPortion(2)),
            Text::new("Port").width(Length::FillPortion(1)),
            Text::new("Address").width(Length::FillPortion(3)),
            Text::new("Action").width(Length::FillPortion(1)),
        ];
        let mut server_list = Column::new().spacing(5);

        for (name, hidden_service) in &self.hidden_services {
            server_list = server_list.push(row![
                Text::new(name)
                    .size(15)
                    .color(Color::from_rgb8(0x9b, 0xa2, 0xae))
                    .width(Length::FillPortion(2)),
                Text::new(&hidden_service.port)
                    .size(15)
                    .color(Color::from_rgb8(0x9b, 0xa2, 0xae))
                    .width(Length::FillPortion(1)),
                Text::new(&hidden_service.address)
                    .size(15)
                    .color(Color::from_rgb8(0x9b, 0xa2, 0xae))
                    .width(Length::FillPortion(3)),
                row![
                    button(svg(clipboard::HANDLE.clone()).width(20))
                        .on_press(Message::CopyToClipboard(Arc::from(
                            hidden_service.address.clone()
                        )))
                        .style(|_style: _, _status: _| {
                            iced::widget::button::Style {
                                background: None,
                                ..Default::default()
                            }
                        })
                        .padding(3),
                    button(svg(edit::HANDLE.clone()).width(20))
                        .on_press(Message::EditHiddenService(name.clone()))
                        .style(|_style: _, _status: _| {
                            iced::widget::button::Style {
                                background: None,
                                ..Default::default()
                            }
                        })
                        .padding(3),
                    button(svg(delete::HANDLE.clone()).width(20))
                        .on_press(Message::RemoveHiddenService(name.clone()))
                        .style(|_style: _, _status: _| {
                            iced::widget::button::Style {
                                background: None,
                                ..Default::default()
                            }
                        })
                        .padding(3),
                ]
                .width(Length::FillPortion(1))
            ]);
        }

        let hidden_services = Container::new(
            Column::new()
                .push(row![Text::new("Hidden services").size(18)])
                .push(header)
                .push(
                    Container::new(scrollable(server_list).height(Length::Shrink)).max_height(200),
                )
                .push(button("Create").on_press(Message::CreateServer))
                .spacing(5),
        )
        .padding(10)
        .height(Length::Shrink)
        .max_height(350)
        .style(|_theme: &Theme| iced::widget::container::Style {
            border: Border {
                radius: Radius::from(12.0),
                width: 1.0,
                color: Color::from_rgb8(28, 36, 49),
            },
            background: Some(iced::Background::Color(Color::from_rgb8(28, 36, 49))),
            ..Default::default()
        });

        // client tunnels
        let header = row![
            Text::new("Name").width(Length::FillPortion(2)),
            Text::new("Address").width(Length::FillPortion(1)),
            Text::new("Port").width(Length::FillPortion(1)),
            Text::new("Destination").width(Length::FillPortion(3)),
            Text::new("Destination port").width(Length::FillPortion(1)),
            Text::new("Action").width(Length::FillPortion(1)),
        ];
        let mut client_list = Column::new().spacing(5);

        for (name, client_tunnel) in &self.client_tunnels {
            let destination_name = trim_name(&client_tunnel.destination);

            client_list = client_list.push(row![
                Text::new(name)
                    .size(15)
                    .color(Color::from_rgb8(0x9b, 0xa2, 0xae))
                    .width(Length::FillPortion(2)),
                Text::new(&client_tunnel.address)
                    .size(15)
                    .color(Color::from_rgb8(0x9b, 0xa2, 0xae))
                    .width(Length::FillPortion(1)),
                Text::new(&client_tunnel.port)
                    .size(15)
                    .color(Color::from_rgb8(0x9b, 0xa2, 0xae))
                    .width(Length::FillPortion(1)),
                Text::new(destination_name)
                    .size(15)
                    .color(Color::from_rgb8(0x9b, 0xa2, 0xae))
                    .width(Length::FillPortion(3)),
                Text::new(&client_tunnel.destination_port)
                    .size(15)
                    .color(Color::from_rgb8(0x9b, 0xa2, 0xae))
                    .width(Length::FillPortion(1)),
                row![
                    button(svg(edit::HANDLE.clone()).width(20))
                        .on_press(Message::EditClientTunnel(name.clone()))
                        .style(|_style: _, _status: _| {
                            iced::widget::button::Style {
                                background: None,
                                ..Default::default()
                            }
                        })
                        .padding(3),
                    button(svg(delete::HANDLE.clone()).width(20))
                        .on_press(Message::RemoveClientTunnel(name.clone()))
                        .style(|_style: _, _status: _| {
                            iced::widget::button::Style {
                                background: None,
                                ..Default::default()
                            }
                        })
                        .padding(3),
                ]
                .width(Length::FillPortion(1))
            ]);
        }

        let client_tunnels = Container::new(
            Column::new()
                .push(row![Text::new("Client tunnels").size(18)])
                .push(header)
                .push(
                    Container::new(scrollable(client_list).height(Length::Shrink)).max_height(200),
                )
                .push(button("Create").on_press(Message::CreateClient))
                .spacing(5),
        )
        .padding(10)
        .height(Length::Shrink)
        .max_height(350)
        .style(|_theme: &Theme| iced::widget::container::Style {
            border: Border {
                radius: Radius::from(12.0),
                width: 1.0,
                color: Color::from_rgb8(28, 36, 49),
            },
            background: Some(iced::Background::Color(Color::from_rgb8(28, 36, 49))),
            ..Default::default()
        });

        content = content.push(hidden_services);
        content = content.push(client_tunnels);

        content
    }
}
