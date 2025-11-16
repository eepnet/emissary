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
    svg_util::{address_book, bandwidth, dashboard, power_off, server, settings},
    types::{Message, SidebarMessage},
};

use iced::{
    advanced::widget::Text,
    alignment::Horizontal,
    border::Radius,
    widget::{button, column, container, row, svg, Container, Row, Space},
    Background, Border, Color, Length, Theme,
};

pub fn sidebar<'a>(selected: Option<SidebarMessage>, active: bool) -> Container<'a, Message> {
    let items = vec![
        (
            SidebarMessage::Dashboard,
            dashboard::HANDLE.clone(),
            "Dashboard",
        ),
        (
            SidebarMessage::Bandwidth,
            bandwidth::HANDLE.clone(),
            "Bandwidth",
        ),
        (
            SidebarMessage::HiddenServices,
            server::HANDLE.clone(),
            "Hidden services",
        ),
        (
            SidebarMessage::AddressBook,
            address_book::HANDLE.clone(),
            "Address book",
        ),
        (
            SidebarMessage::Settings,
            settings::HANDLE.clone(),
            "Settings",
        ),
    ];

    let mut col = column![
        Container::new(Text::new("emissary").size(24).color(Color::WHITE))
            .width(Length::Fill)
            .align_x(Horizontal::Center),
    ]
    .spacing(5);

    for (msg, icon, label) in items.into_iter() {
        let is_selected = Some(msg) == selected;

        let content = Row::new()
            .push(svg(icon).content_fit(iced::ContentFit::Contain).width(25))
            .push(Text::new(label).color(Color::from_rgb(0.8392, 0.8392, 0.8392)))
            .spacing(10)
            .width(Length::Fill);

        let btn = button(content)
            .style(if is_selected {
                |_theme: &Theme, _status| iced::widget::button::Style {
                    background: Some(Background::Color(Color::from_rgb8(54, 40, 176))),
                    text_color: Color::from_rgb8(77, 163, 255),
                    border: Border {
                        color: Color::TRANSPARENT,
                        width: 0.0,
                        radius: Radius::from(5.0),
                    },
                    ..Default::default()
                }
            } else {
                |_theme: &Theme, _status| iced::widget::button::Style {
                    background: None,
                    text_color: Color::from_rgb8(77, 163, 255),
                    ..Default::default()
                }
            })
            .width(Length::Fill)
            .on_press(Message::ButtonPressed(msg));

        col = col.push(btn);
    }

    col = col.push(Space::new(Length::Fill, Length::Fill));

    let power_button = button(svg(power_off::HANDLE.clone()).width(30).height(30))
        .padding(5)
        .style(if active {
            |_theme: &Theme, _status| iced::widget::button::Style {
                background: Some(Background::Color(Color::from_rgb8(54, 40, 176))),
                text_color: Color::from_rgb8(77, 163, 255),
                border: Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: Radius::from(20.0),
                },
                ..Default::default()
            }
        } else {
            |_theme: &Theme, _status| iced::widget::button::Style {
                background: Some(Background::Color(Color::from_rgb8(211, 47, 47))),
                text_color: Color::from_rgb8(77, 163, 255),
                border: Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: Radius::from(20.0),
                },
                ..Default::default()
            }
        })
        .on_press(Message::Shutdown);

    col = col.push(
        row![
            Space::new(Length::Fill, 20),
            power_button,
            Space::new(Length::Fill, 20)
        ]
        .padding(10),
    );

    container(col)
        .height(Length::Fill)
        .style(|_theme: &Theme| iced::widget::container::Style {
            border: Border::default(),
            text_color: Some(Color::WHITE),
            background: Some(iced::Background::Color(Color::from_rgb8(28, 36, 49))),
            ..Default::default()
        })
}
