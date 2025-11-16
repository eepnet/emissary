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

use crate::ui::native::types::{Message, Tab};

use emissary_core::{
    crypto::{base32_encode, base64_decode},
    primitives::Destination,
};
use iced::{
    advanced::widget::Text,
    border::Radius,
    widget::{button, column, row, svg, Container, Space},
    Border, Color, Element, Length, Theme,
};

pub fn tab_button<T: Copy + PartialEq + Into<Tab>>(
    tab: T,
    active: T,
    handle: iced::widget::svg::Handle,
    label: &'static str,
) -> Element<'static, Message> {
    let icon = svg(handle).width(20).height(20);
    let content = row![icon, Space::with_width(8), Text::new(label)];
    let mut button = button(content).on_press(Message::TabSelected(tab.into()));

    if tab == active {
        button = button.style(|_theme: &Theme, _status| iced::widget::button::Style {
            background: None,
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(0.0),
            },
            text_color: Color::from_rgb8(51, 153, 255),
            ..Default::default()
        })
    } else {
        button = button.style(|_theme: &Theme, _status| iced::widget::button::Style {
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(0.0),
            },
            background: None,
            text_color: iced::Color::from_rgb8(180, 180, 180),
            ..Default::default()
        })
    }

    if tab == active {
        column![
            button,
            Container::new(Space::new(Length::Fill, 1)).style(|_theme: &Theme| {
                iced::widget::container::Style {
                    border: Border {
                        radius: Radius::from(12.0),
                        width: 1.0,
                        color: Color::from_rgb8(51, 153, 255),
                    },
                    background: Some(iced::Background::Color(Color::from_rgb8(51, 153, 255))),
                    ..Default::default()
                }
            })
        ]
        .into()
    } else {
        column![
            button,
            Container::new(Space::new(Length::Fill, 1)).style(|_theme: &Theme| {
                iced::widget::container::Style {
                    border: Border {
                        radius: Radius::from(12.0),
                        width: 1.0,
                        color: Color::WHITE,
                    },
                    background: Some(iced::Background::Color(Color::from_rgb8(51, 153, 255))),
                    ..Default::default()
                }
            })
        ]
        .into()
    }
}

pub fn read_b32_address(path: &str) -> Option<String> {
    let destination = std::fs::read_to_string(path).ok()?;
    let destination = base64_decode(&destination)?;
    let destination = Destination::parse(&destination).unwrap();
    Some(base32_encode(destination.id().to_vec()))
}
