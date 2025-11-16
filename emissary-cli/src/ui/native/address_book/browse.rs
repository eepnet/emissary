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
    svg_util::{clipboard, delete},
    types::Message,
    RouterUi,
};

use iced::{
    border::Radius,
    widget::{button, column, container, row, scrollable, svg, Column, Text, TextInput},
    Alignment, Border, Color, Length, Theme,
};

impl RouterUi {
    pub fn browse_address_book<'a>(&'a self, content: Column<'a, Message>) -> Column<'a, Message> {
        let title = Text::new("Browse destinations");
        let search_bar = TextInput::new("Search...", &self.search_term)
            .on_input(Message::SearchChanged)
            .padding(10)
            .size(15)
            .width(Length::Fill)
            .style(
                |_theme: &Theme, _status: _| iced::widget::text_input::Style {
                    border: Border {
                        radius: Radius::from(6.0),
                        width: 1.0,
                        color: Color::from_rgb8(28, 36, 49),
                    },
                    background: iced::Background::Color(iced::Color::from_rgb8(0x37, 0x41, 0x51)),
                    icon: Color::WHITE,
                    placeholder: Color::from_rgb8(0x9b, 0xa2, 0xae),
                    value: Color::from_rgb8(0xf3, 0xf3, 0xf2),
                    selection: Color::from_rgb8(0x9b, 0xa2, 0xae),
                },
            );

        let header = row![
            Text::new("Hostname").width(Length::FillPortion(2)),
            Text::new("Address").width(Length::FillPortion(4)),
            Text::new("Action").width(Length::FillPortion(1)),
        ];

        let mut list = Column::new().spacing(5);
        for (key, value) in &self.addresses {
            if !self.search_term.is_empty() && !key.contains(&self.search_term) {
                continue;
            }

            list = list.push(row![
                Text::new(&**key)
                    .size(15)
                    .color(Color::from_rgb8(0x9b, 0xa2, 0xae))
                    .width(Length::FillPortion(2)),
                Text::new(&**value)
                    .size(15)
                    .color(Color::from_rgb8(0x9b, 0xa2, 0xae))
                    .width(Length::FillPortion(4)),
                row![
                    button(svg(clipboard::HANDLE.clone()).width(20))
                        .on_press(Message::CopyToClipboard(value.clone()))
                        .style(|_style: _, _status: _| {
                            iced::widget::button::Style {
                                background: None,
                                ..Default::default()
                            }
                        })
                        .padding(3),
                    button(svg(delete::HANDLE.clone()).width(20))
                        .on_press(Message::RemoveHost(key.clone()))
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

        content.push(
            container(
                column![
                    title,
                    search_bar,
                    header,
                    scrollable(list).height(Length::Fill)
                ]
                .spacing(5)
                .align_x(Alignment::Start),
            )
            .padding(10),
        )
    }
}
