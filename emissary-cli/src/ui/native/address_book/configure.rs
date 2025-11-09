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
    types::{Message, SubscriptionStatus},
    RouterUi,
};

use iced::{
    advanced::widget::Text,
    border::Radius,
    widget::{button, Column, Container, TextInput},
    Border, Color, Theme,
};

impl RouterUi {
    pub fn configure_address_book<'a>(
        &'a self,
        mut content: Column<'a, Message>,
    ) -> Column<'a, Message> {
        let subscriptions = Container::new(
            Column::new()
                .push(Text::new("Modify subscriptions"))
                .push(Text::new("Subscriptions").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Comma-separated list of subscriptions", &self.subscriptions)
                        .size(15)
                        .on_input(Message::SubscriptionsChanged)
                        .padding(10)
                        .style(
                            |_theme: &Theme, _status: _| iced::widget::text_input::Style {
                                border: Border {
                                    radius: Radius::from(6.0),
                                    width: 1.0,
                                    color: Color::from_rgb8(28, 36, 49),
                                },
                                background: iced::Background::Color(iced::Color::from_rgb8(
                                    0x37, 0x41, 0x51,
                                )),
                                icon: Color::WHITE,
                                placeholder: Color::from_rgb8(0x9b, 0xa2, 0xae),
                                value: Color::from_rgb8(0xf3, 0xf3, 0xf2),
                                selection: Color::from_rgb8(0x9b, 0xa2, 0xae),
                            },
                        ),
                )
                .spacing(5),
        )
        .padding(10);

        content = content.push(subscriptions);

        match &self.subscription_status {
            SubscriptionStatus::Idle => {}
            SubscriptionStatus::Saved => {
                content = content.push(
                    Container::new(
                        Text::new("Subscriptions saved").color(Color::from_rgb8(0, 163, 108)),
                    )
                    .padding(10),
                );
            }
            SubscriptionStatus::Error(error) => {
                content = content.push(
                    Container::new(Text::new(error).color(Color::from_rgb8(0xe3, 0x42, 0x34)))
                        .padding(10),
                );
            }
        }

        content = content
            .push(Container::new(button("Save").on_press(Message::SaveSubscriptions)).padding(10));
        content
    }
}
