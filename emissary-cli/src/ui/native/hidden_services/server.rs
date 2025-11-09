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

use crate::ui::native::{types::Message, RouterUi};

use iced::{
    advanced::widget::Text,
    border::Radius,
    widget::{button, row, Column, Container, TextInput},
    Border, Color, Length, Theme,
};

impl RouterUi {
    pub fn create_server<'a>(
        &'a self,
        mut content: Column<'a, Message>,
        error: &'a Option<String>,
    ) -> Column<'a, Message> {
        let server_info = Container::new(
            Column::new()
                .push(Text::new("Name").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Name", &self.server_name)
                        .size(15)
                        .on_input(Message::ServerNameChanged)
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
                .push(Text::new("Port").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Port", &self.server_port)
                        .size(15)
                        .on_input(Message::ServerPortChanged)
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
                .push(
                    Text::new("Destination path")
                        .size(15)
                        .color(Color::from_rgb8(0x9b, 0xa2, 0xae)),
                )
                .push(
                    TextInput::new("Path", &self.server_path)
                        .size(15)
                        .on_input(Message::ServerPathChanged)
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
        );

        let mut inner_content = Column::new()
            .push(row![Text::new("Create a hidden service").size(18)])
            .push(server_info);

        if let Some(error) = error {
            inner_content = inner_content.push(Container::new(
                Text::new(error).color(Color::from_rgb8(0xe3, 0x42, 0x34)),
            ));
        }

        let add_server = Container::new(
            inner_content.spacing(5).push(
                row![
                    button("Save").on_press(Message::SaveServer),
                    button("Cancel").on_press(Message::CancelHiddenService)
                ]
                .spacing(5),
            ),
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

        content = content.push(add_server);
        content
    }

    pub fn edit_server<'a>(
        &'a self,
        mut content: Column<'a, Message>,
        error: &'a Option<String>,
    ) -> Column<'a, Message> {
        let server_info = Container::new(
            Column::new()
                .push(Text::new("Name").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Name", &self.edit_server_name)
                        .size(15)
                        .on_input(Message::EditServerNameChanged)
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
                .push(Text::new("Port").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Port", &self.edit_server_port)
                        .size(15)
                        .on_input(Message::EditServerPortChanged)
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
                .push(
                    Text::new("Destination path")
                        .size(15)
                        .color(Color::from_rgb8(0x9b, 0xa2, 0xae)),
                )
                .push(
                    TextInput::new("Path", &self.edit_server_path)
                        .size(15)
                        .on_input(Message::EditServerPathChanged)
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
        );

        let mut inner_content = Column::new()
            .push(row![Text::new("Edit a hidden service").size(18)])
            .push(server_info);

        if let Some(error) = error {
            inner_content = inner_content.push(Container::new(
                Text::new(error).color(Color::from_rgb8(0xe3, 0x42, 0x34)),
            ));
        }

        let add_server = Container::new(
            inner_content.spacing(5).push(
                row![
                    button("Save").on_press(Message::SaveEditServer),
                    button("Cancel").on_press(Message::CancelHiddenService)
                ]
                .spacing(5),
            ),
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

        content = content.push(add_server);
        content
    }
}
