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
    widget::{Checkbox, Column, Container, TextInput},
    Background, Border, Color, Theme,
};

#[derive(Clone)]
pub struct I2cpConfig {
    port: Option<String>,
    host: Option<String>,
    enabled: bool,
}

impl I2cpConfig {
    fn port(&self) -> &str {
        self.port.as_ref().map_or("", |port| port.as_str())
    }

    fn host(&self) -> &str {
        self.host.as_ref().map_or("", |host| host.as_str())
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_port(&mut self, port: String) {
        self.port = Some(port);
    }

    pub fn set_host(&mut self, host: String) {
        self.host = Some(host);
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl From<&Option<crate::config::I2cpConfig>> for I2cpConfig {
    fn from(value: &Option<crate::config::I2cpConfig>) -> Self {
        match value {
            Some(config) => Self {
                port: Some(config.port.to_string()),
                host: config.host.clone(),
                enabled: true,
            },
            None => Self {
                port: None,
                host: None,
                enabled: false,
            },
        }
    }
}

impl TryInto<Option<crate::config::I2cpConfig>> for I2cpConfig {
    type Error = String;

    fn try_into(self) -> Result<Option<crate::config::I2cpConfig>, Self::Error> {
        if !self.enabled {
            return Ok(None);
        }

        Ok(Some(crate::config::I2cpConfig {
            port: match self.port {
                Some(port) => port.parse::<u16>().map_err(|_| String::from("Invalid I2CP port"))?,
                None => 0,
            },
            host: self.host,
        }))
    }
}

#[derive(Clone)]
pub struct SamConfig {
    tcp_port: Option<String>,
    udp_port: Option<String>,
    host: Option<String>,
    enabled: bool,
}

impl SamConfig {
    fn tcp_port(&self) -> &str {
        self.tcp_port.as_ref().map_or("", |port| port.as_str())
    }

    fn udp_port(&self) -> &str {
        self.udp_port.as_ref().map_or("", |port| port.as_str())
    }

    fn host(&self) -> &str {
        self.host.as_ref().map_or("", |host| host.as_str())
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_tcp_port(&mut self, port: String) {
        self.tcp_port = Some(port);
    }

    pub fn set_udp_port(&mut self, port: String) {
        self.udp_port = Some(port);
    }

    pub fn set_host(&mut self, host: String) {
        self.host = Some(host);
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl From<&Option<crate::config::SamConfig>> for SamConfig {
    fn from(value: &Option<crate::config::SamConfig>) -> Self {
        match value {
            Some(config) => Self {
                tcp_port: Some(config.tcp_port.to_string()),
                udp_port: Some(config.udp_port.to_string()),
                host: config.host.clone(),
                enabled: true,
            },
            None => Self {
                tcp_port: None,
                udp_port: None,
                host: None,
                enabled: false,
            },
        }
    }
}

impl TryInto<Option<crate::config::SamConfig>> for SamConfig {
    type Error = String;

    fn try_into(self) -> Result<Option<crate::config::SamConfig>, Self::Error> {
        if !self.enabled {
            return Ok(None);
        }

        Ok(Some(crate::config::SamConfig {
            tcp_port: match self.tcp_port {
                Some(port) =>
                    port.parse::<u16>().map_err(|_| String::from("Invalid SAM TCP port"))?,
                None => 0,
            },
            udp_port: match self.udp_port {
                Some(port) =>
                    port.parse::<u16>().map_err(|_| String::from("Invalid SAM UDP port"))?,
                None => 0,
            },
            host: self.host,
        }))
    }
}

impl RouterUi {
    pub fn client_settings<'a>(&self, mut settings: Column<'a, Message>) -> Column<'a, Message> {
        let i2cp = Container::new(
            Column::new()
                .push(Text::new("I2CP"))
                .push(Text::new("Port").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Port", self.i2cp.port())
                        .size(15)
                        .on_input(Message::I2cpPortChanged)
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
                .push(Text::new("Host").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Host", self.i2cp.host())
                        .size(15)
                        .on_input(Message::I2cpHostChanged)
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
                    Checkbox::new("Enable", self.i2cp.enabled())
                        .size(15)
                        .on_toggle(Message::I2cpEnabled)
                        .style(|_theme: &Theme, status: _| iced::widget::checkbox::Style {
                            text_color: Some(Color::from_rgb8(0x9b, 0xa2, 0xae)),
                            background: match status {
                                iced::widget::checkbox::Status::Active { is_checked }
                                | iced::widget::checkbox::Status::Hovered { is_checked }
                                    if is_checked =>
                                    Background::Color(Color::from_rgb8(0x60, 0x82, 0xb6)),
                                _ => Background::Color(Color::from_rgb8(28, 36, 49)),
                            },
                            icon_color: Color::WHITE,
                            border: Border {
                                radius: Radius::from(1.0),
                                width: 1.0,
                                color: Color::from_rgb8(0x60, 0x82, 0xb6),
                            },
                        }),
                )
                .spacing(5),
        )
        .padding(10);

        let sam = Container::new(
            Column::new()
                .push(Text::new("SAMv3"))
                .push(Text::new("TCP port").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("7656", self.sam.tcp_port())
                        .size(15)
                        .on_input(Message::SamTcpPortChanged)
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
                .push(Text::new("UDP port").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("7655", self.sam.udp_port())
                        .size(15)
                        .on_input(Message::SamUdpPortChanged)
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
                .push(Text::new("Host").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Host", self.sam.host())
                        .size(15)
                        .on_input(Message::SamHostChanged)
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
                    Checkbox::new("Enable", self.sam.enabled())
                        .text_size(15)
                        .on_toggle(Message::SamEnabled)
                        .style(|_theme: &Theme, status: _| iced::widget::checkbox::Style {
                            text_color: Some(Color::from_rgb8(0x9b, 0xa2, 0xae)),
                            background: match status {
                                iced::widget::checkbox::Status::Active { is_checked }
                                | iced::widget::checkbox::Status::Hovered { is_checked }
                                    if is_checked =>
                                    Background::Color(Color::from_rgb8(0x60, 0x82, 0xb6)),
                                _ => Background::Color(Color::from_rgb8(28, 36, 49)),
                            },
                            icon_color: Color::WHITE,
                            border: Border {
                                radius: Radius::from(1.0),
                                width: 1.0,
                                color: Color::from_rgb8(0x60, 0x82, 0xb6),
                            },
                        }),
                )
                .spacing(10),
        )
        .padding(10);

        settings = settings.push(i2cp);
        settings = settings.push(sam);
        settings
    }
}
