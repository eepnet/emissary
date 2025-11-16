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
pub struct HttpProxyConfig {
    port: Option<String>,
    host: Option<String>,
    outproxy: Option<String>,
    enabled: bool,
}

impl HttpProxyConfig {
    fn port(&self) -> &str {
        self.port.as_ref().map_or("", |port| port.as_str())
    }

    fn host(&self) -> &str {
        self.host.as_ref().map_or("", |host| host.as_str())
    }

    fn outproxy(&self) -> &str {
        self.outproxy.as_ref().map_or("", |outproxy| outproxy.as_str())
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

    pub fn set_outproxy(&mut self, outproxy: String) {
        self.outproxy = Some(outproxy);
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl TryInto<Option<crate::config::HttpProxyConfig>> for HttpProxyConfig {
    type Error = String;

    fn try_into(self) -> Result<Option<crate::config::HttpProxyConfig>, Self::Error> {
        if !self.enabled {
            return Ok(None);
        }

        Ok(Some(crate::config::HttpProxyConfig {
            port: match self.port {
                Some(port) =>
                    port.parse::<u16>().map_err(|_| String::from("Invalid HTTP proxy port"))?,
                None => 0,
            },
            host: {
                let host = self.host.ok_or_else(|| String::from("Host missing for HTTP proxy"))?;

                if host.is_empty() {
                    return Err(String::from("Host missing for HTTP proxy"));
                }

                host
            },
            outproxy: self.outproxy,
        }))
    }
}

impl From<&Option<crate::config::HttpProxyConfig>> for HttpProxyConfig {
    fn from(value: &Option<crate::config::HttpProxyConfig>) -> Self {
        match value {
            Some(value) => Self {
                port: Some(value.port.to_string()),
                host: Some(value.host.clone()),
                outproxy: value.outproxy.clone(),
                enabled: true,
            },
            None => Self {
                port: None,
                host: None,
                outproxy: None,
                enabled: false,
            },
        }
    }
}

#[derive(Clone)]
pub struct SocksProxyConfig {
    port: Option<String>,
    host: Option<String>,
    enabled: bool,
}

impl SocksProxyConfig {
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

impl TryInto<Option<crate::config::SocksProxyConfig>> for SocksProxyConfig {
    type Error = String;

    fn try_into(self) -> Result<Option<crate::config::SocksProxyConfig>, Self::Error> {
        if !self.enabled {
            return Ok(None);
        }

        Ok(Some(crate::config::SocksProxyConfig {
            port: match self.port {
                Some(port) =>
                    port.parse::<u16>().map_err(|_| String::from("Invalid SOCKS proxy port"))?,
                None => 0,
            },
            host: {
                let host = self.host.ok_or_else(|| String::from("Host missing for SOCKS proxy"))?;

                if host.is_empty() {
                    return Err(String::from("Host missing for SOCKS proxy"));
                }

                host
            },
        }))
    }
}

impl From<&Option<crate::config::SocksProxyConfig>> for SocksProxyConfig {
    fn from(value: &Option<crate::config::SocksProxyConfig>) -> Self {
        match value {
            Some(value) => Self {
                port: Some(value.port.to_string()),
                host: Some(value.host.clone()),
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

impl RouterUi {
    pub fn proxy_settings<'a>(&self, mut settings: Column<'a, Message>) -> Column<'a, Message> {
        let http = Container::new(
            Column::new()
                .push(Text::new("HTTP"))
                .push(Text::new("Port").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Port", self.http_proxy.port())
                        .size(15)
                        .on_input(Message::HttpPortChanged)
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
                    TextInput::new("Host", self.http_proxy.host())
                        .size(15)
                        .on_input(Message::HttpHostChanged)
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
                .push(Text::new("Outproxy").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Outproxy", self.http_proxy.outproxy())
                        .size(15)
                        .on_input(Message::OutproxyChanged)
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
                    Checkbox::new("Enable", self.http_proxy.enabled())
                        .size(15)
                        .on_toggle(Message::HttpEnabled)
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

        let socks = Container::new(
            Column::new()
                .push(Text::new("SOCKSv5"))
                .push(Text::new("Port").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Port", self.socks_proxy.port())
                        .size(15)
                        .on_input(Message::SocksPortChanged)
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
                    TextInput::new("Host", self.socks_proxy.host())
                        .size(15)
                        .on_input(Message::SocksHostChanged)
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
                    Checkbox::new("Enable", self.socks_proxy.enabled())
                        .size(15)
                        .on_toggle(Message::SocksEnabled)
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

        settings = settings.push(http);
        settings = settings.push(socks);
        settings
    }
}
