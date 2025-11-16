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

use std::net::Ipv4Addr;

use crate::ui::native::{types::Message, RouterUi};

use iced::{
    advanced::widget::Text,
    border::Radius,
    widget::{Checkbox, Column, Container, TextInput},
    Background, Border, Color, Theme,
};

#[derive(Debug, Clone)]
pub struct TransportConfig {
    port: Option<String>,
    host: Option<String>,
    publish: Option<bool>,
    enabled: bool,
}

impl TransportConfig {
    fn port(&self) -> &str {
        self.port.as_ref().map_or("", |port| port.as_str())
    }

    fn host(&self) -> &str {
        self.host.as_ref().map_or("", |host| host.as_str())
    }

    fn published(&self) -> bool {
        self.publish.unwrap_or(false)
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

    pub fn set_published(&mut self, published: bool) {
        self.publish = Some(published);
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl TryInto<Option<crate::config::Ntcp2Config>> for TransportConfig {
    type Error = String;

    fn try_into(self) -> Result<Option<crate::config::Ntcp2Config>, Self::Error> {
        if !self.enabled {
            return Ok(None);
        }

        Ok(Some(crate::config::Ntcp2Config {
            port: match self.port {
                Some(port) =>
                    port.parse::<u16>().map_err(|_| String::from("Invalid NTCP2 port"))?,
                None => 0,
            },
            host: self
                .host
                .as_ref()
                .map(|s| {
                    s.parse::<Ipv4Addr>().map_err(|_| String::from("Invalid NTCP2 IPv4 address"))
                })
                .transpose()?,
            publish: self.publish,
        }))
    }
}

impl From<&Option<crate::config::Ntcp2Config>> for TransportConfig {
    fn from(value: &Option<crate::config::Ntcp2Config>) -> Self {
        match value {
            Some(value) => Self {
                port: Some(value.port.to_string()),
                host: value.host.map(|address| address.to_string()),
                publish: value.publish,
                enabled: true,
            },
            None => Self {
                port: None,
                host: None,
                publish: None,
                enabled: false,
            },
        }
    }
}

impl TryInto<Option<crate::config::Ssu2Config>> for TransportConfig {
    type Error = String;

    fn try_into(self) -> Result<Option<crate::config::Ssu2Config>, Self::Error> {
        if !self.enabled {
            return Ok(None);
        }

        Ok(Some(crate::config::Ssu2Config {
            port: match self.port {
                Some(port) => port.parse::<u16>().map_err(|_| String::from("Invalid SSU2 port"))?,
                None => 0,
            },
            host: self
                .host
                .as_ref()
                .map(|s| {
                    s.parse::<Ipv4Addr>().map_err(|_| String::from("Invalid SSU2 IPv4 address"))
                })
                .transpose()?,
            publish: self.publish,
        }))
    }
}

impl From<&Option<crate::config::Ssu2Config>> for TransportConfig {
    fn from(value: &Option<crate::config::Ssu2Config>) -> Self {
        match value {
            Some(value) => Self {
                port: Some(value.port.to_string()),
                host: value.host.map(|address| address.to_string()),
                publish: value.publish,
                enabled: true,
            },
            None => Self {
                port: None,
                host: None,
                publish: None,
                enabled: false,
            },
        }
    }
}

#[derive(Clone)]
pub struct PortForwardingConfig {
    pub nat_pmp: bool,
    pub upnp: bool,
}

impl TryInto<Option<crate::config::PortForwardingConfig>> for PortForwardingConfig {
    type Error = String;

    fn try_into(self) -> Result<Option<crate::config::PortForwardingConfig>, Self::Error> {
        if !self.nat_pmp && !self.upnp {
            return Ok(None);
        }

        Ok(Some(crate::config::PortForwardingConfig {
            nat_pmp: self.nat_pmp,
            upnp: self.upnp,
            name: String::from("emissary"),
        }))
    }
}

impl From<&Option<crate::config::PortForwardingConfig>> for PortForwardingConfig {
    fn from(value: &Option<crate::config::PortForwardingConfig>) -> Self {
        match value {
            Some(value) => Self {
                nat_pmp: value.nat_pmp,
                upnp: value.upnp,
            },
            None => Self {
                nat_pmp: false,
                upnp: false,
            },
        }
    }
}

impl RouterUi {
    pub fn transport_settings<'a>(&self, mut settings: Column<'a, Message>) -> Column<'a, Message> {
        let ntcp2_port = self.ntcp2.port();
        let ntcp2_host = self.ntcp2.host();
        let ntcp2_published = self.ntcp2.published();

        let ntcp2 = Container::new(
            Column::new()
                .push(Text::new("NTCP2"))
                .push(Text::new("Port").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Port", ntcp2_port)
                        .size(15)
                        .on_input(Message::Ntcp2PortChanged)
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
                    TextInput::new("Host", ntcp2_host)
                        .size(15)
                        .on_input(Message::Ntcp2HostChanged)
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
                    Checkbox::new("Publish", ntcp2_published)
                        .size(15)
                        .on_toggle(Message::Ntcp2Published)
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
                .push(
                    Checkbox::new("Enable", self.ntcp2.enabled())
                        .size(15)
                        .on_toggle(Message::Ntcp2Enabled)
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

        let ssu2_port = self.ssu2.port();
        let ssu2_host = self.ssu2.host();
        let ssu2_published = self.ssu2.published();

        let ssu2 = Container::new(
            Column::new()
                .push(Text::new("SSU2"))
                .push(Text::new("Port").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("Port", ssu2_port)
                        .size(15)
                        .on_input(Message::Ssu2PortChanged)
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
                    TextInput::new("Host", ssu2_host)
                        .size(15)
                        .on_input(Message::Ssu2HostChanged)
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
                    Checkbox::new("Publish", ssu2_published)
                        .text_size(15)
                        .on_toggle(Message::Ssu2Published)
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
                .push(
                    Checkbox::new("Enable", self.ssu2.enabled())
                        .text_size(15)
                        .on_toggle(Message::Ssu2Enabled)
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

        let port_forwarding = Container::new(
            Column::new()
                .push(Text::new("Port forwarding"))
                .push(
                    Checkbox::new("NAT-PMP", self.port_forwarding.nat_pmp)
                        .text_size(15)
                        .on_toggle(Message::NatPmpEnabled)
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
                .push(
                    Checkbox::new("UPnP", self.port_forwarding.upnp)
                        .text_size(15)
                        .on_toggle(Message::UpnpEnabled)
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

        settings = settings.push(ntcp2);
        settings = settings.push(ssu2);
        settings = settings.push(port_forwarding);
        settings
    }
}
