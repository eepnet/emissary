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
use std::num::NonZeroUsize;

use iced::{
    advanced::widget::Text,
    border::Radius,
    widget::{Checkbox, Column, Container, TextInput},
    Background, Border, Color, Theme,
};

#[derive(Clone)]
pub struct ExploratoryConfig {
    inbound_len: Option<String>,
    inbound_count: Option<String>,
    outbound_len: Option<String>,
    outbound_count: Option<String>,
}

impl ExploratoryConfig {
    fn inbound_len(&self) -> &str {
        self.inbound_len.as_ref().map_or("", |inbound_len| inbound_len.as_str())
    }

    fn inbound_count(&self) -> &str {
        self.inbound_count.as_ref().map_or("", |inbound_count| inbound_count.as_str())
    }

    fn outbound_len(&self) -> &str {
        self.outbound_len.as_ref().map_or("", |outbound_len| outbound_len.as_str())
    }

    fn outbound_count(&self) -> &str {
        self.outbound_count
            .as_ref()
            .map_or("", |outbound_count| outbound_count.as_str())
    }

    pub fn set_inbound_len(&mut self, inbound_len: String) {
        self.inbound_len = Some(inbound_len);
    }

    pub fn set_inbound_count(&mut self, inbound_count: String) {
        self.inbound_count = Some(inbound_count);
    }

    pub fn set_outbound_len(&mut self, outbound_len: String) {
        self.outbound_len = Some(outbound_len);
    }

    pub fn set_outbound_count(&mut self, outbound_count: String) {
        self.outbound_count = Some(outbound_count);
    }
}

impl TryInto<Option<crate::config::ExploratoryConfig>> for ExploratoryConfig {
    type Error = String;

    fn try_into(self) -> Result<Option<crate::config::ExploratoryConfig>, Self::Error> {
        // if all options are unspecified, don't create `[exploratory]` field in `router.toml`
        if self.inbound_len.is_none()
            && self.inbound_count.is_none()
            && self.outbound_len.is_none()
            && self.outbound_count.is_none()
        {
            return Ok(None);
        }

        Ok(Some(crate::config::ExploratoryConfig {
            inbound_len: self
                .inbound_len
                .and_then(|x| x.parse::<NonZeroUsize>().ok())
                .ok_or(String::from("Invalid inbound length"))?
                .into(),
            inbound_count: self
                .inbound_count
                .and_then(|x| x.parse::<NonZeroUsize>().ok())
                .ok_or(String::from("Invalid inbound count"))?
                .into(),
            outbound_len: self
                .outbound_len
                .and_then(|x| x.parse::<NonZeroUsize>().ok())
                .ok_or(String::from("Invalid outbound length"))?
                .into(),
            outbound_count: self
                .outbound_count
                .and_then(|x| x.parse::<NonZeroUsize>().ok())
                .ok_or(String::from("Invalid outbound count"))?
                .into(),
        }))
    }
}

impl From<&Option<crate::config::ExploratoryConfig>> for ExploratoryConfig {
    fn from(value: &Option<crate::config::ExploratoryConfig>) -> Self {
        let Some(value) = value else {
            return Self {
                inbound_len: None,
                inbound_count: None,
                outbound_len: None,
                outbound_count: None,
            };
        };

        Self {
            inbound_len: Some(value.inbound_len.to_string()),
            inbound_count: Some(value.inbound_count.to_string()),
            outbound_len: Some(value.outbound_len.to_string()),
            outbound_count: Some(value.outbound_count.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct TransitConfig {
    max_tunnels: Option<String>,
    enabled: bool,
}

impl TransitConfig {
    fn max_tunnels(&self) -> &str {
        self.max_tunnels.as_ref().map_or("", |max_tunnels| max_tunnels.as_str())
    }

    pub fn set_max_tunnels(&mut self, max_tunnels: String) {
        self.max_tunnels = Some(max_tunnels);
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl TryInto<Option<crate::config::TransitConfig>> for TransitConfig {
    type Error = String;

    fn try_into(self) -> Result<Option<crate::config::TransitConfig>, Self::Error> {
        if !self.enabled {
            return Ok(None);
        }

        Ok(Some(crate::config::TransitConfig {
            max_tunnels: self
                .max_tunnels
                .map(|max_tunnels| max_tunnels.parse::<usize>())
                .transpose()
                .map_err(|_| String::from("Invalid transit tunnel max count"))?,
        }))
    }
}

impl From<&Option<crate::config::TransitConfig>> for TransitConfig {
    fn from(value: &Option<crate::config::TransitConfig>) -> Self {
        let Some(value) = value else {
            return Self {
                max_tunnels: None,
                enabled: false,
            };
        };

        Self {
            max_tunnels: value.max_tunnels.map(|max_tunnels| max_tunnels.to_string()),
            enabled: true,
        }
    }
}

impl RouterUi {
    pub fn tunnel_settings<'a>(&self, mut settings: Column<'a, Message>) -> Column<'a, Message> {
        let exploratory = Container::new(
            Column::new()
                .push(Text::new("Exploratory tunnels"))
                .push(
                    Text::new("Inbound length").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)),
                )
                .push(
                    TextInput::new("3", self.exploratory.inbound_len())
                        .size(15)
                        .on_input(Message::ExploratoryInboundLengthChanged)
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
                .push(Text::new("Inbound count").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)))
                .push(
                    TextInput::new("2", self.exploratory.inbound_count())
                        .size(15)
                        .on_input(Message::ExploratoryInboundCountChanged)
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
                    Text::new("Outbound length").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)),
                )
                .push(
                    TextInput::new("3", self.exploratory.outbound_len())
                        .size(15)
                        .on_input(Message::ExploratoryOutboundLengthChanged)
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
                    Text::new("Outbound count").size(15).color(Color::from_rgb8(0x9b, 0xa2, 0xae)),
                )
                .push(
                    TextInput::new("2", self.exploratory.outbound_count())
                        .size(15)
                        .on_input(Message::ExploratoryOutboundCountChanged)
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

        let transit = Container::new(
            Column::new()
                .push(Text::new("Transit tunnels"))
                .push(
                    Text::new("Maximum number of transit tunnels")
                        .size(15)
                        .color(Color::from_rgb8(0x9b, 0xa2, 0xae)),
                )
                .push(
                    TextInput::new("5000", self.transit.max_tunnels())
                        .size(15)
                        .on_input(Message::TransitTunnelCountChanged)
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
                    Checkbox::new("Enable", self.transit.enabled())
                        .size(15)
                        .on_toggle(Message::TransitTunnelsEnabled)
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

        settings = settings.push(exploratory);
        settings = settings.push(transit);
        settings
    }
}
