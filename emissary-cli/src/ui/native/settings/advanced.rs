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
    widget::{Checkbox, Column, Container},
    Background, Border, Color, Theme,
};

pub struct AdvancedConfig {
    floodfill: bool,
    allow_local: bool,
    insecure_tunnels: bool,
}

impl AdvancedConfig {
    pub fn floodfill(&self) -> bool {
        self.floodfill
    }

    pub fn allow_local(&self) -> bool {
        self.allow_local
    }

    pub fn insecure_tunnels(&self) -> bool {
        self.insecure_tunnels
    }

    pub fn set_floodfill(&mut self, enabled: bool) {
        self.floodfill = enabled;
    }

    pub fn set_allow_local(&mut self, enabled: bool) {
        self.allow_local = enabled;
    }

    pub fn set_insecure_tunnels(&mut self, enabled: bool) {
        self.insecure_tunnels = enabled;
    }
}

impl From<&crate::config::EmissaryConfig> for AdvancedConfig {
    fn from(value: &crate::config::EmissaryConfig) -> Self {
        Self {
            floodfill: value.floodfill,
            allow_local: value.allow_local,
            insecure_tunnels: value.insecure_tunnels,
        }
    }
}

impl RouterUi {
    pub fn advanced_settings<'a>(&self, mut settings: Column<'a, Message>) -> Column<'a, Message> {
        let netdb = Container::new(
            Column::new()
                .push(Text::new("NetDB"))
                .push(
                    Checkbox::new("Run the router as floodfill", self.advanced.floodfill())
                        .size(15)
                        .on_toggle(Message::FloodfillEnabled)
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

        let development = Container::new(
            Column::new()
                .push(Text::new("Development"))
                .push(
                    Checkbox::new("Allow use of local addresses", self.advanced.allow_local())
                        .size(15)
                        .on_toggle(Message::LocalAddressesEnabled)
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
                    Checkbox::new("Enable insecure tunnels", self.advanced.insecure_tunnels())
                        .size(15)
                        .on_toggle(Message::InsecureTunnelsEnabled)
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

        settings = settings.push(netdb);
        settings = settings.push(development);
        settings
    }
}
