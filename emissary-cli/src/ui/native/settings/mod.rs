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
    svg_util::{
        advanced as advanced_icon, alt_route, handshake, settings, tunnels as tunnels_icon,
    },
    types::{Message, SettingsStatus, SettingsTab},
    utils::tab_button,
    RouterUi,
};

use iced::{
    advanced::widget::Text,
    border::Radius,
    widget::{button, column, row, scrollable, Column, Container},
    Border, Color, Element, Length, Theme,
};

pub mod advanced;
pub mod client;
pub mod proxies;
pub mod transports;
pub mod tunnels;

impl RouterUi {
    pub fn settings(&self) -> Element<'_, Message> {
        let title = Container::new(
            Column::new()
                .push(Text::new("Settings").size(24).color(Color::WHITE))
                .push(
                    Text::new("Configure your I2P router")
                        .size(16)
                        .color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                )
                .spacing(5),
        );

        let tabs = row![
            tab_button(
                SettingsTab::Transports,
                self.active_settings_tab,
                settings::HANDLE.clone(),
                "Transports"
            ),
            tab_button(
                SettingsTab::Client,
                self.active_settings_tab,
                handshake::HANDLE.clone(),
                "Clients"
            ),
            tab_button(
                SettingsTab::Proxies,
                self.active_settings_tab,
                alt_route::HANDLE.clone(),
                "Proxies"
            ),
            tab_button(
                SettingsTab::Tunnels,
                self.active_settings_tab,
                tunnels_icon::HANDLE.clone(),
                "Tunnels"
            ),
            tab_button(
                SettingsTab::Advanced,
                self.active_settings_tab,
                advanced_icon::HANDLE.clone(),
                "Advanced"
            ),
        ]
        .width(Length::Fill);

        let mut settings = column![tabs];
        match self.active_settings_tab {
            SettingsTab::Transports => {
                settings = self.transport_settings(settings);
            }
            SettingsTab::Client => {
                settings = self.client_settings(settings);
            }
            SettingsTab::Proxies => {
                settings = self.proxy_settings(settings);
            }
            SettingsTab::Tunnels => {
                settings = self.tunnel_settings(settings);
            }
            SettingsTab::Advanced => {
                settings = self.advanced_settings(settings);
            }
        }

        settings = settings
            .push(Container::new(button("Save").on_press(Message::SaveSettings)).padding(10));

        match self.settings_status {
            SettingsStatus::Idle(_) => {}
            SettingsStatus::Saved(_) => {
                settings = settings.push(
                    Container::new(
                        Text::new("Router configuration updated")
                            .color(Color::from_rgb8(0, 163, 108)),
                    )
                    .padding(10),
                );
            }
            SettingsStatus::Error(_, ref error) => {
                settings = settings.push(
                    Container::new(Text::new(error).color(Color::from_rgb8(0xe3, 0x42, 0x34)))
                        .padding(10),
                );
            }
        }

        // For some reason, scrollable only works here. Anywhere else and the save button on longer
        // pages (proxies) is hidden.
        let settings =
            Container::new(scrollable(settings))
                .padding(10)
                .height(750)
                .style(|_theme: &Theme| iced::widget::container::Style {
                    border: Border {
                        radius: Radius::from(12.0),
                        width: 1.0,
                        color: Color::from_rgb8(28, 36, 49),
                    },
                    background: Some(iced::Background::Color(Color::from_rgb8(28, 36, 49))),
                    ..Default::default()
                });

        column![title, settings].spacing(30).padding(20).into()
    }
}
