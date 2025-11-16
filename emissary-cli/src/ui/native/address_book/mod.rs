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

use crate::{
    config::AddressBookConfig,
    ui::native::{
        config::save_router_config,
        svg_util::{person_add, search, settings},
        types::{AddressBookTab, Message},
        utils::tab_button,
        RouterUi,
    },
};

use emissary_core::primitives::Destination;
use iced::{
    advanced::widget::Text,
    border::Radius,
    widget::{column, row, Column, Container},
    Border, Color, Element, Length, Theme,
};

use std::sync::Arc;

mod add_destination;
mod browse;
mod configure;

impl RouterUi {
    pub fn address_book(&self) -> Element<'_, Message> {
        let title = Container::new(
            Column::new()
                .push(Text::new("Address book").size(24).color(Color::WHITE))
                .push(
                    Text::new("Browse and configure your local address book")
                        .size(16)
                        .color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                )
                .spacing(5),
        );

        let tabs = row![
            tab_button(
                AddressBookTab::Browse,
                self.active_address_book_tab,
                search::HANDLE.clone(),
                "Browse"
            ),
            tab_button(
                AddressBookTab::AddDestination,
                self.active_address_book_tab,
                person_add::HANDLE.clone(),
                "Add destination"
            ),
            tab_button(
                AddressBookTab::Configure,
                self.active_address_book_tab,
                settings::HANDLE.clone(),
                "Configure"
            ),
        ]
        .width(Length::Fill);

        let mut content = column![tabs];
        match self.active_address_book_tab {
            AddressBookTab::Browse => {
                content = self.browse_address_book(content);
            }
            AddressBookTab::AddDestination => {
                content = self.add_destination(content);
            }
            AddressBookTab::Configure => {
                content = self.configure_address_book(content);
            }
        }

        let settings = Container::new(content).padding(10).height(750).style(|_theme: &Theme| {
            iced::widget::container::Style {
                border: Border {
                    radius: Radius::from(12.0),
                    width: 1.0,
                    color: Color::from_rgb8(28, 36, 49),
                },
                background: Some(iced::Background::Color(Color::from_rgb8(28, 36, 49))),
                ..Default::default()
            }
        });

        column![title, settings].spacing(30).padding(20).into()
    }

    pub fn save_destination(&mut self) -> Result<(), String> {
        if !self.hostname.ends_with(".i2p") {
            return Err(String::from("Hostname must end in .i2p"));
        }

        if self.destination.is_empty() {
            return Err(String::from("Destination/Base32 address not specified"));
        }

        let destination = &self.destination;
        let destination = destination.strip_prefix("http://").unwrap_or(destination);
        let destination = destination.strip_prefix("https://").unwrap_or(destination);
        let destination = destination.strip_prefix("www.").unwrap_or(destination);
        let destination = destination.strip_suffix(".b32.i2p").unwrap_or(destination);

        match emissary_core::crypto::base64_decode(destination) {
            Some(destination) => match Destination::parse(&destination) {
                Ok(destination) =>
                    if let Some(handle) = &self.address_book_handle {
                        handle.add_base64(self.hostname.clone(), destination);
                    },
                Err(_) => {
                    return Err(String::from("Not a valid destination"));
                }
            },
            None => match emissary_core::crypto::base32_decode(destination) {
                Some(_) =>
                    if let Some(handle) = &self.address_book_handle {
                        handle.add_base32(self.hostname.clone(), destination.to_string());
                    },
                None =>
                    return Err(String::from(
                        "Invalid destination, failed to decode to base64/base32",
                    )),
            },
        }

        self.destination = String::from("");
        self.hostname = String::from("");

        Ok(())
    }

    pub fn remove_host(&mut self, data: Arc<str>) {
        self.addresses.remove(&data);

        if let Some(handle) = &self.address_book_handle {
            handle.remove(data.as_ref());
        }
    }

    pub fn save_subscriptions(&mut self) -> Result<(), String> {
        let subscriptions =
            self.subscriptions.split(",").map(ToOwned::to_owned).collect::<Vec<String>>();

        if !subscriptions.iter().all(|url| url.ends_with(".i2p/hosts.txt")) {
            return Err(String::from(
                "All URLs are not valid I2P subscription URLs\n\n\
                Example: http://host1.i2p/hosts.txt,http://host2.i2p/hosts.txt",
            ));
        }

        match self.config.address_book {
            None =>
                self.config.address_book = Some(AddressBookConfig {
                    default: None,
                    subscriptions: Some(subscriptions),
                }),
            Some(ref mut address_book) => {
                address_book.subscriptions = Some(subscriptions);
            }
        }

        save_router_config(self.base_path.join("router.toml"), &self.config);

        Ok(())
    }

    pub fn handle_destination_changed(&mut self) {
        // TODO: print information about the destination?
    }
}
