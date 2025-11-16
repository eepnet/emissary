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
    types::{HiddenServiceStatus, Message},
    utils::read_b32_address,
    RouterUi,
};

use iced::{
    advanced::widget::Text,
    widget::{column, Column, Container},
    Color, Element,
};

mod client;
mod overview;
mod server;

pub struct HiddenService {
    pub port: String,
    pub path: String,
    pub address: String,
}

pub struct ClientTunnel {
    pub address: String,
    pub port: String,
    pub destination: String,
    pub destination_port: String,
}

impl RouterUi {
    pub fn hidden_services(&self) -> Element<'_, Message> {
        let title = Container::new(
            Column::new()
                .push(Text::new("Hidden services and client tunnels").size(24).color(Color::WHITE))
                .push(
                    Text::new("Configure hidden services and client tunnels")
                        .size(16)
                        .color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                )
                .spacing(5),
        );

        let content = column![title];

        let content = match self.service_status {
            HiddenServiceStatus::Idle => self.hidden_service_overview(content),
            HiddenServiceStatus::CreateServer(ref error) => self.create_server(content, error),
            HiddenServiceStatus::EditServer(ref error) => self.edit_server(content, error),
            HiddenServiceStatus::CreateClient(ref error) => self.create_client(content, error),
            HiddenServiceStatus::EditClient(ref error) => self.edit_client(content, error),
        };

        content.spacing(15).padding(20).into()
    }

    pub fn save_server(&mut self) -> Result<String, String> {
        if self.server_port.parse::<u16>().is_err() {
            return Err(String::from("Invalid port"));
        }

        match read_b32_address(&self.server_path) {
            Some(address) => Ok(format!("{address}.b32.i2p")),
            None => Ok(String::from("Key file does not exist")),
        }
    }

    pub fn save_edit_server(&mut self) -> Result<String, String> {
        if self.edit_server_port.parse::<u16>().is_err() {
            return Err(String::from("Invalid port"));
        }

        match read_b32_address(&self.edit_server_path) {
            Some(address) => Ok(format!("{address}.b32.i2p")),
            None => Ok(String::from("Key file does not exist")),
        }
    }

    pub fn save_client(&mut self) -> Result<(), String> {
        if self.client_port.parse::<u16>().is_err() {
            return Err(String::from("Invalid local port"));
        }

        if self.client_destination_port.parse::<u16>().is_err() {
            return Err(String::from("Invalid destination port"));
        }

        if !self.client_destination.ends_with(".i2p") {
            return Err(String::from(
                "Destination must be a .i2p or .b32.i2p address",
            ));
        }

        Ok(())
    }

    pub fn save_edit_client(&mut self) -> Result<(), String> {
        if self.edit_client_port.parse::<u16>().is_err() {
            return Err(String::from("Invalid local port"));
        }

        if self.edit_client_destination_port.parse::<u16>().is_err() {
            return Err(String::from("Invalid destination port"));
        }

        if !self.edit_client_destination.ends_with(".i2p") {
            return Err(String::from(
                "Destination must be a .i2p or .b32.i2p address",
            ));
        }

        Ok(())
    }

    pub fn export_hidden_services(&self) -> Option<Vec<crate::config::ServerTunnelConfig>> {
        if self.hidden_services.is_empty() {
            return None;
        }

        Some(
            self.hidden_services
                .iter()
                .map(|(name, service)| crate::config::ServerTunnelConfig {
                    name: name.clone(),
                    port: service.port.parse::<u16>().expect("to succeed"),
                    destination_path: service.path.clone(),
                })
                .collect(),
        )
    }

    pub fn export_client_tunnels(&self) -> Option<Vec<crate::config::ClientTunnelConfig>> {
        if self.client_tunnels.is_empty() {
            return None;
        }

        Some(
            self.client_tunnels
                .iter()
                .map(|(name, tunnel)| crate::config::ClientTunnelConfig {
                    name: name.clone(),
                    address: Some(tunnel.address.clone()),
                    port: tunnel.port.parse::<u16>().expect("to succeed"),
                    destination: tunnel.destination.clone(),
                    destination_port: Some(
                        tunnel.destination_port.parse::<u16>().expect("to succeed"),
                    ),
                })
                .collect(),
        )
    }
}
