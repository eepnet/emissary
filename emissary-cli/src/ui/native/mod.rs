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
    config::Theme as RouterTheme,
    ui::{calculate_bandwidth, Status},
};

use emissary_core::events::{Event, EventSubscriber};
use iced::{
    time,
    widget::{button, column, container, row, toggler, Column, Text},
    Alignment, Element, Length, Subscription, Task, Theme,
};
use tokio::sync::mpsc::Sender;

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
enum View {
    Overview,
    Destinations,
    Settings,
}

#[derive(Debug, Clone)]
enum Message {
    ButtonPressed(View),
    ThemeToggled(bool),
    CopyToClipboard(String),
    GracefulShutdown,
    ForcefulShutdown,
    Tick,
}

/// Router UI.
pub struct RouterUi {
    /// Cumulative bandwidth of all transports.
    bandwidth: usize,

    /// Active client destinations.
    client_destinations: Vec<String>,

    /// Subscriber to events emitted by `emissary-core`.
    events: EventSubscriber,

    /// Has light mode been enabled.
    light_mode: bool,

    /// Total number of routers.
    num_routers: usize,

    /// Total number of transit tunnels.
    num_transit_tunnels: usize,

    /// How many tunnel builds have failed.
    num_tunnel_build_failures: usize,

    /// How many tunnels have been built.
    num_tunnels_built: usize,

    /// How often shoudl the UI be refreshed.
    refresh_interval: Duration,

    /// Active server destinations.
    server_destinations: Vec<(String, String)>,

    /// TX channel for sending a graceful shutdown signal to router.
    shutdown_tx: Sender<()>,

    /// Router status.
    status: Status,

    /// Cumulative bandwidth of all transit tunnels.
    transit_bandwidth: usize,

    /// Uptime.
    uptime: Instant,

    /// Current view.
    view: View,
}

impl RouterUi {
    fn new(
        events: EventSubscriber,
        light_mode: bool,
        refresh_interval: usize,
        shutdown_tx: Sender<()>,
    ) -> (Self, Task<Message>) {
        (
            RouterUi {
                bandwidth: 0usize,
                client_destinations: Vec::new(),
                events,
                light_mode,
                num_routers: 0usize,
                num_transit_tunnels: 0usize,
                num_tunnel_build_failures: 0usize,
                num_tunnels_built: 0usize,
                refresh_interval: if refresh_interval == 0 {
                    Duration::from_secs(10)
                } else {
                    Duration::from_secs(refresh_interval as u64)
                },
                server_destinations: Vec::new(),
                shutdown_tx,
                status: Status::Active,
                transit_bandwidth: 0usize,
                uptime: Instant::now(),
                view: View::Overview,
            },
            Task::none(),
        )
    }

    pub fn start(
        events: EventSubscriber,
        theme: RouterTheme,
        refresh_interval: usize,
        shutdown_tx: Sender<()>,
    ) -> anyhow::Result<()> {
        iced::application("emissary", RouterUi::update, RouterUi::view)
            .subscription(RouterUi::subscription)
            .theme(RouterUi::theme)
            .run_with(move || {
                RouterUi::new(
                    events,
                    std::matches!(theme, RouterTheme::Light),
                    refresh_interval,
                    shutdown_tx,
                )
            })
            .map_err(From::from)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => {
                while let Some(event) = self.events.router_status() {
                    match event {
                        Event::RouterStatus {
                            client_destinations,
                            server_destinations,
                            transit,
                            transport,
                            tunnel,
                        } => {
                            self.transit_bandwidth = transit.bandwidth;
                            self.num_transit_tunnels = transit.num_tunnels;
                            self.bandwidth = transport.bandwidth;
                            self.num_routers = transport.num_connected_routers;
                            self.server_destinations.extend(server_destinations);
                            self.client_destinations.extend(client_destinations);
                            self.num_tunnels_built = tunnel.num_tunnels_built;
                            self.num_tunnel_build_failures = tunnel.num_tunnel_build_failures;
                        }
                        Event::ShuttingDown =>
                            if let Status::Active = self.status {
                                self.status = Status::ShuttingDown(Instant::now());
                            },
                        Event::ShutDown => {}
                    }
                }

                Task::none()
            }
            Message::ButtonPressed(view) => {
                self.view = view;

                Task::none()
            }
            Message::ThemeToggled(value) => {
                self.light_mode = value;

                Task::none()
            }
            Message::GracefulShutdown => {
                self.status = Status::ShuttingDown(Instant::now());
                let _ = self.shutdown_tx.try_send(());

                Task::none()
            }
            Message::ForcefulShutdown => std::process::exit(0),
            Message::CopyToClipboard(address) => iced::clipboard::write(address),
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let sidebar = column![
            button("Overview").on_press(Message::ButtonPressed(View::Overview)),
            button("Destinations").on_press(Message::ButtonPressed(View::Destinations)),
            button("Settings").on_press(Message::ButtonPressed(View::Settings)),
        ]
        .spacing(10)
        .padding(10)
        .align_x(Alignment::Start);

        let main_content = match self.view {
            View::Overview => {
                let mut uptime = self.uptime.elapsed().as_secs();
                if uptime == 0 {
                    uptime = 1;
                }

                let status_text = Text::new(format!("Status: {}", self.status));

                let uptime_text = Text::new(format!(
                    "Uptime: {} h {} min {} s",
                    uptime / 60 / 60,
                    (uptime / 60) % 60,
                    uptime % 60,
                ));
                let total_bandwidth_text = {
                    let (total, total_unit) = calculate_bandwidth(self.bandwidth as f64);
                    let (per_second, per_second_unit) =
                        calculate_bandwidth(self.bandwidth as f64 / uptime as f64);

                    Text::new(format!(
                        "Total bandwidth: {total:.2} {total_unit} ({per_second:.2} {per_second_unit}/s)",
                    ))
                };
                let num_connected_text =
                    Text::new(format!("Number of connected routers: {}", self.num_routers));
                let tunnel_build_success_rate_text = {
                    if self.num_tunnels_built == 0 && self.num_tunnel_build_failures == 0 {
                        Text::new("Tunnel build success rate: 0%".to_string())
                    } else {
                        Text::new(format!(
                            "Tunnel build success rate: {}%",
                            ((self.num_tunnels_built as f64
                                / ((self.num_tunnels_built + self.num_tunnel_build_failures)
                                    as f64))
                                * 100f64) as usize
                        ))
                    }
                };
                let num_transit_tunnels_text =
                    Text::new(format!("Transit tunnels: {}", self.num_transit_tunnels));
                let transit_bandwidth_text = {
                    let (total, total_unit) = calculate_bandwidth(self.transit_bandwidth as f64);
                    let (per_second, per_second_unit) =
                        calculate_bandwidth(self.transit_bandwidth as f64 / uptime as f64);

                    Text::new(format!(
                        "Transit bandwidth: {total:.2} {total_unit} ({per_second:.2} {per_second_unit}/s)",
                    ))
                };

                column![
                    Text::new("Overview").size(36),
                    uptime_text,
                    status_text,
                    total_bandwidth_text,
                    num_connected_text,
                    tunnel_build_success_rate_text,
                    num_transit_tunnels_text,
                    transit_bandwidth_text,
                    row![
                        match self.status {
                            Status::Active =>
                                button("Graceful shutdown").on_press(Message::GracefulShutdown),
                            Status::ShuttingDown(_) =>
                                button("Graceful shutdown").style(|theme, _| {
                                    iced::widget::button::primary(theme, button::Status::Disabled)
                                }),
                        },
                        button("Forceful shutdown")
                            .style(iced::widget::button::danger)
                            .on_press(Message::ForcefulShutdown),
                    ]
                    .spacing(10)
                ]
                .spacing(20)
                .padding(30)
                .align_x(Alignment::Start)
            }
            View::Destinations => {
                let mut test = Vec::new();

                test.push(Text::new("Server destinations").size(36).into());

                for (name, address) in &self.server_destinations {
                    test.push(
                        row![
                            Text::new(format!("{name}: http://{address}.b32.i2p")),
                            button("Copy to clipboard").on_press(Message::CopyToClipboard(
                                format!("http://{address}.b32.i2p")
                            ))
                        ]
                        .spacing(10)
                        .into(),
                    );
                }

                test.push(Text::new("Client destinations").size(36).into());

                for name in &self.client_destinations {
                    test.push(Text::new(name.to_string()).into());
                }

                Column::from_vec(test).spacing(20).padding(30).align_x(Alignment::Start)
            }
            View::Settings => column![
                Text::new("Settings").size(36),
                toggler(self.light_mode)
                    .label("Light mode")
                    .on_toggle(Message::ThemeToggled)
                    .spacing(10)
            ]
            .spacing(20)
            .padding(30)
            .align_x(Alignment::Start),
        };

        let content_container = container(main_content).padding(20).width(Length::FillPortion(3));

        let layout = row![sidebar, content_container]
            .height(Length::Fill)
            .width(Length::Fill)
            .spacing(10);

        container(layout).height(Length::Fill).width(Length::Fill).into()
    }

    fn subscription(&self) -> Subscription<Message> {
        time::every(self.refresh_interval).map(|_| Message::Tick)
    }

    fn theme(&self) -> Theme {
        if self.light_mode {
            Theme::Light
        } else {
            Theme::Dark
        }
    }
}
