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

use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Settings(SettingsTab),
    AddressBook(AddressBookTab),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsTab {
    Transports,
    Client,
    Proxies,
    Tunnels,
    Advanced,
}

impl From<SettingsTab> for Tab {
    fn from(value: SettingsTab) -> Self {
        Self::Settings(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressBookTab {
    Browse,
    AddDestination,
    Configure,
}

impl From<AddressBookTab> for Tab {
    fn from(value: AddressBookTab) -> Self {
        Self::AddressBook(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidebarMessage {
    Dashboard,
    AddressBook,
    Bandwidth,
    HiddenServices,
    Settings,
}

#[derive(Debug, Clone)]
pub enum TimeRange {
    Live,
    TenMin,
    OneHour,
    SixHours,
}

#[derive(Debug, Clone)]
pub enum Message {
    RangeSelected(TimeRange),
    SearchChanged(String),
    HostnameChanged(String),
    CopyToClipboard(Arc<str>),
    RemoveHost(Arc<str>),
    DestinationChanged(String),
    ButtonPressed(SidebarMessage),
    ShowRouterId,
    BanwidthKindToggled,
    ToggleInbound,
    ToggleOutbound,
    TabSelected(Tab),
    Tick,
    Ntcp2PortChanged(String),
    SubscriptionsChanged(String),
    SaveSubscriptions,
    Ntcp2HostChanged(String),
    Ntcp2Published(bool),
    Ntcp2Enabled(bool),
    Ssu2PortChanged(String),
    Ssu2HostChanged(String),
    Ssu2Published(bool),
    Ssu2Enabled(bool),
    NatPmpEnabled(bool),
    UpnpEnabled(bool),
    I2cpPortChanged(String),
    I2cpHostChanged(String),
    I2cpEnabled(bool),
    SamTcpPortChanged(String),
    SamUdpPortChanged(String),
    SamHostChanged(String),
    SamEnabled(bool),
    HttpPortChanged(String),
    HttpHostChanged(String),
    OutproxyChanged(String),
    HttpInboundLenChanged(String),
    HttpInboundCountChanged(String),
    HttpOutboundLenChanged(String),
    HttpOutboundCountChanged(String),
    HttpEnabled(bool),
    SocksPortChanged(String),
    SocksHostChanged(String),
    SocksEnabled(bool),
    FloodfillEnabled(bool),
    TransitTunnelCountChanged(String),
    TransitTunnelsEnabled(bool),
    ExploratoryInboundLengthChanged(String),
    ExploratoryInboundCountChanged(String),
    ExploratoryOutboundLengthChanged(String),
    ExploratoryOutboundCountChanged(String),
    SaveSettings,
    SaveDestination,
    LocalAddressesEnabled(bool),
    InsecureTunnelsEnabled(bool),
    CreateServer,
    CreateClient,
    CancelHiddenService,
    SaveServer,
    ServerNameChanged(String),
    ServerPortChanged(String),
    ServerPathChanged(String),
    RemoveHiddenService(String),
    EditHiddenService(String),
    EditServerNameChanged(String),
    EditServerPortChanged(String),
    EditServerPathChanged(String),
    SaveEditServer,
    SaveClient,
    RemoveClientTunnel(String),
    EditClientTunnel(String),
    SaveEditClient,
    ClientNameChanged(String),
    ClientAddressChanged(String),
    ClientPortChanged(String),
    ClientDestinationChanged(String),
    ClientDestinationPortChanged(String),
    EditClientNameChanged(String),
    EditClientAddressChanged(String),
    EditClientPortChanged(String),
    EditClientDestinationChanged(String),
    EditClientDestinationPortChanged(String),
    Shutdown,
}

pub enum SettingsStatus {
    Idle(SettingsTab),
    Saved(SettingsTab),
    Error(SettingsTab, String),
}

impl SettingsStatus {
    pub fn tab(&self) -> &SettingsTab {
        match self {
            Self::Idle(tab) => tab,
            Self::Saved(tab) => tab,
            Self::Error(tab, _) => tab,
        }
    }
}

pub enum AddDestinationStatus {
    Idle,
    Saved,
    Error(String),
}

pub enum SubscriptionStatus {
    Idle,
    Saved,
    Error(String),
}

pub enum HiddenServiceStatus {
    Idle,
    CreateServer(Option<String>),
    EditServer(Option<String>),
    CreateClient(Option<String>),
    EditClient(Option<String>),
}
