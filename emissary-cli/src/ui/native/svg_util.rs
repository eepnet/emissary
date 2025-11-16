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

macro_rules! load_svg {
    ($name:ident, $path:literal) => {
        pub mod $name {
            use iced::widget::svg::Handle;
            use std::sync::LazyLock;

            const BYTES: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), $path));
            pub static HANDLE: LazyLock<Handle> = LazyLock::new(|| Handle::from_memory(BYTES));
        }
    };
}

load_svg!(address_book, "/assets/icons/address_book.svg");
load_svg!(advanced, "/assets/icons/advanced.svg");
load_svg!(alt_route, "/assets/icons/alt-route.svg");
load_svg!(bandwidth, "/assets/icons/bandwidth.svg");
load_svg!(clipboard, "/assets/icons/clipboard.svg");
load_svg!(dashboard, "/assets/icons/dashboard.svg");
load_svg!(delete, "/assets/icons/delete.svg");
load_svg!(download, "/assets/icons/download.svg");
load_svg!(edit, "/assets/icons/edit.svg");
load_svg!(handshake, "/assets/icons/handshake.svg");
load_svg!(network_status, "/assets/icons/network-status.svg");
load_svg!(peak_traffic, "/assets/icons/peak-traffic.svg");
load_svg!(person_add, "/assets/icons/person_add.svg");
load_svg!(power_off, "/assets/icons/power-off.svg");
load_svg!(routers, "/assets/icons/routers.svg");
load_svg!(search, "/assets/icons/search.svg");
load_svg!(server, "/assets/icons/server.svg");
load_svg!(settings, "/assets/icons/settings.svg");
load_svg!(tbsr, "/assets/icons/tbsr.svg");
load_svg!(tunnels, "/assets/icons/tunnels.svg");
load_svg!(upload, "/assets/icons/upload.svg");
