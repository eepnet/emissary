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
    widget::{column, Column, Container},
    Color, Element,
};

impl RouterUi {
    pub fn _network_status(&self) -> Element<'_, Message> {
        let title = Container::new(
            Column::new()
                .push(Text::new("Network status").size(24).color(Color::WHITE))
                .push(
                    Text::new("Monitor network connections and transit tunnels")
                        .size(16)
                        .color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                )
                .spacing(5),
        );

        column![title].spacing(30).padding(20).into()
    }
}
