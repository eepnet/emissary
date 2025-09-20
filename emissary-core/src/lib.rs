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

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(test, allow(clippy::all))]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::manual_async_fn)]
#![allow(clippy::type_complexity)]
#![allow(clippy::enum_variant_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::new_ret_no_self)]
#![allow(clippy::module_inception)]
#![allow(clippy::option_map_unit_fn)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::should_implement_trait)]

extern crate alloc;

pub type Result<T> = core::result::Result<T, Error>;

pub use config::{
    Config, ExploratoryConfig, I2cpConfig, MetricsConfig, Ntcp2Config, SamConfig, Ssu2Config,
    TransitConfig,
};
pub use error::Error;
pub use profile::Profile;

mod bloom;
mod config;
mod destination;
mod error;
mod i2cp;
mod netdb;
mod profile;
mod sam;
mod shutdown;
mod subsystem;
mod transport;
mod tunnel;
mod util;

pub mod crypto;
pub mod events;
pub mod i2np;
pub mod primitives;
pub mod protocol;
pub mod router;
pub mod runtime;
