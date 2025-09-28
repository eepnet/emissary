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

use clap::{ArgGroup, Subcommand};

pub mod base64;

/// Router commands.
///
/// These are inspired by [`i2pd-tools`](https://github.com/PurpleI2P/i2pd-tools/).
#[derive(Subcommand)]
pub enum RouterCommand {
    /// Base64-encode data using the I2P Base64 alphabet.
    ///
    /// Input is read from stdin if `string` and `file` are not specified.
    ///
    /// Output is written to stdout if `output` is not specified.
    #[command(group(
        ArgGroup::new("input")
            .args(&["string", "file"])
            .required(false)
            .multiple(false),
    ))]
    Base64Encode {
        /// Input string to encode.
        #[arg(short = 's', long, value_name = "STRING")]
        string: Option<String>,

        /// Input file to encode.
        #[arg(short = 'f', long, value_name = "FILE")]
        file: Option<String>,

        /// Path to output file where the Base64-encoded string is written to.
        #[arg(short = 'o', long, value_name = "OUTPUT")]
        output: Option<String>,
    },

    /// Base64-decode data using the I2P Base64 alphabet.
    ///
    /// Input is read from stdin if `string` and `file` are not specified.
    ///
    /// Output is written to stdout if `output` is not specified.
    #[command(group(
        ArgGroup::new("input")
            .args(&["string", "file"])
            .required(false)
            .multiple(false),
    ))]
    Base64Decode {
        /// Input string to decode.
        #[arg(short = 's', long, value_name = "STRING")]
        string: Option<String>,

        /// Input file to decode.
        #[arg(short = 'f', long, value_name = "FILE")]
        file: Option<String>,

        /// Path to output file where the Base64-decoded string is written to.
        #[arg(short = 'o', long, value_name = "OUTPUT")]
        output: Option<String>,
    },
}
