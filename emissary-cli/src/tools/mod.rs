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

mod base64;
mod devnet;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tools";

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

    /// Spawn an isolated, local I2P network.
    Devnet {
        /// How many floodfills the network has.
        #[arg(short = 'f', long, value_name = "NUM_FLOODFILLS", default_value_t = 3)]
        num_floodfills: usize,

        /// How many regular routers the network has.
        #[arg(short = 'r', long, value_name = "NUM_ROUTERS", default_value_t = 3)]
        num_routers: usize,

        /// Path where the routerInfo files are stored.
        ///
        /// If not specified, a random directory is created.
        #[arg(short = 'p', long, value_name = "PATH")]
        path: Option<String>,
    },
}

impl RouterCommand {
    /// Execute router command and exit.
    pub async fn execute(self) -> ! {
        match self {
            RouterCommand::Base64Encode {
                string,
                file,
                output,
            } =>
                if let Err(error) = base64::encode(string, file, output) {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to base64-encode input",
                    );
                    std::process::exit(1);
                },
            RouterCommand::Base64Decode {
                string,
                file,
                output,
            } =>
                if let Err(error) = base64::decode(string, file, output) {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to base64-decode input",
                    );
                    std::process::exit(1);
                },
            RouterCommand::Devnet {
                num_floodfills,
                num_routers,
                path,
            } => devnet::spawn_network(num_floodfills, num_routers, path).await,
        }

        std::process::exit(0);
    }
}
