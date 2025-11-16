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

use crate::config::EmissaryConfig;

use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    sync::Arc,
};

/// Load Base32 addresses from disk.
pub fn load_addresses(path: PathBuf) -> BTreeMap<Arc<str>, Arc<str>> {
    let Ok(file) = File::open(&path) else {
        tracing::warn!(
            target: "emissary::ui",
            path = %path.display(),
            "failed to open address book file",
        );
        return BTreeMap::new();
    };
    let reader = BufReader::new(file);

    reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let (key, value) = line.split_once('=')?;

            Some((Arc::from(key), Arc::from(format!("http://{value}.b32.i2p"))))
        })
        .collect()
}

/// Save router configuration to disk.
pub fn save_router_config(path: PathBuf, config: &EmissaryConfig) {
    std::fs::write(path, toml::to_string(config).unwrap()).unwrap();
}
