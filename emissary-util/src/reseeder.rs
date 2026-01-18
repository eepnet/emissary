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
    certificates::CREATIVECOWPAT_SSL,
    su3::{ReseedRouterInfo, Su3},
};

use anyhow::anyhow;
use rand::{thread_rng, Rng};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONNECTION, USER_AGENT},
    Certificate, ClientBuilder,
};

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::reseeder";

/// How many times is reseeding retried before giving up.
const NUM_RETRIES: usize = 5usize;

/// How many routers should [`Reseeder`] find before terminating the process.
const MIN_ROUTER_INFOS_TO_DOWNLOAD: usize = 100usize;

/// Reseed servers.
const RESEED_SERVERS: &[&str] = &[
    "https://reseed.stormycloud.org/",
    "https://reseed-pl.i2pd.xyz/",
    "https://reseed-fr.i2pd.xyz/",
    "https://www2.mk16.de/",
    "https://reseed2.i2p.net/",
    "https://banana.incognet.io/",
    "https://reseed.diva.exchange/",
    "https://reseed.i2pgit.org/",
    "https://i2p.novg.net/",
    "https://reseed.onion.im/",
    "https://reseed.memcpy.io/",
    "https://i2pseed.creativecowpat.net:8443/",
    "https://reseed.sahil.world/",
    "https://i2p.diyarciftci.xyz/",
];

/// HTTPS reseeder.
pub struct Reseeder;

impl Reseeder {
    /// Attempt to reseed from `hosts` and parse response into a vector of serialized router infos.
    async fn reseed_inner(
        hosts: &[&str],
        force_ipv4: bool,
    ) -> anyhow::Result<Vec<ReseedRouterInfo>> {
        let client = if force_ipv4 {
            ClientBuilder::new().local_address("0.0.0.0:0".parse().ok())
        } else {
            ClientBuilder::new()
        }
        .add_root_certificate(
            Certificate::from_pem_bundle(CREATIVECOWPAT_SSL.as_bytes())
                .expect("to succeed")
                .pop()
                .expect("to exist"),
        )
        .timeout(Duration::from_secs(15))
        .build()?;

        let headers = HeaderMap::from_iter([
            (USER_AGENT, HeaderValue::from_static("Wget/1.11.4")),
            (CONNECTION, HeaderValue::from_static("close")),
        ]);

        // servers which have failed
        let mut already_tried = HashSet::<usize>::new();
        let mut routers = HashMap::<String, ReseedRouterInfo>::new();

        for _ in 0..NUM_RETRIES {
            let server = loop {
                let server = thread_rng().gen_range(0..hosts.len());

                if already_tried.insert(server) {
                    break server;
                }
            };

            tracing::info!(
                target: LOG_TARGET,
                host = %hosts[server],
                "reseed from host"
            );

            let response = match client
                .get(format!("{}/i2pseeds.su3", hosts[server]))
                .headers(headers.clone())
                .send()
                .await
            {
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        server = ?hosts[server],
                        ?error,
                        "failed to reseed"
                    );
                    continue;
                }
                Ok(response) => response,
            };

            if !response.status().is_success() {
                tracing::warn!(
                    target: LOG_TARGET,
                    status = ?response.status(),
                    "request to reseed server failed",
                );
                continue;
            }

            match response.bytes().await {
                Ok(bytes) => match Su3::parse_reseed(&bytes, true) {
                    None => continue,
                    Some(downloaded) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            server = ?hosts[server],
                            num_routers = ?downloaded.len(),
                            "reseed succeeded"
                        );

                        routers
                            .extend(downloaded.into_iter().map(|info| (info.name.clone(), info)));

                        if routers.len() >= MIN_ROUTER_INFOS_TO_DOWNLOAD {
                            return Ok(routers.into_values().collect());
                        }
                    }
                },
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        server = ?hosts[server],
                        %error,
                        "failed to get response from reseeed server"
                    );
                }
            }
        }

        if !routers.is_empty() && routers.len() < MIN_ROUTER_INFOS_TO_DOWNLOAD {
            tracing::warn!(
                target: LOG_TARGET,
                num_downloaded = ?routers.len(),
                limit = ?MIN_ROUTER_INFOS_TO_DOWNLOAD,
                "could not download enough uniqueu router infos",
            );
            return Ok(routers.into_values().collect());
        }

        Err(anyhow!("failed to reseed"))
    }

    /// Reseed from `hosts` or from `RESEED_SERVERS` if `hosts` are not specified.
    pub async fn reseed(
        hosts: Option<Vec<String>>,
        force_ipv4: bool,
    ) -> anyhow::Result<Vec<ReseedRouterInfo>> {
        match hosts {
            None => Self::reseed_inner(RESEED_SERVERS, force_ipv4).await,
            Some(hosts) =>
                Self::reseed_inner(
                    &hosts.iter().map(AsRef::as_ref).collect::<Vec<_>>(),
                    force_ipv4,
                )
                .await,
        }
    }
}
