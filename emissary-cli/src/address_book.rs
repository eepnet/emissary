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

use crate::config::AddressBookConfig;

use emissary_core::{
    crypto::{base32_encode, base64_decode},
    primitives::Destination,
    runtime::AddressBook,
};
use futures::channel::oneshot;
use parking_lot::RwLock;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONNECTION},
    Client, Proxy,
};

use std::{
    collections::HashMap, future::Future, path::PathBuf, pin::Pin, sync::Arc, time::Duration,
};

/// Logging target for the file
const LOG_TARGET: &str = "emissary::address-book";

/// Backoff if downloading the hosts file fails.
const RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// How many times each subscription is tried before giving up.
const SUBSCRIPTION_NUM_RETRIES: usize = 5usize;

/// Address book.
pub struct AddressBookManager {
    /// Path to address book.
    address_book_path: PathBuf,

    /// URL from which the primary `hosts.txt` is downloaded.
    hosts_url: Option<String>,

    /// Additional subscriptions.
    subscriptions: Vec<String>,

    /// Hostname -> Base32 address mappings
    addresses: Arc<RwLock<HashMap<String, String>>>,
}

impl AddressBookManager {
    /// Create new [`AddressBookManager`].
    pub async fn new(base_path: PathBuf, config: AddressBookConfig) -> Self {
        let path = base_path.join("addressbook");

        // load (hostname, base32 address) mappings from disk
        let addresses = match tokio::fs::read_to_string(path.join("addresses")).await {
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    path = %path.join("addresses").display(),
                    error = ?error.kind(),
                    "failed to load base32 addresses from disk",
                );
                HashMap::new()
            }
            Ok(content) => content
                .lines()
                .filter_map(|line| {
                    line.split_once('=').map(|(key, value)| (key.to_owned(), value.to_owned()))
                })
                .collect(),
        };

        Self {
            address_book_path: path,
            addresses: Arc::new(RwLock::new(addresses)),
            hosts_url: config.default,
            subscriptions: config
                .subscriptions
                .map_or_else(Vec::new, |subscriptions| subscriptions),
        }
    }

    /// Get opaque handling implementing [`AddressBook`].
    pub fn handle(&self) -> Arc<dyn AddressBook> {
        Arc::new(AddressBookHandle {
            address_book_path: Arc::from(self.address_book_path.to_str().expect("to succeed")),
            addresses: Arc::clone(&self.addresses),
        })
    }

    /// Attempt to download `hosts.txt` from `url`.
    async fn download(client: &Client, url: &str) -> Option<String> {
        let response = match client
            .get(url.to_string())
            .headers(HeaderMap::from_iter([(
                CONNECTION,
                HeaderValue::from_static("close"),
            )]))
            .send()
            .await
        {
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?url,
                    ?error,
                    "failed to fetch hosts.txt"
                );
                return None;
            }
            Ok(response) => response,
        };

        if !response.status().is_success() {
            tracing::debug!(
                target: LOG_TARGET,
                ?url,
                status = ?response.status(),
                "request to address book server failed",
            );
            return None;
        }

        match response.bytes().await {
            Ok(response) => match std::str::from_utf8(&response) {
                Ok(response) => Some(response.to_owned()),
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?url,
                        ?error,
                        "failed to convert `hosts.txt` to utf-8",
                    );
                    None
                }
            },
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?url,
                    ?error,
                    "failed to get response from address book server"
                );
                None
            }
        }
    }

    /// Parse `hosts` into base64 destinations and base32 addresses and merge the results into
    /// `addresses`.
    ///
    /// Addresses already present in `addresses` will be ignored.
    async fn parse_and_merge(
        &self,
        addresses: &mut HashMap<String, (String, String)>,
        hosts: String,
    ) {
        for line in hosts.lines() {
            let Some((hostname, base64_destination)) = line.split_once('=') else {
                tracing::warn!(
                    target: LOG_TARGET,
                    %line,
                    "ignoring invalid address",
                );
                continue;
            };
            let hostname = hostname.trim().to_string();

            if addresses.contains_key(&hostname) {
                tracing::trace!(
                    target: LOG_TARGET,
                    %hostname,
                    "skipping an already-existing address",
                );
                continue;
            }

            let base64_destination = match base64_destination.find("#!") {
                Some(index) => base64_destination[..index].trim().to_string(),
                None => base64_destination.trim().to_string(),
            };

            let Some(decoded) = base64_decode(&base64_destination) else {
                tracing::warn!(
                    target: LOG_TARGET,
                    %hostname,
                    "ignoring invalid base64-encoded destination",
                );
                continue;
            };

            match Destination::parse(&decoded) {
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %hostname,
                        ?error,
                        "ignoring invalid destination",
                    );
                    continue;
                }
                Ok(destination) => {
                    let base32_address = base32_encode(&destination.id().to_vec());
                    addresses.insert(hostname, (base32_address, base64_destination));
                }
            }
        }
    }

    /// Start event loop for [`AddressBookManager`].
    ///
    /// Before the address book subscription download starts, [`AddressBook`] waits on
    /// `http_proxy_ready_rx` which the HTTP proxy sends a signal to once it's ready.
    pub async fn run(
        self,
        http_port: u16,
        http_host: String,
        http_proxy_ready_rx: oneshot::Receiver<()>,
    ) {
        let Some(hosts_url) = &self.hosts_url else {
            tracing::debug!(
                target: LOG_TARGET,
                "address book download disabled",
            );
            return;
        };

        if let Err(error) = http_proxy_ready_rx.await {
            tracing::error!(
                target: LOG_TARGET,
                ?error,
                "http proxy failed to start, cannot start address book",
            );
        }

        tracing::info!(
            target: LOG_TARGET,
            ?http_port,
            ?http_host,
            ?hosts_url,
            subscriptions = ?self.subscriptions,
            "create address book",
        );

        let client = Client::builder()
            .proxy(Proxy::http(format!("http://{http_host}:{http_port}")).expect("to succeed"))
            .http1_title_case_headers()
            .build()
            .expect("to succeed");

        let mut addresses = HashMap::<String, (String, String)>::new();

        loop {
            match Self::download(&client, hosts_url).await {
                Some(hosts) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        url = %hosts_url,
                        "hosts.txt downloaded",
                    );

                    self.parse_and_merge(&mut addresses, hosts).await;
                    break;
                }
                None => tokio::time::sleep(RETRY_BACKOFF).await,
            }
        }

        // save hosts to disk at this point as subscriptions might contain .i2p addresses
        // which the http proxy must be able to resolve to .b32.i2p addresses
        self.save_to_disk(addresses.clone()).await;

        for subscription in &self.subscriptions {
            for _ in 0..SUBSCRIPTION_NUM_RETRIES {
                match Self::download(&client, subscription).await {
                    Some(hosts) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            url = subscription,
                            "hosts.txt downloaded",
                        );

                        self.parse_and_merge(&mut addresses, hosts).await;
                        break;
                    }
                    None => tokio::time::sleep(RETRY_BACKOFF).await,
                }
            }
        }

        self.save_to_disk(addresses).await;
    }

    /// Save `addresses` to disk.
    ///
    /// Parses each destination in `addresses` into its .b32.i2p address, stores all .b32.i2p
    /// addresses along with their hostnames into a file and stores all .Base64-encoded destinations
    /// into a separate directory where each destination is indexed by their hostname.
    async fn save_to_disk(&self, addresses: HashMap<String, (String, String)>) {
        let (addresses, destinations): (HashMap<_, _>, HashMap<_, _>) = addresses
            .into_iter()
            .map(|(hostname, (base32, base64))| ((hostname.clone(), base32), (hostname, base64)))
            .unzip();

        // store base32-encoded addresses on disk and update `addresses`
        {
            let base32_addresses = {
                let mut inner = self.addresses.write();
                let base32_addresses =
                    addresses.into_iter().fold(String::new(), |acc, (hostname, address)| {
                        inner.insert(hostname.clone(), address.clone());

                        format!("{hostname}={address}\n{acc}")
                    });

                base32_addresses
            };

            let base32_addresses =
                match tokio::fs::read_to_string(self.address_book_path.join("addresses")).await {
                    Ok(old_addresses) => format!("{old_addresses}{base32_addresses}"),
                    Err(_) => base32_addresses,
                };

            if let Err(error) =
                tokio::fs::write(self.address_book_path.join("addresses"), base32_addresses).await
            {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to write base32 addresses to disk",
                );
            }
        }

        // store base64-encoded destinations on disk
        match tokio::fs::create_dir_all(self.address_book_path.join("destinations")).await {
            Err(error) => tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "failed to create directory for destinations",
            ),
            Ok(_) =>
                for (hostname, destination) in destinations {
                    if let Err(error) = tokio::fs::write(
                        self.address_book_path.join("destinations").join(format!("{hostname}.txt")),
                        destination,
                    )
                    .await
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %hostname,
                            ?error,
                            "failed to store destination to disk",
                        );
                    }
                },
        }
    }
}

/// Address book handle.
#[derive(Clone)]
pub struct AddressBookHandle {
    /// Path to address book.
    address_book_path: Arc<str>,

    /// Hostname -> Base32 address mappings
    addresses: Arc<RwLock<HashMap<String, String>>>,
}

impl AddressBook for AddressBookHandle {
    fn resolve_b64(&self, host: String) -> Pin<Box<dyn Future<Output = Option<String>> + Send>> {
        let path = Arc::clone(&self.address_book_path);

        Box::pin(async move {
            tokio::fs::read_to_string(format!("{path}/destinations/{host}.txt")).await.ok()
        })
    }

    fn resolve_b32(&self, host: &str) -> Option<String> {
        self.addresses.write().get(host).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn save_only_destination() {
        let dir = tempdir().unwrap();
        let address_book = AddressBookManager::new(
            dir.keep(),
            AddressBookConfig {
                default: Some(String::from("url")),
                subscriptions: None,
            },
        )
        .await;

        let mut addresses = HashMap::<String, (String, String)>::new();
        let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfcKolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAXgKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9nBdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJPUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpBZz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPybmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lzS9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVgDZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8SWcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYhbfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLdJuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYmAAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==#!action=adddest#date=1490103520#olddest=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3uSzpWS0EHmrlfoLr5uGGd9ZHwwCIcgfOATaPRMUEQxiK9q48PS0V3EXXO4-YLT0vIfk4xO~XqZpn8~PW1kFe2mQMHd7oO89yCk-3yizRG3UyFtI7-mO~eCI6-m1spYoigStgoupnC3G85gJkqEjMm49gUjbhfWKWI-6NwTj0ZnAAAA#oldsig=MbSvc9wsxSm37B65rUC~BCZzFsIJe0-CXCH8n97ZaMMizNUjeytgBQ==#sig=R2wREo~02liJmU4UGfVZr88XFMiHdYDXVfS~HtyxFxwYG~2o1guP~RocqmHBCE6yPg1Cm8m336d~jqijAVJzBA==".to_string();

        address_book.parse_and_merge(&mut addresses, hosts).await;
        let addresses = addresses
            .into_iter()
            .map(|(hostname, (_, destination))| (hostname, destination))
            .collect::<HashMap<_, _>>();

        assert_eq!(addresses.get(&String::from("tracker2.postman.i2p")), Some(&String::from("lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfcKolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==")));

        assert_eq!(addresses.get(&String::from("psi.i2p")), Some(&String::from("a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJPUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpBZz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPybmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lzS9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA")));

        assert_eq!(addresses.get(&String::from("zerobin.i2p")), Some(&String::from("Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVgDZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8SWcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYhbfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLdJuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYmAAAA")));

        assert_eq!(addresses.get(&String::from("zzz.i2p")), Some(&String::from("GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==")));
    }

    #[tokio::test]
    async fn host_lookup() {
        // create address book
        let dir = {
            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: Some(String::from("url")),
                    subscriptions: None,
                },
            )
            .await;

            let mut addresses = HashMap::<String, (String, String)>::new();
            let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfcKolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAXgKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9nBdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJPUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpBZz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPybmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lzS9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVgDZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8SWcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYhbfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLdJuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYmAAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

            address_book.parse_and_merge(&mut addresses, hosts).await;
            address_book.save_to_disk(addresses).await;

            dir
        };

        // load address book from disk
        let address_book = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: None,
            },
        )
        .await;
        let handle = address_book.handle();

        // try to find base32 address and base64-encoded destination of a saved destination
        let host = handle.resolve_b32("zzz.i2p").expect("to find base32 address for zzz.i2p");
        assert_eq!(
            host,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua".to_string()
        );

        let destination = handle
            .resolve_b64("zzz.i2p".to_string())
            .await
            .expect("expected to find destination for zzz.i2p");
        assert_eq!(destination, "GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==");

        // attempt to find base32 address for an unknown hostname
        assert!(handle.resolve_b32("test.i2p").is_none());
        assert!(handle.resolve_b64("test.i2p".to_string()).await.is_none());
    }

    #[tokio::test]
    async fn save_to_disk() {
        let dir = tempdir().unwrap().path().to_owned();
        tokio::fs::create_dir_all(dir.join("addressbook")).await.unwrap();

        let address_book = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: Some(String::from("url")),
                subscriptions: None,
            },
        )
        .await;

        let mut addresses = HashMap::<String, (String, String)>::new();
        let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfcKolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAXgKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9nBdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJPUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpBZz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPybmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lzS9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVgDZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8SWcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYhbfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLdJuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYmAAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==#!action=adddest#date=1490103520#olddest=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3uSzpWS0EHmrlfoLr5uGGd9ZHwwCIcgfOATaPRMUEQxiK9q48PS0V3EXXO4-YLT0vIfk4xO~XqZpn8~PW1kFe2mQMHd7oO89yCk-3yizRG3UyFtI7-mO~eCI6-m1spYoigStgoupnC3G85gJkqEjMm49gUjbhfWKWI-6NwTj0ZnAAAA#oldsig=MbSvc9wsxSm37B65rUC~BCZzFsIJe0-CXCH8n97ZaMMizNUjeytgBQ==#sig=R2wREo~02liJmU4UGfVZr88XFMiHdYDXVfS~HtyxFxwYG~2o1guP~RocqmHBCE6yPg1Cm8m336d~jqijAVJzBA==".to_string();

        address_book.parse_and_merge(&mut addresses, hosts).await;
        address_book.save_to_disk(addresses.clone()).await;

        // verify all base64 destinations have been saved under correct keys
        for (key, (_, value)) in addresses {
            let key = key.strip_suffix(".i2p").unwrap();

            let path = dir.join("addressbook/destinations").join(&format!("{key}.i2p.txt"));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), value);
        }

        // verify all base32 addresses have been saved and correspond to correct hostnames
        let content = std::fs::read_to_string(&dir.join("addressbook/addresses")).unwrap();
        let mut expected = HashMap::<&str, &str>::from_iter([
            (
                "psi.i2p",
                "avviiexdngd32ccoy4kuckvc3mkf53ycvzbz6vz75vzhv4tbpk5a",
            ),
            (
                "zerobin.i2p",
                "3564erslxzaoucqasxsjerk4jz2xril7j2cbzd4p7flpb4ut67hq",
            ),
            (
                "tracker2.postman.i2p",
                "6a4kxkg5wp33p25qqhgwl6sj4yh4xuf5b3p3qldwgclebchm3eea",
            ),
            (
                "zzz.i2p",
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua",
            ),
        ]);

        for line in content.lines() {
            let (key, value) = line.split_once('=').unwrap();
            let expected_value = expected.remove(&key).unwrap();

            assert_eq!(expected_value, value);
        }
    }

    #[tokio::test]
    async fn redownload_address_book() {
        // create address book
        let dir = {
            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: Some(String::from("url")),
                    subscriptions: None,
                },
            )
            .await;

            let mut addresses = HashMap::<String, (String, String)>::new();
            let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfcKolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAXgKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9nBdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJPUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpBZz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPybmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lzS9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVgDZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8SWcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYhbfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLdJuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYmAAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

            address_book.parse_and_merge(&mut addresses, hosts).await;
            address_book.save_to_disk(addresses).await;

            dir
        };

        // load address book from disk
        //
        // this simulates a startup from disk
        {
            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                },
            )
            .await;
            let handle = address_book.handle();

            // verify all hosts are found
            for host in ["psi.i2p", "zerobin.i2p", "tracker2.postman.i2p", "zzz.i2p"] {
                assert!(handle.resolve_b32(host).is_some());
                assert!(handle.resolve_b64(host.to_string()).await.is_some());
            }

            // download more hosts from some other subscriptions
            //
            // verify that the new destinations are stored on disk, theb base32 address book is
            // updated and that `AddressBookHandle` has the new base32 addresses
            let new_hosts = "echo.idk.i2p=75Mgd8DeYkNAdk6mrF0rOt3WuM6bYi3k7n3BRIp-np5-5-py1YTmBJSRq9EXL1YrweUpal~ZT~46~-lMW~zKHA46iTWsZzKFMEKFdfoM2fSgZDlEaoalW4QzkQjbOVO0atkEK15uXO2WiCRgfUab0Gyp-EcGkdQq8FuF~sPLlm4xa90cmT6G~s1SeaNLII8DPli-XqZppSGOSArMSEYsxZPNfKs5UxvEeCrbUjBLCGhy2K3x926Af9bZk1ITIW~K70xo-rSD0SbDXO9vT4e7fiq21Q2LicAofn~Y4MwPz6jr0CUZQAHxwCy1N3OR0XYFsTI4XS1LZ3zGwVpEjCfVD1mQhCLzzIjRHgGB6Cr3xj3FntBhv0d9pBuogUjOkLEnmFHpj5ONE7l~3aUsR6vRYTUDfwnxXnIi9KF-PPyOAACXCz~T06QXVfaqzTj8tyr40cUqKIZHquaMZrAkqqa26KM3l0fu755UVo43MfD3f9zo3erjo~UDI~oP1bYyEU3LBQAEAAcAAA==\n\
3chelectricboogaloo.i2p=W5br4iApDNRQ-IY0yZQqrv-BqIj5Rk1XytcDUHcTpGHiyeaEPlP3wRr~zMTKrlCh78IRI26m8GwjE2VKdoMMwl9j9GdikQX4p4J0912IcRZbFGVIkibe36KgqkKJ9-s1gv4yzDVjEG2ZE6CMn-NZJxyp3a7Ypa1UFDLATdepKFhHZRK3EN9fcUfMy2EAMwgihnd4JVZTytSVOcKfUrhIXf1lKmgr9qN9uXv38q2mtYMzbnWNe6TlB9GWrAZnsREB1kEZMts28leSGB~kYJHSlxQQvgOA0Rt9s3xkvP~EThUmyIIDZ9SlBh8iek6E1wreHfRhsCA9qTdCcs5XivxG0CMJR4F-Q55AlSFWthsgJrUrb9x4RB6fTANv5bvZH3yBMQvZZxgqu4sN6MbPVaW2X7x3ldq3~UwG~HXvdvA7wP-sBq3uEshPCuVhJD8ojUDqm9prLIVuLWt2pIiVbz-l4P-jx769A0OoN8-Z6j5b7zLNdd~QX0NPfXVMp1V~Z4fFBQAEAAcAAA==\n\
gts.varikvalefor.i2p=cqwoYXfztQTzDKaPMsElmgfflDLLRBBvQSTgHfhBKnGkT-lKzL659h480A9YQuZfmKSzaplidYTvMPIrS4lhh4m7ybvkt3Dv9bLd8QR7k14gw~arshKakr6HgkpUXU8uwA6ns45bsLKe~PbASIGbPEIudRjtrvmRpXxqy~0mpjkXkhhm8RJx3CM7iO62ZyspCXTI2GV2rbvcxyD6kEcQd-YrU5tnimSUN8b1WqbkoQBvEn1JR~mn-KJzR4RUpKd~FgqPesMI2rM8dyl4bQkHv3XrWU3YZ75bsXaht80Ii6rrcPrD3LCERIC43rII0Y1UQarpij2ZyC508ccveIbGroUWOsrPz8tLklnIuvZIor~2MkWK9e2zymXMPU~8ZJDVhAFd2PSJs~TFBrwvzD2mvcG-ChvrS051Gv1ZPIOqDLGdTEBC7BV2OyDlzKu0VnHsiS3h2PwBJdXx9zk~HXAA1hwLCjuIwSYpNIQxrEaFEu2Eh6keqo-kKidL~Lcxk~hUBQAEAAcAAA==".to_string();

            let mut addresses = HashMap::<String, (String, String)>::new();
            address_book.parse_and_merge(&mut addresses, new_hosts).await;
            address_book.save_to_disk(addresses).await;

            // verify all old and new hosts are found
            for host in [
                "psi.i2p",
                "zerobin.i2p",
                "tracker2.postman.i2p",
                "zzz.i2p",
                "echo.idk.i2p",
                "3chelectricboogaloo.i2p",
                "gts.varikvalefor.i2p",
            ] {
                assert!(handle.resolve_b32(host).is_some());
                assert!(handle.resolve_b64(host.to_string()).await.is_some());
            }
        }

        // load address book from disk again and verify all hosts are still in the address book
        {
            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                },
            )
            .await;
            let handle = address_book.handle();

            for host in [
                "psi.i2p",
                "zerobin.i2p",
                "tracker2.postman.i2p",
                "zzz.i2p",
                "echo.idk.i2p",
                "3chelectricboogaloo.i2p",
                "gts.varikvalefor.i2p",
            ] {
                assert!(handle.resolve_b32(host).is_some());
                assert!(handle.resolve_b64(host.to_string()).await.is_some());
            }
        }
    }
}
