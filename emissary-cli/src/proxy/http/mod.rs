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
    config::HttpProxyConfig,
    proxy::http::{
        error::HttpError,
        request::Request,
        response::{send_response, Status},
    },
};

use emissary_core::runtime::AddressBook;
use futures::{channel::oneshot, future::Either};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use yosemite::{style, Session, SessionOptions, StreamOptions};

use std::{sync::Arc, time::Duration};

mod error;
mod request;
mod response;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::proxy::http";

/// Request context.
#[derive(Debug)]
struct RequestContext {
    /// Client's TCP stream.
    stream: TcpStream,

    /// Parsed request.
    request: Request,
}

/// HTTP proxy.
pub struct HttpProxy {
    /// Handle to [`AddressBook`], if it was enabled.
    address_book_handle: Option<Arc<dyn AddressBook>>,

    // TCP listener.
    listener: TcpListener,

    /// Inbound requests.
    requests: JoinSet<Option<RequestContext>>,

    /// SAMv3 streaming session for the HTTP proxy.
    session: Session<style::Stream>,

    /// HTTP outproxy, if enabled.
    outproxy: Option<String>,
}

impl HttpProxy {
    /// Create new [`HttpProxy`].
    ///
    /// `http_proxy_ready_tx` is used to notify [`AddressBook`] once the HTTP proxy is ready
    /// so it can download the hosts file(s).
    pub async fn new(
        config: HttpProxyConfig,
        samv3_tcp_port: u16,
        http_proxy_ready_tx: Option<oneshot::Sender<()>>,
        address_book_handle: Option<Arc<dyn AddressBook>>,
    ) -> crate::Result<Self> {
        tracing::info!(
            target: LOG_TARGET,
            host = %config.host,
            port = %config.port,
            outproxy = ?config.outproxy,
            "starting http proxy",
        );

        // create session before starting the tcp listener for the proxy
        let session = Session::<style::Stream>::new(SessionOptions {
            publish: false,
            samv3_tcp_port,
            nickname: "http-proxy".to_string(),
            ..Default::default()
        })
        .await?;
        let listener = TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;

        if let Some(tx) = http_proxy_ready_tx {
            let _ = tx.send(());
        }

        // validate outproxy
        //
        // if the outproxy is given as a .b32.i2p host, it can be used as-is
        //
        // if it's given as a .i2p host, it must be converted into a .b32.i2p host by doing a host
        // lookup into address book
        //
        // if either address book is disabled or hostname is not found in it, outproxy is disabled
        let outproxy = match config.outproxy {
            None => None,
            Some(outproxy) => {
                let outproxy = outproxy.strip_prefix("http://").unwrap_or(&outproxy);
                let outproxy = outproxy.strip_prefix("www.").unwrap_or(outproxy);

                match outproxy.ends_with(".i2p") {
                    false => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %outproxy,
                            "outproxy must be .b32.i2p or .i2p hostname",
                        );
                        None
                    }
                    true => match (outproxy.ends_with(".b32.i2p"), &address_book_handle) {
                        (true, _) => Some(outproxy.to_owned()),
                        (false, Some(handle)) => match handle.resolve_b32(outproxy.to_owned()) {
                            Either::Left(host) => Some(format!("{host}.b32.i2p")),
                            Either::Right(future) => match future.await {
                                Some(host) => Some(format!("{host}.b32.i2p")),
                                None => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %outproxy,
                                        "outproxy not found in address book",
                                    );
                                    None
                                }
                            },
                        },
                        (false, None) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                %outproxy,
                                "address book not enabled, unable to resolve outproxy hostname",
                            );
                            None
                        }
                    },
                }
            }
        };

        Ok(Self {
            address_book_handle,
            listener,
            outproxy,
            requests: JoinSet::new(),
            session,
        })
    }

    /// Read request from browser.
    ///
    /// Parses and validates the received request and returns [`RequestContext`] which contains the
    /// validated request and the TCP stream of the client which is used to send the response or an
    /// error.
    async fn read_request(mut stream: TcpStream) -> Result<RequestContext, (TcpStream, HttpError)> {
        let mut buffer = vec![0u8; 8192];
        let mut nread = 0usize;

        // read from `stream` until complete request has been received
        loop {
            nread += match stream.read(&mut buffer[nread..]).await {
                Err(error) => return Err((stream, HttpError::Io(error.kind()))),
                Ok(0) => return Err((stream, HttpError::Io(std::io::ErrorKind::BrokenPipe))),
                Ok(nread) => nread,
            };

            let mut headers = [httparse::EMPTY_HEADER; 64];
            match httparse::Request::new(&mut headers).parse(&buffer[..nread]) {
                Err(_) => return Err((stream, HttpError::Malformed)),
                Ok(request) if request.is_complete() => break,
                Ok(_) => {}
            }
        }

        match Request::parse(buffer[..nread].to_vec()) {
            Err(error) => Err((stream, error)),
            Ok(request) => Ok(RequestContext { stream, request }),
        }
    }

    /// Handle `request`.
    ///
    /// Assembles the validated request into an actual HTTP request and resolves a .i2p host into a
    /// .b32.i2p host if a .i2p host was used and if address book was enabled.
    ///
    /// If the outbound request was for an outproxy, ensures that an outproxy has been configured.
    ///
    /// After the final request has been assembled and the host has been resolved, opens a stream to
    /// the remote destination and if a connection is successfully established, sends the request
    /// and reads the response which is relayed to client.
    async fn on_request(&mut self, request: RequestContext) -> Result<(), (TcpStream, HttpError)> {
        let RequestContext {
            mut stream,
            request,
        } = request;

        let (host, request) =
            match request.assemble(&self.address_book_handle, &self.outproxy).await {
                Ok((host, request)) => (host, request),
                Err(error) => return Err((stream, error)),
            };

        let future = self.session.connect_detached_with_options(
            &host,
            StreamOptions {
                dst_port: 80,
                ..Default::default()
            },
        );

        tokio::spawn(async move {
            match future.await {
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to connect to destination",
                    );
                    send_response(stream, Status::GatewayTimeout(host)).await;
                    Err(error)
                }
                Ok(mut i2p_stream) => {
                    // write request and read from the stream until it is closed
                    i2p_stream.write_all(&request).await?;

                    tokio::io::copy_bidirectional(&mut i2p_stream, &mut stream)
                        .await
                        .map_err(From::from)
                }
            }
        });

        Ok(())
    }

    /// Run event loop of [`HttpProxy`].
    pub async fn run(mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                connection = self.listener.accept() => match connection {
                    Ok((stream, _)) => {
                        self.requests.spawn(async move {
                            match tokio::time::timeout(Duration::from_secs(10), Self::read_request(stream)).await {
                                Err(_) => None,
                                Ok(Ok(request)) => Some(request),
                                Ok(Err((stream, error))) => {
                                    tracing::debug!(
                                        target: LOG_TARGET,
                                        ?error,
                                        "failed to handle inbound http request",
                                    );
                                    send_response(stream, Status::BadRequest(error)).await;
                                    None
                                }
                            }
                        });
                    }
                    Err(error) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to read from socket"
                        );
                    }
                },
                request = self.requests.join_next(), if !self.requests.is_empty() => match request {
                    None | Some(Ok(None)) => {}
                    Some(Ok(Some(request))) => if let Err((stream, error)) = self.on_request(request).await {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to handle inbound http request",
                        );
                        send_response(stream, Status::BadRequest(error)).await;
                    }
                    Some(Err(error)) => tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to poll http request",
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{address_book::AddressBookManager, config::AddressBookConfig};
    use reqwest::{
        header::{HeaderMap, HeaderValue, CONNECTION},
        Client, Proxy, StatusCode,
    };
    use tempfile::tempdir;
    use tokio::io::{AsyncBufReadExt, BufReader};

    /// Fake SAMv3 server.
    struct SamServer {
        /// TCP listener for the server.
        listener: TcpListener,
    }

    impl SamServer {
        /// Create new [`SamServer`].
        async fn new() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

            Self { listener }
        }

        /// Run the event loop of [`SamServer`].
        async fn run(self) {
            while let Ok((stream, _)) = self.listener.accept().await {
                tokio::spawn(async move {
                    let mut lines = BufReader::new(stream).lines();

                    while let Ok(Some(command)) = lines.next_line().await {
                        if command.starts_with("HELLO VERSION") {
                            lines
                                .get_mut()
                                .write_all("HELLO REPLY RESULT=OK VERSION=3.2\n".as_bytes())
                                .await
                                .unwrap();
                            continue;
                        }

                        if command.starts_with("SESSION CREATE") {
                            lines
                                .get_mut()
                                .write_all(
                                    "SESSION STATUS RESULT=OK DESTINATION=Fam-qmfYnngAnwkq3qwhkkoUeWNP\
                                        ckuYbZhK4xWwTzHa3BN9DY4dozKDPywI22LWfT1ALnVDonnRhCux0Iv3wc74-s2CTJOGLp\
                                        YvPGviS99dFSqRwgxi1dESbt5Liw4FIDZQMcDjcNziHspnTFfE4B3sZUtoNM0GYkrgksS3\
                                        BgVo3SvNn57~FkHDJvNxcaEL0uq9OGPfxNXNtyIeBxaUSJjYNbgcHG9Q2kzb~Z39FzylbE\
                                        iS979HJnc~w9Wo4DO8VCHGM1j6-CeRlf3hZpMaqQQJU0Q~k035~voydSIzDLJzMPvVmKAV\
                                        4q-0A5ikidKKv1N3kREQF5xDuDT1z3BMVHMIsyUECi8HOm3Ixa7XdcqpvHRl~W4RksOEdM\
                                        ChLrUZbqVr-8uW0lMRhRszAuU2PnF16bw9XEZoVAsNNHgvFQvnOwfLnPpSxtZaGNHGO8w\
                                        QaYmT3cImMUUhBbc9dcTYAHy8geZ1KzW4j7lpH4SsNaJPszCevkIVdvlqEAXZqh1YBQAE\
                                        AAcAADwJfIcEBwdeM2rjFM~cPo4btsSszyKlGZeUPzoTfHZv~4eR5efcr5YlogkmARNw57\
                                        h4sjmYvTESdTE7353u2uI=\n".as_bytes(),
                                )
                                .await
                                .unwrap();
                            continue;
                        }

                        println!("unhandled command: {command}");
                    }
                });
            }
        }
    }

    async fn read_response(mut stream: TcpStream) -> String {
        let mut buffer = vec![0u8; 8192];
        let mut nread = 0usize;

        // read from `stream` until complete request has been received
        loop {
            nread += match stream.read(&mut buffer[nread..]).await {
                Err(_) => panic!("i/o error"),
                Ok(0) => panic!("read zero"),
                Ok(nread) => nread,
            };

            let mut headers = [httparse::EMPTY_HEADER; 64];
            match httparse::Response::new(&mut headers).parse(&buffer[..nread]) {
                Err(error) => panic!("failed to parse response: {error:?}"),
                Ok(response) if response.is_complete() =>
                    return std::str::from_utf8(&buffer[..nread]).unwrap().to_owned(),
                Ok(_) => {}
            }
        }
    }

    #[tokio::test]
    async fn invalid_request() {
        let sam_port = {
            let sam = SamServer::new().await;
            let port = sam.listener.local_addr().unwrap().port();
            tokio::spawn(sam.run());

            port
        };

        let proxy = HttpProxy::new(
            HttpProxyConfig {
                port: 0,
                host: "127.0.0.1".to_string(),
                outproxy: None,
            },
            sam_port,
            None,
            None,
        )
        .await
        .unwrap();
        let address = proxy.listener.local_addr().unwrap();
        tokio::spawn(proxy.run());

        // send invalid http request to the proxy
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all("hello, world!\n".as_bytes()).await.unwrap();

        let response = read_response(stream).await;
        assert!(response.contains("400 Bad Request"));
        assert!(response.contains("Malformed request"));
    }

    #[tokio::test]
    async fn connect_to_i2p_without_address_book() {
        let sam_port = {
            let sam = SamServer::new().await;
            let port = sam.listener.local_addr().unwrap().port();
            tokio::spawn(sam.run());

            port
        };

        let proxy = HttpProxy::new(
            HttpProxyConfig {
                port: 0,
                host: "127.0.0.1".to_string(),
                outproxy: None,
            },
            sam_port,
            None,
            None,
        )
        .await
        .unwrap();
        let port = proxy.listener.local_addr().unwrap().port();
        tokio::spawn(proxy.run());

        let client = Client::builder()
            .proxy(Proxy::http(format!("http://127.0.0.1:{port}")).expect("to succeed"))
            .http1_title_case_headers()
            .build()
            .expect("to succeed");

        match client
            .get("http://zzz.i2p")
            .headers(HeaderMap::from_iter([(
                CONNECTION,
                HeaderValue::from_static("close"),
            )]))
            .send()
            .await
        {
            Err(error) => panic!("failure: {error:?}"),
            Ok(response) => {
                assert_eq!(response.status(), StatusCode::from_u16(400).unwrap());
                assert!(response
                    .text()
                    .await
                    .unwrap()
                    .contains("Cannot connect to .i2p host, address book not enabled"));
            }
        };
    }

    #[tokio::test]
    async fn address_book_enabled_but_host_not_found() {
        let sam_port = {
            let sam = SamServer::new().await;
            let port = sam.listener.local_addr().unwrap().port();
            tokio::spawn(sam.run());

            port
        };

        // create empty address book
        let address_book = {
            let dir = tempdir().unwrap().into_path();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();
            tokio::fs::File::create(dir.join("addressbook/addresses")).await.unwrap();

            AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                },
            )
            .handle()
        };

        let proxy = HttpProxy::new(
            HttpProxyConfig {
                port: 0,
                host: "127.0.0.1".to_string(),
                outproxy: None,
            },
            sam_port,
            None,
            Some(address_book),
        )
        .await
        .unwrap();
        let port = proxy.listener.local_addr().unwrap().port();
        tokio::spawn(proxy.run());

        let client = Client::builder()
            .proxy(Proxy::http(format!("http://127.0.0.1:{port}")).expect("to succeed"))
            .http1_title_case_headers()
            .build()
            .expect("to succeed");

        match client
            .get("http://zzz.i2p")
            .headers(HeaderMap::from_iter([(
                CONNECTION,
                HeaderValue::from_static("close"),
            )]))
            .send()
            .await
        {
            Err(error) => panic!("failure: {error:?}"),
            Ok(response) => {
                assert_eq!(response.status(), StatusCode::from_u16(400).unwrap());
                assert!(response.text().await.unwrap().contains("Host not found in address book"));
            }
        };
    }

    #[tokio::test]
    async fn outproxy_not_configured() {
        let sam_port = {
            let sam = SamServer::new().await;
            let port = sam.listener.local_addr().unwrap().port();
            tokio::spawn(sam.run());

            port
        };

        let proxy = HttpProxy::new(
            HttpProxyConfig {
                port: 0,
                host: "127.0.0.1".to_string(),
                outproxy: None,
            },
            sam_port,
            None,
            None,
        )
        .await
        .unwrap();
        let port = proxy.listener.local_addr().unwrap().port();
        tokio::spawn(proxy.run());

        let client = Client::builder()
            .proxy(Proxy::http(format!("http://127.0.0.1:{port}")).expect("to succeed"))
            .http1_title_case_headers()
            .build()
            .expect("to succeed");

        match client
            .get("http://google.com")
            .headers(HeaderMap::from_iter([(
                CONNECTION,
                HeaderValue::from_static("close"),
            )]))
            .send()
            .await
        {
            Err(error) => panic!("failure: {error:?}"),
            Ok(response) => {
                assert_eq!(response.status(), StatusCode::from_u16(400).unwrap());
                assert!(response
                    .text()
                    .await
                    .unwrap()
                    .contains("Cannot connect to clearnet address, outproxy not enabled"));
            }
        };
    }

    #[tokio::test]
    async fn outproxy_given_as_i2p_host_but_no_address_book() {
        let sam_port = {
            let sam = SamServer::new().await;
            let port = sam.listener.local_addr().unwrap().port();
            tokio::spawn(sam.run());

            port
        };

        let proxy = HttpProxy::new(
            HttpProxyConfig {
                port: 0,
                host: "127.0.0.1".to_string(),
                outproxy: Some("outproxy.i2p".to_string()),
            },
            sam_port,
            None,
            None,
        )
        .await
        .unwrap();
        let port = proxy.listener.local_addr().unwrap().port();
        tokio::spawn(proxy.run());

        let client = Client::builder()
            .proxy(Proxy::http(format!("http://127.0.0.1:{port}")).expect("to succeed"))
            .http1_title_case_headers()
            .build()
            .expect("to succeed");

        match client
            .get("http://google.com")
            .headers(HeaderMap::from_iter([(
                CONNECTION,
                HeaderValue::from_static("close"),
            )]))
            .send()
            .await
        {
            Err(error) => panic!("failure: {error:?}"),
            Ok(response) => {
                assert_eq!(response.status(), StatusCode::from_u16(400).unwrap());
                assert!(response
                    .text()
                    .await
                    .unwrap()
                    .contains("Cannot connect to clearnet address, outproxy not enabled"));
            }
        };
    }

    #[tokio::test]
    async fn outproxy_not_found_in_address_book() {
        let sam_port = {
            let sam = SamServer::new().await;
            let port = sam.listener.local_addr().unwrap().port();
            tokio::spawn(sam.run());

            port
        };

        // create empty address book
        let address_book = {
            let dir = tempdir().unwrap().into_path();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();
            tokio::fs::File::create(dir.join("addressbook/addresses")).await.unwrap();

            AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                },
            )
            .handle()
        };

        let proxy = HttpProxy::new(
            HttpProxyConfig {
                port: 0,
                host: "127.0.0.1".to_string(),
                outproxy: Some("outproxy.i2p".to_string()),
            },
            sam_port,
            None,
            Some(address_book),
        )
        .await
        .unwrap();
        let port = proxy.listener.local_addr().unwrap().port();
        tokio::spawn(proxy.run());

        let client = Client::builder()
            .proxy(Proxy::http(format!("http://127.0.0.1:{port}")).expect("to succeed"))
            .http1_title_case_headers()
            .build()
            .expect("to succeed");

        match client
            .get("http://google.com")
            .headers(HeaderMap::from_iter([(
                CONNECTION,
                HeaderValue::from_static("close"),
            )]))
            .send()
            .await
        {
            Err(error) => panic!("failure: {error:?}"),
            Ok(response) => {
                assert_eq!(response.status(), StatusCode::from_u16(400).unwrap());
                assert!(response
                    .text()
                    .await
                    .unwrap()
                    .contains("Cannot connect to clearnet address, outproxy not enabled"));
            }
        };
    }

    #[tokio::test]
    async fn outproxy_resolved_from_i2p_hostname() {
        let sam_port = {
            let sam = SamServer::new().await;
            let port = sam.listener.local_addr().unwrap().port();
            tokio::spawn(sam.run());

            port
        };

        // create empty address book
        let address_book = {
            let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO\
                57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwcea\
                TMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1k\
                OIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypc\
                R1D1WY2tDqMKRYFVyLE~MTPVjRRgXfcKolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJM\
                BQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#\
                sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAXgKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBT\
                xQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5\
                JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpT\
                tcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtH\
                AsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9nBdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs\
                3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2p=a11l91etedRW5Kl2GhdDI9qiRBbD\
                RAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJPUlGlh9yIfBY40CQ0Ermy8gz\
                jHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpBZz~vIaG9matUSHinop\
                Eo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPybmvsD1SCbMQ2\
                ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lzS9GWf\
                2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUE\
                VgDZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5U\
                QW96kgL8SWcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJ\
                AUkk~8gLqgJwoUYhbfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvI\
                bl36iuIduZnGKPEBD31hVLdJuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM\
                6l~BvPl2OKQIBhXIxJLOOavGyqmmYmAAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCj\
                FTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC\
                3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94\
                E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~\
                DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjj\
                xlFBsjUJyYkFjBQAEAAcAAA==".to_string();

            let dir = tempdir().unwrap().into_path();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();
            tokio::fs::write(dir.join("addressbook/addresses"), hosts).await.unwrap();

            AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                },
            )
            .handle()
        };

        // no prefixes
        {
            let proxy = HttpProxy::new(
                HttpProxyConfig {
                    port: 0,
                    host: "127.0.0.1".to_string(),
                    outproxy: Some("zzz.i2p".to_string()),
                },
                sam_port,
                None,
                Some(address_book.clone()),
            )
            .await
            .unwrap();

            assert_eq!(
                proxy.outproxy.as_ref().unwrap().as_str(),
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
            );
        }

        // www. prefix
        {
            let proxy = HttpProxy::new(
                HttpProxyConfig {
                    port: 0,
                    host: "127.0.0.1".to_string(),
                    outproxy: Some("www.zzz.i2p".to_string()),
                },
                sam_port,
                None,
                Some(address_book.clone()),
            )
            .await
            .unwrap();

            assert_eq!(
                proxy.outproxy.as_ref().unwrap().as_str(),
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
            );
        }

        // http:// prefix
        {
            let proxy = HttpProxy::new(
                HttpProxyConfig {
                    port: 0,
                    host: "127.0.0.1".to_string(),
                    outproxy: Some("http://zzz.i2p".to_string()),
                },
                sam_port,
                None,
                Some(address_book.clone()),
            )
            .await
            .unwrap();

            assert_eq!(
                proxy.outproxy.as_ref().unwrap().as_str(),
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
            );
        }

        // http://www. prefix
        {
            let proxy = HttpProxy::new(
                HttpProxyConfig {
                    port: 0,
                    host: "127.0.0.1".to_string(),
                    outproxy: Some("http://www.zzz.i2p".to_string()),
                },
                sam_port,
                None,
                Some(address_book.clone()),
            )
            .await
            .unwrap();

            assert_eq!(
                proxy.outproxy.as_ref().unwrap().as_str(),
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
            );
        }

        // http://www. .b32.i2p host
        {
            let proxy = HttpProxy::new(
                HttpProxyConfig {
                    port: 0,
                    host: "127.0.0.1".to_string(),
                    outproxy: Some(
                        "http://www.lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
                            .to_string(),
                    ),
                },
                sam_port,
                None,
                Some(address_book.clone()),
            )
            .await
            .unwrap();

            assert_eq!(
                proxy.outproxy.as_ref().unwrap().as_str(),
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
            );
        }

        // http:// .b32.i2p host
        {
            let proxy = HttpProxy::new(
                HttpProxyConfig {
                    port: 0,
                    host: "127.0.0.1".to_string(),
                    outproxy: Some(
                        "http://lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
                            .to_string(),
                    ),
                },
                sam_port,
                None,
                Some(address_book.clone()),
            )
            .await
            .unwrap();

            assert_eq!(
                proxy.outproxy.as_ref().unwrap().as_str(),
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
            );
        }

        // http:// .b32.i2p host
        {
            let proxy = HttpProxy::new(
                HttpProxyConfig {
                    port: 0,
                    host: "127.0.0.1".to_string(),
                    outproxy: Some(
                        "www.lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
                            .to_string(),
                    ),
                },
                sam_port,
                None,
                Some(address_book.clone()),
            )
            .await
            .unwrap();

            assert_eq!(
                proxy.outproxy.as_ref().unwrap().as_str(),
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
            );
        }

        // .b32.i2p host
        {
            let proxy = HttpProxy::new(
                HttpProxyConfig {
                    port: 0,
                    host: "127.0.0.1".to_string(),
                    outproxy: Some(
                        "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".to_string(),
                    ),
                },
                sam_port,
                None,
                Some(address_book.clone()),
            )
            .await
            .unwrap();

            assert_eq!(
                proxy.outproxy.as_ref().unwrap().as_str(),
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
            );
        }
    }
}
