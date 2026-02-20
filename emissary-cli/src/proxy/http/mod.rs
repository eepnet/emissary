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
use futures::channel::oneshot;
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
        let tunnel_config = config.tunnel_config.unwrap_or_default();
        let session = Session::<style::Stream>::new(SessionOptions {
            publish: false,
            samv3_tcp_port,
            nickname: "http-proxy".to_string(),
            inbound_len: tunnel_config.inbound_len,
            inbound_quantity: tunnel_config.inbound_count,
            outbound_len: tunnel_config.outbound_len,
            outbound_quantity: tunnel_config.outbound_count,
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
                        (false, Some(handle)) => match handle.resolve_base32(outproxy) {
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
                tunnel_config: None,
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
                tunnel_config: None,
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
            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();
            tokio::fs::File::create(dir.join("addressbook/addresses")).await.unwrap();

            AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                },
            )
            .await
            .handle()
        };

        let proxy = HttpProxy::new(
            HttpProxyConfig {
                port: 0,
                host: "127.0.0.1".to_string(),
                outproxy: None,
                tunnel_config: None,
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
                tunnel_config: None,
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
                tunnel_config: None,
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
            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();
            tokio::fs::File::create(dir.join("addressbook/addresses")).await.unwrap();

            AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                },
            )
            .await
            .handle()
        };

        let proxy = HttpProxy::new(
            HttpProxyConfig {
                port: 0,
                host: "127.0.0.1".to_string(),
                outproxy: Some("outproxy.i2p".to_string()),
                tunnel_config: None,
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
            let hosts = "psi.i2p=avviiexdngd32ccoy4kuckvc3mkf53ycvzbz6vz75vzhv4tbpk5a\n\
                    zerobin.i2p=3564erslxzaoucqasxsjerk4jz2xril7j2cbzd4p7flpb4ut67hq\n\
                    tracker2.postman.i2p=6a4kxkg5wp33p25qqhgwl6sj4yh4xuf5b3p3qldwgclebchm3eea\n\
                    zzz.i2p=lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua\n"
                .to_string();

            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();
            tokio::fs::write(dir.join("addressbook/addresses"), hosts).await.unwrap();

            AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                },
            )
            .await
            .handle()
        };

        // no prefixes
        {
            let proxy = HttpProxy::new(
                HttpProxyConfig {
                    port: 0,
                    host: "127.0.0.1".to_string(),
                    outproxy: Some("zzz.i2p".to_string()),
                    tunnel_config: None,
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
                    tunnel_config: None,
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
                    tunnel_config: None,
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
                    tunnel_config: None,
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
                    tunnel_config: None,
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
                    tunnel_config: None,
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
                    tunnel_config: None,
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
                    tunnel_config: None,
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
