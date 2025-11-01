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

use crate::proxy::http::{HttpError, LOG_TARGET};

use emissary_core::runtime::AddressBook;

use std::sync::{Arc, LazyLock};

/// Illegal HTTP headers that get removed from the inbound HTTP request.
static ILLEGAL: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    Vec::from_iter([
        "accept",
        "referer",
        "x-requested-with",
        "via",
        "from",
        "forwarded",
        "dnt",
        "x-forwarded",
        "proxy-",
    ])
});

/// Host kind.
#[derive(Debug, PartialEq, Eq)]
pub enum HostKind {
    /// .i2p host.
    ///
    /// Address book must've been enabled and the host must exist in address book.
    I2p {
        /// Host
        host: String,
    },

    /// .b32.i2p host
    B32 {
        /// Host.
        host: String,
    },

    /// Clearnet host.
    ///
    /// Outproxy must exist.
    Clearnet {
        /// Host.
        host: String,
    },
}

/// Parsed request.
#[derive(Debug)]
pub struct Request {
    /// Host kind.
    host: HostKind,

    /// Method.
    method: String,

    /// Path.
    path: String,

    /// Request.
    request: Vec<u8>,
}

impl Request {
    /// Parse request.
    ///
    /// Ensure `request` is a valid HTTP request, extract the method and path and parse the host of
    /// the request into `HostKind` which will later on be used to check if the request can actually
    /// be made to the request remote host.
    ///
    /// If the parsed is [`HostKind::Clearnet`], an outproxy must have been configured and if the
    /// parsed host is [`HostKind::I2p`], address book must have been enabled and the .i2p host must
    /// be found int the address book.
    pub fn parse(request: Vec<u8>) -> Result<Self, HttpError> {
        // parse request and create a new request with sanitized headers
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let httparse::Status::Complete(_) = req.parse(&request)? else {
            tracing::warn!(
                target: LOG_TARGET,
                "received partial response",
            );
            debug_assert!(false);
            return Err(HttpError::PartialRequest);
        };

        let method = match req.method {
            None => return Err(HttpError::MethodMissing),
            Some("GET") => "GET".to_string(),
            Some("POST") => "POST".to_string(),
            Some("CONNECT") => "CONNECT".to_string(),
            Some(method) => return Err(HttpError::MethodNotSupported(method.to_string())),
        };

        let path = match url::Url::parse(req.path.ok_or(HttpError::InvalidPath)?) {
            Ok(url) => match url.query() {
                Some(query) => format!("{}?{query}", url.path()),
                None if method == "CONNECT" => url.to_string(),
                None => url.path().to_string(),
            },
            Err(_) => req.path.ok_or(HttpError::InvalidPath)?.to_string(),
        };

        let host = match req.headers.iter().find(|header| header.name.to_lowercase() == "host") {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "host missing",
                );
                return Err(HttpError::InvalidHost);
            }
            Some(host) => {
                let host = std::str::from_utf8(host.value).map_err(|_| HttpError::Malformed)?;
                let host = host.strip_prefix("www.").unwrap_or(host).to_string();

                match host.ends_with(".i2p") {
                    false => HostKind::Clearnet { host },
                    true => match host.ends_with(".b32.i2p") {
                        false => HostKind::I2p { host },
                        true => HostKind::B32 { host },
                    },
                }
            }
        };

        Ok(Self {
            host,
            method,
            path,
            request,
        })
    }

    /// Attempt to assemble [`Request`] into a serialized request that can be sent to remote host.
    ///
    /// Takes two parameters: `address_book` and `outproxy`. `address_book` is used to resolve .i2p
    /// host into a .b32.i2p host, if host is [`HostKind::I2p`]. If `address_book` doesn't exist or
    /// the .i2p host was not found in the address book, an error is returned to indicate that the
    /// request could not be assmebled. `outproxy` is the .b32.i2p host of the outproxy, if
    /// configured, and it must exist if host is [`HostKind::Clearnet`].
    ///
    /// The function constructs a new HTTP request, setting the correct user agent and stripping any
    /// "illegal" headers before returning it to the caller, allowing them to send it to remote
    /// host.
    ///
    /// Returns a `(host, request)` tuple where the `host` is the .b32.i2p address of the remote
    /// host SAM should connect to (either an eepsite or an outproxy) and where `request` is a
    /// serialized HTTP request.
    pub async fn assemble(
        self,
        address_book: &Option<Arc<dyn AddressBook>>,
        outproxy: &Option<String>,
    ) -> Result<(String, Vec<u8>), HttpError> {
        let user_agent = match &self.host {
            HostKind::Clearnet { .. } =>
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0\r\n",
            _ => "User-Agent: MYOB/6.66 (AN/ON)\r\n",
        };

        // resolve host for the request
        //
        // .b32.i2p: no modifications needed
        // .i2p:     attempt to resolve .i2p host to .b32.i2p host
        // clearnet: ensure outproxy has been configured and return its .b32.i2p hostname
        //
        // if a clearnet address is used and an outproxy has been enabled, the host that is the
        // original request must be kept unmodified as the request is sent to clearnet and such
        // an address obviously doesn't need to (and cannot be) resolved to a .b32.i2p hostname
        let (host, keep_original_host) = match (self.host, address_book, outproxy) {
            (HostKind::B32 { host }, _, _) => (host, false),
            (HostKind::I2p { host }, Some(address_book), _) =>
                match address_book.resolve_b32(&host) {
                    Some(host) => (format!("{host}.b32.i2p"), false),
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %host,
                            ".i2p host not found in the address book",
                        );
                        return Err(HttpError::HostNotFound);
                    }
                },
            (HostKind::Clearnet { .. }, _, Some(outproxy)) => (outproxy.clone(), true),
            (HostKind::I2p { host }, None, _) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %host,
                    "cannot connect to .i2p host, address book not enabled"
                );
                return Err(HttpError::AddressBookNotEnabled);
            }
            (HostKind::Clearnet { host }, _, None) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %host,
                    "cannot connect to clearnet host, outproxy not enabled",
                );
                return Err(HttpError::OutproxyNotEnabled);
            }
        };

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let body_start = req.parse(&self.request)?.unwrap();

        let mut sanitized = Vec::new();

        sanitized.extend_from_slice(format!("{} ", self.method).as_bytes());
        sanitized.extend_from_slice(format!("{} ", self.path).as_bytes());
        sanitized.extend_from_slice("HTTP/1.1\r\n".as_bytes());
        sanitized.extend_from_slice(user_agent.as_bytes());

        for header in req.headers.iter_mut() {
            if header.name.to_lowercase().starts_with("accept") {
                if header.name.to_lowercase() == "accept-encoding" {
                    sanitized.extend_from_slice("Accept-Encoding: ".as_bytes());
                    sanitized.extend_from_slice(header.value);
                    sanitized.extend_from_slice("\r\n".as_bytes());
                }
                continue;
            }

            // modify host if not explicitly forbidden
            //
            // the host must be modified for .i2p requests as otherwise the request would leak
            // information about local addressbook
            //
            // the host must be kept unmodified for clearnet requests going through an outproxy
            if header.name.to_lowercase() == "host" && !keep_original_host {
                sanitized.extend_from_slice("Host: ".as_bytes());
                sanitized.extend_from_slice(host.as_bytes());
                sanitized.extend_from_slice("\r\n".as_bytes());
                continue;
            }

            if header.name.to_lowercase() == "connection" {
                match std::str::from_utf8(header.value) {
                    Ok(value) if value.to_lowercase() == "upgrade" => {
                        sanitized.extend_from_slice("Connection: upgrade\r\n".as_bytes());
                    }
                    _ => sanitized.extend_from_slice("Connection: close\r\n".as_bytes()),
                }

                continue;
            }

            if header.name.to_lowercase() == "referer" {
                let Ok(value) = std::str::from_utf8(header.value) else {
                    continue;
                };

                if value.contains(&host) {
                    sanitized.extend_from_slice("Referer: ".as_bytes());
                    sanitized.extend_from_slice(header.value);
                    sanitized.extend_from_slice("\r\n".as_bytes());
                } else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?value,
                        "skipping invalid `Referer`",
                    )
                }

                continue;
            }

            // ignore User-Agent as it has already been added
            if header.name.to_lowercase() == "user-agent" {
                continue;
            }

            if ILLEGAL.iter().any(|illegal| header.name.to_lowercase().starts_with(illegal)) {
                tracing::warn!(
                    target: LOG_TARGET,
                    name = ?header.name,
                    value = ?(std::str::from_utf8(header.value)),
                    "skipping illegal header",
                );
                continue;
            }

            sanitized.extend_from_slice(format!("{}: ", header.name).as_bytes());
            sanitized.extend_from_slice(header.value);
            sanitized.extend_from_slice("\r\n".as_bytes());
        }

        sanitized.extend_from_slice("\r\n".as_bytes());
        sanitized.extend_from_slice(&self.request[body_start..]);

        Ok((host, sanitized))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{address_book::AddressBookManager, config::AddressBookConfig};
    use std::path::PathBuf;
    use tempfile::tempdir;

    async fn make_address_book() -> (Arc<dyn AddressBook>, PathBuf) {
        let hosts = "psi.i2p=avviiexdngd32ccoy4kuckvc3mkf53ycvzbz6vz75vzhv4tbpk5a\n\
                    zerobin.i2p=3564erslxzaoucqasxsjerk4jz2xril7j2cbzd4p7flpb4ut67hq\n\
                    tracker2.postman.i2p=6a4kxkg5wp33p25qqhgwl6sj4yh4xuf5b3p3qldwgclebchm3eea\n\
                    zzz.i2p=lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua\n"
            .to_string();

        let dir = tempdir().unwrap().keep();
        tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();
        tokio::fs::write(dir.join("addressbook/addresses"), hosts).await.unwrap();

        let address_book = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: Some(String::from("url")),
                subscriptions: None,
            },
        )
        .await;

        (address_book.handle(), dir.join("addressbook/addresses"))
    }

    #[tokio::test]
    async fn get_accepted() {
        let request = "GET / HTTP/1.1\r\n\
                    Host: lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p\r\n\r\n"
            .as_bytes()
            .to_vec();

        let Request {
            host,
            request,
            method,
            path,
        } = Request::parse(request).unwrap();

        assert_eq!(
            host,
            HostKind::B32 {
                host: "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".to_string()
            }
        );
        assert_eq!(method, "GET".to_string());
        assert_eq!(path, "/".to_string());

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(
            req.headers.iter().find(|header| header.name == "Host").unwrap().value,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".as_bytes(),
        );
    }

    #[tokio::test]
    async fn get_full_path() {
        let request = "GET http://www.lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p HTTP/1.1\r\n\
                            Host: www.lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p\r\n\r\n"
            .as_bytes()
            .to_vec();
        let request = Request::parse(request).unwrap();

        assert_eq!(
            request.host,
            HostKind::B32 {
                host: "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".to_string()
            }
        );
        assert_eq!(request.method, "GET".to_string());
        assert_eq!(request.path, "/".to_string());

        // assemble request and verify `Host` is valid
        let (host, request) = request.assemble(&None, &None).await.unwrap();

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(
            req.headers.iter().find(|header| header.name == "Host").unwrap().value,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".as_bytes(),
        );
        assert_eq!(
            host.as_str(),
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p",
        );
    }

    #[tokio::test]
    async fn www_stripped_from_host() {
        let request = "GET / HTTP/1.1\r\nHost: \
                        www.lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p\r\n\r\n"
            .as_bytes()
            .to_vec();
        let request = Request::parse(request).unwrap();

        assert_eq!(
            request.host,
            HostKind::B32 {
                host: "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".to_string()
            }
        );
        assert_eq!(request.method, "GET".to_string());
        assert_eq!(request.path, "/".to_string());

        let (host, request) = request.assemble(&None, &None).await.unwrap();
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("GET"));
        assert_eq!(req.path, Some("/"));
        assert_eq!(
            host.as_str(),
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p",
        );
        assert_eq!(
            req.headers.iter().find(|header| header.name == "Host").unwrap().value,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".as_bytes(),
        );
    }

    #[tokio::test]
    async fn converted_to_relative_path() {
        let request = "GET http://www.lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p/topics/new-topic?query=1 \
                        HTTP/1.1\r\nHost: www.lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p\r\n\r\n".as_bytes().to_vec();
        let request = Request::parse(request).unwrap();

        assert_eq!(
            request.host,
            HostKind::B32 {
                host: "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".to_string()
            }
        );
        assert_eq!(request.method, "GET".to_string());
        assert_eq!(request.path, "/topics/new-topic?query=1".to_string());

        let (host, request) = request.assemble(&None, &None).await.unwrap();
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("GET"));
        assert_eq!(req.path, Some("/topics/new-topic?query=1"));
        assert_eq!(
            host.as_str(),
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p",
        );
        assert_eq!(
            req.headers.iter().find(|header| header.name == "Host").unwrap().value,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".as_bytes(),
        );
    }

    #[tokio::test]
    async fn post_accepted() {
        let request = "POST /upload HTTP/1.1\r\n\
                        Host: www.lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p\r\n\
                        Content-Type: text/plain\r\n\
                        Content-Length: 12\r\n\r\n\
                        hello, world"
            .as_bytes()
            .to_vec();

        let request = Request::parse(request).unwrap();
        assert_eq!(
            request.host,
            HostKind::B32 {
                host: "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".to_string()
            }
        );
        assert_eq!(request.method, "POST".to_string());
        assert_eq!(request.path, "/upload".to_string());

        let (host, request) = request.assemble(&None, &None).await.unwrap();
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("POST"));
        assert_eq!(req.path, Some("/upload"));
        assert_eq!(
            std::str::from_utf8(&request[_body_start..]).unwrap(),
            "hello, world"
        );
        assert_eq!(
            req.headers.iter().find(|header| header.name == "Host").unwrap().value,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".as_bytes(),
        );
        assert_eq!(
            host.as_str(),
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p",
        );
        assert_eq!(
            req.headers.iter().find(|header| header.name == "Content-Length").unwrap().value,
            "12".as_bytes(),
        );
    }

    #[test]
    #[should_panic]
    fn read_partial_request() {
        let request = "GET / HTTP/1.1\r\nHost".as_bytes().to_vec();
        let _ = Request::parse(request).unwrap();
    }

    #[tokio::test]
    async fn i2p_host_address_book_disabled() {
        let request = "GET / HTTP/1.1\r\nHost: host.i2p\r\n\r\n".as_bytes().to_vec();
        let request = Request::parse(request).unwrap();

        assert_eq!(
            request.host,
            HostKind::I2p {
                host: "host.i2p".to_string()
            }
        );
        assert_eq!(request.method, "GET".to_string());
        assert_eq!(request.path, "/".to_string());
        assert_eq!(
            request.assemble(&None, &None).await.unwrap_err(),
            HttpError::AddressBookNotEnabled
        );
    }

    #[tokio::test]
    async fn i2p_host_not_found_in_address_book() {
        let address_book = make_address_book().await.0;
        let request = "GET / HTTP/1.1\r\nHost: host.i2p\r\n\r\n".as_bytes().to_vec();
        let request = Request::parse(request).unwrap();

        assert_eq!(
            request.host,
            HostKind::I2p {
                host: "host.i2p".to_string()
            }
        );
        assert_eq!(request.method, "GET".to_string());
        assert_eq!(request.path, "/".to_string());
        assert_eq!(
            request.assemble(&Some(address_book), &None).await.unwrap_err(),
            HttpError::HostNotFound
        );
    }

    #[tokio::test]
    async fn i2p_host_found_in_address_book() {
        let address_book = make_address_book().await.0;
        let request = "GET / HTTP/1.1\r\nHost: zzz.i2p\r\n\r\n".as_bytes().to_vec();
        let request = Request::parse(request).unwrap();

        assert_eq!(
            request.host,
            HostKind::I2p {
                host: "zzz.i2p".to_string()
            }
        );
        assert_eq!(request.method, "GET".to_string());
        assert_eq!(request.path, "/".to_string());

        let (host, request) = request.assemble(&Some(address_book), &None).await.unwrap();
        assert_eq!(
            host.as_str(),
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
        );

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("GET"));
        assert_eq!(req.path, Some("/"));
        assert_eq!(
            req.headers.iter().find(|header| header.name == "Host").unwrap().value,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".as_bytes(),
        );
    }

    #[tokio::test]
    async fn converted_to_relative_path_host_lookup() {
        let address_book = make_address_book().await.0;
        let request = "GET http://www.zzz.i2p.b32.i2p/topics/new-topic?query=1 HTTP/1.1\r\nHost: www.zzz.i2p\r\n\r\n"
            .as_bytes()
            .to_vec();
        let request = Request::parse(request).unwrap();

        assert_eq!(
            request.host,
            HostKind::I2p {
                host: "zzz.i2p".to_string()
            }
        );
        assert_eq!(request.method, "GET".to_string());
        assert_eq!(request.path, "/topics/new-topic?query=1".to_string());

        let (host, request) = request.assemble(&Some(address_book), &None).await.unwrap();
        assert_eq!(
            host.as_str(),
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
        );

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("GET"));
        assert_eq!(req.path, Some("/topics/new-topic?query=1"));
        assert_eq!(
            req.headers.iter().find(|header| header.name == "Host").unwrap().value,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".as_bytes(),
        );
    }

    #[tokio::test]
    async fn i2p_host_found_in_b32_cache() {
        let (address_book, path) = make_address_book().await;

        // first query which does a lookup to disk
        {
            let request = "GET / HTTP/1.1\r\nHost: zzz.i2p\r\n\r\n".as_bytes().to_vec();
            let request = Request::parse(request).unwrap();

            assert_eq!(
                request.host,
                HostKind::I2p {
                    host: "zzz.i2p".to_string()
                }
            );
            assert_eq!(request.method, "GET".to_string());
            assert_eq!(request.path, "/".to_string());

            let (host, request) =
                request.assemble(&Some(address_book.clone()), &None).await.unwrap();
            assert_eq!(
                host.as_str(),
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
            );

            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            let _body_start = req.parse(&request).unwrap().unwrap();

            assert_eq!(req.method, Some("GET"));
            assert_eq!(req.path, Some("/"));
            assert_eq!(
                req.headers.iter().find(|header| header.name == "Host").unwrap().value,
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".as_bytes(),
            );
        }

        // remove address book file
        tokio::fs::remove_file(path).await.unwrap();

        // address book is removed from disk but zzz.i2p has been cached
        {
            let request = "GET / HTTP/1.1\r\nHost: zzz.i2p\r\n\r\n".as_bytes().to_vec();
            let request = Request::parse(request).unwrap();

            assert_eq!(
                request.host,
                HostKind::I2p {
                    host: "zzz.i2p".to_string()
                }
            );
            assert_eq!(request.method, "GET".to_string());
            assert_eq!(request.path, "/".to_string());

            let (host, request) = request.assemble(&Some(address_book), &None).await.unwrap();
            assert_eq!(
                host.as_str(),
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p"
            );

            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            let _body_start = req.parse(&request).unwrap().unwrap();

            assert_eq!(req.method, Some("GET"));
            assert_eq!(req.path, Some("/"));
            assert_eq!(
                req.headers.iter().find(|header| header.name == "Host").unwrap().value,
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".as_bytes(),
            );
        }
    }

    #[tokio::test]
    async fn clearnet_host_no_outproxy() {
        let request = "GET / HTTP/1.1\r\nHost: host.com\r\n\r\n".as_bytes().to_vec();
        let request = Request::parse(request).unwrap();

        assert_eq!(
            request.host,
            HostKind::Clearnet {
                host: "host.com".to_string()
            }
        );
        assert_eq!(request.method, "GET".to_string());
        assert_eq!(request.path, "/".to_string());

        assert_eq!(
            request.assemble(&None, &None).await.unwrap_err(),
            HttpError::OutproxyNotEnabled
        );
    }

    #[tokio::test]
    async fn clearnet_host_outproxy_enabled() {
        let request = "GET / HTTP/1.1\r\nHost: host.com\r\n\r\n".as_bytes().to_vec();
        let request = Request::parse(request).unwrap();

        assert_eq!(
            request.host,
            HostKind::Clearnet {
                host: "host.com".to_string()
            }
        );
        assert_eq!(request.method, "GET".to_string());
        assert_eq!(request.path, "/".to_string());

        let (host, request) = request
            .assemble(
                &None,
                &Some("lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(
            host,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".to_string()
        );

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("GET"));
        assert_eq!(req.path, Some("/"));
        assert_eq!(
            req.headers.iter().find(|header| header.name == "Host").unwrap().value,
            "host.com".as_bytes()
        );
    }

    #[tokio::test]
    async fn connect_accepted() {
        let request = "CONNECT www.google.com:443 HTTP/1.1\r\n\
            User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Firefox/122.0\r\n\
            Proxy-Connection: keep-alive\r\n\
            Connection: keep-alive\r\n\
            Host: www.google.com:443\r\n\r\n"
            .as_bytes()
            .to_vec();
        let request = Request::parse(request).unwrap();

        assert_eq!(
            request.host,
            HostKind::Clearnet {
                host: "google.com:443".to_string()
            }
        );
        assert_eq!(request.method, "CONNECT".to_string());
        assert_eq!(request.path, "www.google.com:443".to_string());

        let (host, request) = request
            .assemble(
                &None,
                &Some("lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(
            host,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p".to_string()
        );

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("CONNECT"));
        assert_eq!(req.path, Some("www.google.com:443"));
        assert_eq!(
            req.headers.iter().find(|header| header.name == "Host").unwrap().value,
            "www.google.com:443".as_bytes()
        );
        assert_eq!(
            req.headers.iter().find(|header| header.name == "User-Agent").unwrap().value,
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0".as_bytes(),
        );
    }
}
