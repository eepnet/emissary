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

use emissary_core::{
    crypto::base32_encode, events::EventSubscriber, router::Router, runtime::AddressBook, Config,
    Ntcp2Config, SamConfig, Ssu2Config, TransitConfig,
};
use emissary_util::runtime::tokio::Runtime;
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinSet,
};
use yosemite::{
    style::{Anonymous, Primary, Repliable, Stream},
    DestinationKind, Error, I2pError, ProtocolError, RouterApi, Session, SessionOptions,
};

use std::{fs::File, future::Future, io::Read, pin::Pin, sync::Arc, time::Duration};

#[derive(Clone, Copy)]
enum TransportKind {
    Ntcp2,
    Ssu2,
}

async fn make_router(
    floodfill: bool,
    net_id: u8,
    routers: Vec<Vec<u8>>,
    kind: TransportKind,
) -> (Router<Runtime>, EventSubscriber, Vec<u8>) {
    let (ntcp2, ssu2) = match kind {
        TransportKind::Ntcp2 => (
            Some(Ntcp2Config {
                port: 0u16,
                iv: {
                    let mut iv = [0u8; 16];
                    thread_rng().fill_bytes(&mut iv);
                    iv
                },
                key: {
                    let mut key = [0u8; 32];
                    thread_rng().fill_bytes(&mut key);
                    key
                },
                host: Some("127.0.0.1".parse().unwrap()),
                publish: true,
            }),
            None,
        ),
        TransportKind::Ssu2 => (
            None,
            Some(Ssu2Config {
                port: 0u16,
                host: Some("127.0.0.1".parse().unwrap()),
                publish: true,

                static_key: {
                    let mut iv = [0u8; 32];
                    thread_rng().fill_bytes(&mut iv);
                    iv
                },
                intro_key: {
                    let mut key = [0u8; 32];
                    thread_rng().fill_bytes(&mut key);
                    key
                },
            }),
        ),
    };

    let config = Config {
        net_id: Some(net_id),
        floodfill,
        insecure_tunnels: true,
        allow_local: true,
        metrics: None,
        ntcp2,
        ssu2,
        routers,
        samv3_config: Some(SamConfig {
            tcp_port: 0u16,
            udp_port: 0u16,
            host: "127.0.0.1".to_string(),
        }),
        transit: Some(TransitConfig {
            max_tunnels: Some(5000),
        }),
        ..Default::default()
    };

    Router::<Runtime>::new(config, None, None).await.unwrap()
}

#[tokio::test]
async fn generate_destination_ntcp2() {
    generate_destination(TransportKind::Ntcp2).await;
}

#[tokio::test]
async fn generate_destination_ssu2() {
    generate_destination(TransportKind::Ssu2).await;
}

async fn generate_destination(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create the sam router and fetch the random sam tcp port from the router
    let router = make_router(false, net_id, router_infos.clone(), kind).await.0;
    let sam_tcp = router.protocol_address_info().sam_tcp.unwrap().port();

    // spawn the router inte background and wait a moment for the network to boot
    tokio::spawn(router);
    tokio::time::sleep(Duration::from_secs(15)).await;

    // generate new destination and create new session using the destination
    let (_destination, private_key) = tokio::time::timeout(
        Duration::from_secs(5),
        RouterApi::new(sam_tcp).generate_destination(),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let _session = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            destination: DestinationKind::Persistent { private_key },
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
}

#[tokio::test]
async fn streaming_works_ntcp2() {
    streaming_works(TransportKind::Ntcp2).await;
}

#[tokio::test]
async fn streaming_works_ssu2() {
    streaming_works(TransportKind::Ssu2).await;
}

async fn streaming_works(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<u16>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push(router.protocol_address_info().sam_tcp.unwrap().port());
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session1.destination().to_owned();

    let handle = tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(15), session1.accept())
            .await
            .expect("no timeout")
            .expect("to succeed");

        stream.write_all(b"hello, world!\n").await.unwrap();

        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&buffer[..nread]),
            Ok("goodbye, world!\n")
        );

        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[1],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut stream = tokio::time::timeout(Duration::from_secs(10), session2.connect(&dest))
        .await
        .expect("no timeout")
        .expect("to succeed");

    let mut buffer = vec![0u8; 64];
    let nread = stream.read(&mut buffer).await.unwrap();

    assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));

    stream.write_all(b"goodbye, world!\n").await.unwrap();

    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn repliable_datagrams_work_ntcp2() {
    repliable_datagrams_work(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn repliable_datagrams_work_ssu2() {
    repliable_datagrams_work(TransportKind::Ssu2).await
}

async fn repliable_datagrams_work(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _event, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp/udp ports and spawn them in the background
    let mut ports = Vec::<(u16, u16)>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;
        let addr_info = router.protocol_address_info();

        ports.push((
            addr_info.sam_tcp.unwrap().port(),
            addr_info.sam_udp.unwrap().port(),
        ));
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Repliable>::new(SessionOptions {
            samv3_tcp_port: ports[0].0,
            samv3_udp_port: ports[0].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session1.destination().to_owned();

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Repliable>::new(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let handle = tokio::spawn(async move {
        let mut buffer = vec![0u8; 64];

        let (nread, from) =
            tokio::time::timeout(Duration::from_secs(10), session1.recv_from(&mut buffer))
                .await
                .expect("no timeout")
                .expect("to succeed");
        assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));

        session1.send_to(b"goodbye, world!\n", &from).await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    session2.send_to(b"hello, world!\n", &dest).await.unwrap();

    let mut buffer = vec![0u8; 64];
    let (nread, _from) =
        tokio::time::timeout(Duration::from_secs(10), session2.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("to succeed");

    assert_eq!(
        std::str::from_utf8(&buffer[..nread]),
        Ok("goodbye, world!\n"),
    );
    let _ = handle.await;
}

#[tokio::test]
async fn anonymous_datagrams_work_ntcp2() {
    anonymous_datagrams_work(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn anonymous_datagrams_work_ssu2() {
    anonymous_datagrams_work(TransportKind::Ssu2).await
}

async fn anonymous_datagrams_work(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp/udp ports and spawn them in the background
    let mut ports = Vec::<(u16, u16)>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;
        let addr_info = router.protocol_address_info();

        ports.push((
            addr_info.sam_tcp.unwrap().port(),
            addr_info.sam_udp.unwrap().port(),
        ));
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(60),
        Session::<Anonymous>::new(SessionOptions {
            samv3_tcp_port: ports[0].0,
            samv3_udp_port: ports[0].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest1 = session1.destination().to_owned();

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(60),
        Session::<Anonymous>::new(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest2 = session2.destination().to_owned();

    let handle = tokio::spawn(async move {
        let mut buffer = vec![0u8; 64];

        let nread = tokio::time::timeout(Duration::from_secs(30), session1.recv(&mut buffer))
            .await
            .expect("no timeout")
            .expect("to succeed");
        assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));

        session1.send_to(b"goodbye, world!\n", &dest2).await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    session2.send_to(b"hello, world!\n", &dest1).await.unwrap();

    let mut buffer = vec![0u8; 64];
    let nread = tokio::time::timeout(Duration::from_secs(30), session2.recv(&mut buffer))
        .await
        .expect("no timeout")
        .expect("to succeed");

    assert_eq!(
        std::str::from_utf8(&buffer[..nread]),
        Ok("goodbye, world!\n"),
    );
    let _ = handle.await;
}

#[tokio::test]
async fn open_stream_to_self_ntcp2() {
    open_stream_to_self(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn open_stream_to_self_ssu2() {
    open_stream_to_self(TransportKind::Ssu2).await
}

async fn open_stream_to_self(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create the sam router and fetch the random sam tcp port from the router
    let router = make_router(false, net_id, router_infos.clone(), kind).await.0;
    let sam_tcp = router.protocol_address_info().sam_tcp.unwrap().port();

    // spawn the router inte background and wait a moment for the network to boot
    tokio::spawn(router);
    tokio::time::sleep(Duration::from_secs(15)).await;

    let mut session = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session.destination().to_owned();

    match tokio::time::timeout(Duration::from_secs(10), session.connect(&dest))
        .await
        .expect("no timeout")
    {
        Err(Error::Protocol(ProtocolError::Router(I2pError::CantReachPeer))) => {}
        _ => panic!("unexpected result"),
    }
}

#[tokio::test]
async fn create_same_session_twice_transient_ntcp2() {
    create_same_session_twice_transient(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn create_same_session_twice_transient_ssu2() {
    create_same_session_twice_transient(TransportKind::Ssu2).await
}

async fn create_same_session_twice_transient(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create the sam router and fetch the random sam tcp port from the router
    let router = make_router(false, net_id, router_infos.clone(), kind).await.0;
    let sam_tcp = router.protocol_address_info().sam_tcp.unwrap().port();

    // spawn the router inte background and wait a moment for the network to boot
    tokio::spawn(router);
    tokio::time::sleep(Duration::from_secs(15)).await;

    let session = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session.destination().to_owned();

    match tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            destination: DestinationKind::Persistent { private_key: dest },
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    {
        Err(Error::Protocol(ProtocolError::Router(I2pError::DuplicateDest))) => {}
        _ => panic!("should not succeed"),
    }
}

#[tokio::test]
async fn create_same_session_twice_persistent_ntcp2() {
    create_same_session_twice_persistent(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn create_same_session_twice_persistent_ssu2() {
    create_same_session_twice_persistent(TransportKind::Ssu2).await
}

async fn create_same_session_twice_persistent(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create the sam router and fetch the random sam tcp port from the router
    let router = make_router(false, net_id, router_infos.clone(), kind).await.0;
    let sam_tcp = router.protocol_address_info().sam_tcp.unwrap().port();

    // spawn the router inte background and wait a moment for the network to boot
    tokio::spawn(router);
    tokio::time::sleep(Duration::from_secs(15)).await;

    // generate new destination and create new session using the destination
    let (_destination, private_key) = tokio::time::timeout(
        Duration::from_secs(5),
        RouterApi::new(sam_tcp).generate_destination(),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let _session = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            destination: DestinationKind::Persistent {
                private_key: private_key.clone(),
            },
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    match tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            destination: DestinationKind::Persistent { private_key },
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    {
        Err(Error::Protocol(ProtocolError::Router(I2pError::DuplicateDest))) => {}
        _ => panic!("should not succeed"),
    }
}

#[tokio::test]
async fn duplicate_session_id_ntcp2() {
    duplicate_session_id(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn duplicate_session_id_ssu2() {
    duplicate_session_id(TransportKind::Ssu2).await
}

async fn duplicate_session_id(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create the sam router and fetch the random sam tcp port from the router
    let router = make_router(false, net_id, router_infos.clone(), kind).await.0;
    let sam_tcp = router.protocol_address_info().sam_tcp.unwrap().port();

    // spawn the router inte background and wait a moment for the network to boot
    tokio::spawn(router);
    tokio::time::sleep(Duration::from_secs(15)).await;

    let _session = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            nickname: String::from("session_id"),
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    match tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            nickname: String::from("session_id"),
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    {
        Err(Error::Protocol(ProtocolError::Router(I2pError::DuplicateId))) => {}
        _ => panic!("should not succeed"),
    }
}

#[tokio::test]
async fn stream_lots_of_data_ntcp2() {
    stream_lots_of_data(TransportKind::Ntcp2).await
}

// more worker threads are needed because the test transfer a lot of data and it consist of running
// 6 routers without optimizations in a single thread which the executor doesn't like, causing
// immediate ACKs to be delayed up to 100ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_lots_of_data_ssu2() {
    stream_lots_of_data(TransportKind::Ssu2).await
}

async fn stream_lots_of_data(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<u16>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push(router.protocol_address_info().sam_tcp.unwrap().port());
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session1.destination().to_owned();

    // give the session some time to build rest of its inbound tunnels
    tokio::time::sleep(Duration::from_secs(5)).await;

    let (data, digest) = {
        let mut data = vec![0u8; 256 * 1024];
        thread_rng().fill_bytes(&mut data);

        let mut hasher = Sha256::new();
        hasher.update(&data);

        (data, hasher.finalize())
    };

    let handle = tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(15), session1.accept())
            .await
            .expect("no timeout")
            .expect("to succeed");

        stream.write_all(&data).await.unwrap();

        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[1],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut stream = tokio::time::timeout(Duration::from_secs(10), session2.connect(&dest))
        .await
        .expect("no timeout")
        .expect("to succeed");

    let mut buffer = vec![0u8; 256 * 1024];
    tokio::time::timeout(Duration::from_secs(120), stream.read_exact(&mut buffer))
        .await
        .expect("no timeout")
        .expect("to succeed");

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    assert_eq!(digest, hasher.finalize());

    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn forward_stream_ntcp2() {
    forward_stream(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn forward_stream_ssu2() {
    forward_stream(TransportKind::Ssu2).await
}

async fn forward_stream(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<u16>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push(router.protocol_address_info().sam_tcp.unwrap().port());
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0],
            silent_forward: true,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session1.destination().to_owned();

    let handle = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        session1.forward(listener.local_addr().unwrap().port()).await.unwrap();

        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"hello, world!\n").await.unwrap();

        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();

        assert_eq!(
            std::str::from_utf8(&buffer[..nread]),
            Ok("goodbye, world!\n")
        );

        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[1],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut stream = tokio::time::timeout(Duration::from_secs(10), session2.connect(&dest))
        .await
        .expect("no timeout")
        .expect("to succeed");

    let mut buffer = vec![0u8; 64];
    let nread = stream.read(&mut buffer).await.unwrap();

    assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));
    stream.write_all(b"goodbye, world!\n").await.unwrap();

    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn connect_to_inactive_destination_ntcp2() {
    connect_to_inactive_destination(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn connect_to_inactive_destination_ssu2() {
    connect_to_inactive_destination(TransportKind::Ssu2).await
}

async fn connect_to_inactive_destination(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create the sam router and fetch the random sam tcp port from the router
    let router = make_router(false, net_id, router_infos.clone(), kind).await.0;
    let sam_tcp = router.protocol_address_info().sam_tcp.unwrap().port();

    // spawn the router inte background and wait a moment for the network to boot
    tokio::spawn(router);
    tokio::time::sleep(Duration::from_secs(15)).await;

    // generate new destination and create new session using the destination
    let (destination, _private_key) = tokio::time::timeout(
        Duration::from_secs(5),
        RouterApi::new(sam_tcp).generate_destination(),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut session = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    match tokio::time::timeout(Duration::from_secs(60), session.connect(&destination))
        .await
        .expect("no timeout")
    {
        Err(Error::Protocol(ProtocolError::Router(I2pError::CantReachPeer))) => {}
        _ => panic!("unexpected result"),
    }
}

#[tokio::test]
async fn closed_stream_detected_ntcp2() {
    closed_stream_detected(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn closed_stream_detected_ssu2() {
    closed_stream_detected(TransportKind::Ssu2).await
}

async fn closed_stream_detected(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<u16>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push(router.protocol_address_info().sam_tcp.unwrap().port());
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session1.destination().to_owned();

    let handle = tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(15), session1.accept())
            .await
            .expect("no timeout")
            .expect("to succeed");

        stream.write_all(b"hello, world!\n").await.unwrap();

        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&buffer[..nread]),
            Ok("goodbye, world!\n")
        );
        stream.shutdown().await.unwrap();
        drop(stream);
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[1],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut stream = tokio::time::timeout(Duration::from_secs(10), session2.connect(&dest))
        .await
        .expect("no timeout")
        .expect("to succeed");

    let mut buffer = vec![0u8; 64];
    let nread = stream.read(&mut buffer).await.unwrap();

    assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));

    stream.write_all(b"goodbye, world!\n").await.unwrap();

    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
        .await
        .expect("no timeout")
    {
        Ok(0) => {}
        _ => panic!("unexpected result"),
    }

    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn close_and_reconnect_ntcp2() {
    close_and_reconnect(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn close_and_reconnect_ssu2() {
    close_and_reconnect(TransportKind::Ssu2).await
}

async fn close_and_reconnect(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<u16>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push(router.protocol_address_info().sam_tcp.unwrap().port());
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session1.destination().to_owned();

    let handle = tokio::spawn(async move {
        for _ in 0..2 {
            let mut stream = tokio::time::timeout(Duration::from_secs(15), session1.accept())
                .await
                .expect("no timeout")
                .expect("to succeed");

            stream.write_all(b"hello, world!\n").await.unwrap();

            let mut buffer = vec![0u8; 64];
            let nread = stream.read(&mut buffer).await.unwrap();
            assert_eq!(
                std::str::from_utf8(&buffer[..nread]),
                Ok("goodbye, world!\n")
            );
            stream.shutdown().await.unwrap();
            drop(stream);
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[1],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    for _ in 0..2 {
        let mut stream = tokio::time::timeout(Duration::from_secs(10), session2.connect(&dest))
            .await
            .expect("no timeout")
            .expect("to succeed");

        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();

        assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));

        stream.write_all(b"goodbye, world!\n").await.unwrap();

        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .expect("no timeout")
        {
            Ok(0) => {}
            _ => panic!("unexpected result"),
        }
    }

    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn create_multiple_sessions_ntcp2() {
    create_multiple_sessions(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn create_multiple_sessions_ssu2() {
    create_multiple_sessions(TransportKind::Ssu2).await
}

async fn create_multiple_sessions(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..6 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    let router = make_router(false, net_id, router_infos.clone(), kind).await.0;
    let port = router.protocol_address_info().sam_tcp.unwrap().port();
    tokio::spawn(router);

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let stream = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: port,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let repliable = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Repliable>::new(SessionOptions {
            samv3_tcp_port: port,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    drop(stream);
    drop(repliable);

    tokio::time::sleep(Duration::from_secs(2)).await;

    let _anonymous = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Anonymous>::new(SessionOptions {
            samv3_tcp_port: port,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
}

#[tokio::test]
async fn send_data_to_destroyed_session_ntcp2() {
    send_data_to_destroyed_session(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn send_data_to_destroyed_session_ssu2() {
    send_data_to_destroyed_session(TransportKind::Ssu2).await
}

async fn send_data_to_destroyed_session(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<u16>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push(router.protocol_address_info().sam_tcp.unwrap().port());
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session1.destination().to_owned();

    tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(15), session1.accept())
            .await
            .expect("no timeout")
            .expect("to succeed");

        stream.write_all(b"hello, world!\n").await.unwrap();

        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&buffer[..nread]),
            Ok("goodbye, world!\n")
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(session1);
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[1],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut stream = tokio::time::timeout(Duration::from_secs(10), session2.connect(&dest))
        .await
        .expect("no timeout")
        .expect("to succeed");

    let mut buffer = vec![0u8; 64];
    let nread = stream.read(&mut buffer).await.unwrap();

    assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));

    let future = async move {
        while (stream.write_all(b"goodbye, world!\n").await).is_ok() {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };

    tokio::time::timeout(Duration::from_secs(15), future).await.expect("no timeout");
}

#[tokio::test]
async fn connect_using_b32_i2p_ntcp2() {
    connect_using_b32_i2p(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn connect_using_b32_i2p_ssu2() {
    connect_using_b32_i2p(TransportKind::Ssu2).await
}

async fn connect_using_b32_i2p(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<u16>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push(router.protocol_address_info().sam_tcp.unwrap().port());
        tokio::spawn(router);
    }

    let private_key = {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/destination.b64");
        let mut file = File::open(path).unwrap();
        let mut private_key = String::new();

        file.read_to_string(&mut private_key).unwrap();
        private_key
    };

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0],
            destination: DestinationKind::Persistent { private_key },
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let handle = tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(15), session1.accept())
            .await
            .expect("no timeout")
            .expect("to succeed");

        stream.write_all(b"hello, world!\n").await.unwrap();

        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&buffer[..nread]),
            Ok("goodbye, world!\n")
        );

        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[1],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        session2.connect("fnkextln5uh3lafgvmuzcdr736cfced5f6fabdf5kq5dv5rj4jxq.b32.i2p"),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut buffer = vec![0u8; 64];
    let nread = stream.read(&mut buffer).await.unwrap();

    assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));

    stream.write_all(b"goodbye, world!\n").await.unwrap();

    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn unpublished_destination_ntcp2() {
    unpublished_destination(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn unpublished_destination_ssu2() {
    unpublished_destination(TransportKind::Ssu2).await
}

async fn unpublished_destination(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<u16>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push(router.protocol_address_info().sam_tcp.unwrap().port());
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0],
            publish: false,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session1.destination().to_owned();

    let handle = tokio::spawn(async move {
        match tokio::time::timeout(Duration::from_secs(15), session1.accept()).await {
            Err(_) => {}
            _ => panic!("unexpected success"),
        }
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[1],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    match tokio::time::timeout(Duration::from_secs(60), session2.connect(&dest))
        .await
        .expect("no timeout")
    {
        Err(Error::Protocol(ProtocolError::Router(I2pError::CantReachPeer))) => {}
        _ => panic!("unexpected result"),
    }

    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn host_lookup_ntcp2() {
    host_lookup(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn host_lookup_ssu2() {
    host_lookup(TransportKind::Ssu2).await
}

async fn host_lookup(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..6 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create router for the sam server
    let router = make_router(false, net_id, router_infos.clone(), kind).await.0;
    let sam_port = router.protocol_address_info().sam_tcp.unwrap().port();
    tokio::spawn(router);

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_port,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session1.destination().to_owned();

    let handle = tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(120), session1.accept())
            .await
            .expect("no timeout")
            .expect("to succeed");

        stream.write_all(b"hello, world!\n").await.unwrap();

        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&buffer[..nread]),
            Ok("goodbye, world!\n")
        );

        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let (ntcp2, ssu2) = match kind {
        TransportKind::Ntcp2 => (
            Some(Ntcp2Config {
                port: 0u16,
                iv: {
                    let mut iv = [0u8; 16];
                    thread_rng().fill_bytes(&mut iv);
                    iv
                },
                key: {
                    let mut key = [0u8; 32];
                    thread_rng().fill_bytes(&mut key);
                    key
                },
                host: Some("127.0.0.1".parse().unwrap()),
                publish: true,
            }),
            None,
        ),
        TransportKind::Ssu2 => (
            None,
            Some(Ssu2Config {
                port: 0u16,
                host: Some("127.0.0.1".parse().unwrap()),
                publish: true,

                static_key: {
                    let mut iv = [0u8; 32];
                    thread_rng().fill_bytes(&mut iv);
                    iv
                },
                intro_key: {
                    let mut key = [0u8; 32];
                    thread_rng().fill_bytes(&mut key);
                    key
                },
            }),
        ),
    };

    let config = Config {
        net_id: Some(net_id),
        floodfill: false,
        insecure_tunnels: true,
        allow_local: true,
        metrics: None,
        ntcp2,
        ssu2,
        routers: router_infos.clone(),
        samv3_config: Some(SamConfig {
            tcp_port: 0u16,
            udp_port: 0u16,
            host: "127.0.0.1".to_string(),
        }),
        ..Default::default()
    };

    struct AddressBookImpl {
        dest: String,
    }

    impl AddressBook for AddressBookImpl {
        fn resolve_base64(
            &self,
            _: String,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send>> {
            let dest = self.dest.clone();
            Box::pin(async move { Some(dest) })
        }

        fn resolve_base32(&self, _: &str) -> Option<String> {
            let dest = emissary_core::crypto::base64_decode(self.dest.clone()).unwrap();
            let dest = emissary_core::primitives::Destination::parse(dest).unwrap();

            Some(base32_encode(dest.id().to_vec()))
        }
    }

    let (router, _events, _) =
        Router::<Runtime>::new(config, Some(Arc::new(AddressBookImpl { dest })), None)
            .await
            .unwrap();
    let sam_port = router.protocol_address_info().sam_tcp.unwrap().port();
    tokio::spawn(router);

    tokio::time::sleep(Duration::from_secs(30)).await;

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_port,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut stream = tokio::time::timeout(Duration::from_secs(10), session2.connect("host.i2p"))
        .await
        .expect("no timeout")
        .expect("to succeed");

    let mut buffer = vec![0u8; 64];
    let nread = stream.read(&mut buffer).await.unwrap();

    assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));

    stream.write_all(b"goodbye, world!\n").await.unwrap();

    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn open_parallel_streams_ntcp2() {
    open_parallel_streams(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn open_parallel_streams_ssu2() {
    open_parallel_streams(TransportKind::Ssu2).await
}

async fn open_parallel_streams(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<u16>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push(router.protocol_address_info().sam_tcp.unwrap().port());
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let dest = session1.destination().to_owned();

    let handle1 = tokio::spawn(async move {
        for _ in 0..2 {
            let mut stream = tokio::time::timeout(Duration::from_secs(15), session1.accept())
                .await
                .expect("no timeout")
                .expect("to succeed");

            stream.write_all(b"hello, world!\n").await.unwrap();

            let mut buffer = vec![0u8; 64];
            let nread = stream.read(&mut buffer).await.unwrap();
            assert_eq!(
                std::str::from_utf8(&buffer[..nread]),
                Ok("goodbye, world!\n")
            );
        }
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[1],
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let fut1 = session2.connect_detached(&dest);
    let fut2 = session2.connect_detached(&dest);

    let handle2 = tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(10), fut1)
            .await
            .expect("no timeout")
            .expect("to succeed");

        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();
        assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));

        stream.write_all(b"goodbye, world!\n").await.unwrap();
    });

    let handle3 = tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(10), fut2)
            .await
            .expect("no timeout")
            .expect("to succeed");

        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();
        assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));

        stream.write_all(b"goodbye, world!\n").await.unwrap();
    });

    let mut futures = JoinSet::new();
    futures.spawn(handle1);
    futures.spawn(handle2);
    futures.spawn(handle3);

    let values = tokio::time::timeout(Duration::from_secs(30), futures.join_all()).await.unwrap();
    assert!(values.into_iter().all(|value| value.is_ok()));
}

#[tokio::test]
async fn duplicate_sub_session_id_ntcp2() {
    duplicate_sub_session_id(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn duplicate_sub_session_id_ssu2() {
    duplicate_sub_session_id(TransportKind::Ssu2).await
}

async fn duplicate_sub_session_id(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<(u16, u16)>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push((
            router.protocol_address_info().sam_tcp.unwrap().port(),
            router.protocol_address_info().sam_udp.unwrap().port(),
        ));
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Primary>::new(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let _stream_session = tokio::time::timeout(
        Duration::from_secs(5),
        session2.create_subsession::<Stream>(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            nickname: "test-nick".to_string(),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();

    match tokio::time::timeout(
        Duration::from_secs(5),
        session2.create_subsession::<Repliable>(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            nickname: "test-nick".to_string(),
            ..Default::default()
        }),
    )
    .await
    {
        Err(_) => panic!("unexpected timeout"),
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("duplicate session id should've been rejected"),
    }
}

#[tokio::test]
async fn primary_session_with_stream_and_repliable_ntcp2() {
    primary_session_with_stream_and_repliable(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn primary_session_with_stream_and_repliable_ssu2() {
    primary_session_with_stream_and_repliable(TransportKind::Ssu2).await
}

async fn primary_session_with_stream_and_repliable(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<(u16, u16)>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push((
            router.protocol_address_info().sam_tcp.unwrap().port(),
            router.protocol_address_info().sam_udp.unwrap().port(),
        ));
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session_stream = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0].0,
            samv3_udp_port: ports[0].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let mut session_datagram = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Repliable>::new(SessionOptions {
            samv3_tcp_port: ports[0].0,
            samv3_udp_port: ports[0].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let stream_dest = session_stream.destination().to_owned();
    let datagram_dest = session_datagram.destination().to_owned();

    tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(15), session_stream.accept())
            .await
            .expect("no timeout")
            .expect("to succeed");
        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&buffer[..nread]),
            Ok("goodbye, world!\n")
        );

        stream.write_all(b"hello, world!\n").await.unwrap();

        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    tokio::spawn(async move {
        let mut buffer = vec![0u8; 128];
        let (nread, destination) = session_datagram.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..nread], b"hello, world!");

        session_datagram.send_to(b"goodbye, world!", &destination).await.unwrap();
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Primary>::new(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut stream_session = tokio::time::timeout(
        Duration::from_secs(5),
        session2.create_subsession::<Stream>(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let mut datagram_session = tokio::time::timeout(
        Duration::from_secs(5),
        session2.create_subsession::<Repliable>(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();

    let mut stream = tokio::time::timeout(
        Duration::from_secs(30),
        stream_session.connect(&stream_dest),
    )
    .await
    .unwrap()
    .unwrap();

    // ensure streaming works
    {
        stream.write_all(b"goodbye, world!\n").await.unwrap();
        let mut buffer = vec![0u8; 14];
        let nread = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));
    }

    // ensure reliable datagrams work
    {
        datagram_session.send_to(b"hello, world!", &datagram_dest).await.unwrap();

        let mut buffer = vec![0u8; 128];
        let (nread, _destination) = tokio::time::timeout(
            Duration::from_secs(15),
            datagram_session.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..nread], b"goodbye, world!");
    }
}

#[tokio::test]
async fn primary_session_with_stream_and_anonymous_ntcp2() {
    primary_session_with_stream_and_anonymous(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn primary_session_with_stream_and_anonymous_ssu2() {
    primary_session_with_stream_and_anonymous(TransportKind::Ssu2).await
}

async fn primary_session_with_stream_and_anonymous(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<(u16, u16)>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push((
            router.protocol_address_info().sam_tcp.unwrap().port(),
            router.protocol_address_info().sam_udp.unwrap().port(),
        ));
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session_stream = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: ports[0].0,
            samv3_udp_port: ports[0].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
    let mut session_datagram = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Anonymous>::new(SessionOptions {
            samv3_tcp_port: ports[0].0,
            samv3_udp_port: ports[0].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let stream_dest = session_stream.destination().to_owned();
    let datagram_dest = session_datagram.destination().to_owned();

    tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(15), session_stream.accept())
            .await
            .expect("no timeout")
            .expect("to succeed");
        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&buffer[..nread]),
            Ok("goodbye, world!\n")
        );

        stream.write_all(b"hello, world!\n").await.unwrap();

        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let handle = tokio::spawn(async move {
        let mut buffer = vec![0u8; 128];
        let nread = session_datagram.recv(&mut buffer).await.unwrap();

        buffer[..nread].to_vec()
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Primary>::new(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut stream_session = tokio::time::timeout(
        Duration::from_secs(5),
        session2.create_subsession::<Stream>(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let mut datagram_session = tokio::time::timeout(
        Duration::from_secs(5),
        session2.create_subsession::<Anonymous>(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();

    let mut stream = tokio::time::timeout(
        Duration::from_secs(30),
        stream_session.connect(&stream_dest),
    )
    .await
    .unwrap()
    .unwrap();

    // ensure streaming works
    {
        stream.write_all(b"goodbye, world!\n").await.unwrap();
        let mut buffer = vec![0u8; 14];
        let nread = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));
    }

    // ensure anonymous datagrams work
    {
        datagram_session.send_to(b"hello, world!", &datagram_dest).await.unwrap();

        let result = handle.await.unwrap();
        assert_eq!(result, b"hello, world!");
    }
}

#[tokio::test]
async fn two_primary_sessions_ntcp2() {
    two_primary_sessions(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn two_primary_sessions_ssu2() {
    two_primary_sessions(TransportKind::Ssu2).await
}

async fn two_primary_sessions(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<(u16, u16)>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push((
            router.protocol_address_info().sam_tcp.unwrap().port(),
            router.protocol_address_info().sam_udp.unwrap().port(),
        ));
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut primary1 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Primary>::new(SessionOptions {
            samv3_tcp_port: ports[0].0,
            samv3_udp_port: ports[0].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut primary1_stream = tokio::time::timeout(
        Duration::from_secs(5),
        primary1.create_subsession::<Stream>(SessionOptions {
            samv3_tcp_port: ports[0].0,
            samv3_udp_port: ports[0].1,
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let mut primary1_datagram = tokio::time::timeout(
        Duration::from_secs(5),
        primary1.create_subsession::<Repliable>(SessionOptions {
            samv3_tcp_port: ports[0].0,
            samv3_udp_port: ports[0].1,
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();

    let stream_dest = primary1_stream.destination().to_owned();
    let datagram_dest = primary1_datagram.destination().to_owned();
    assert_eq!(stream_dest, datagram_dest);

    tokio::spawn(async move {
        let mut stream = tokio::time::timeout(Duration::from_secs(15), primary1_stream.accept())
            .await
            .expect("no timeout")
            .expect("to succeed");
        let mut buffer = vec![0u8; 64];
        let nread = stream.read(&mut buffer).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&buffer[..nread]),
            Ok("goodbye, world!\n")
        );

        stream.write_all(b"hello, world!\n").await.unwrap();

        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    tokio::spawn(async move {
        let mut buffer = vec![0u8; 128];
        let (nread, destination) = primary1_datagram.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..nread], b"hello, world!");

        primary1_datagram.send_to(b"goodbye, world!", &destination).await.unwrap();
    });

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Primary>::new(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut stream_session = tokio::time::timeout(
        Duration::from_secs(5),
        session2.create_subsession::<Stream>(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let mut datagram_session = tokio::time::timeout(
        Duration::from_secs(5),
        session2.create_subsession::<Repliable>(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();

    let mut stream = tokio::time::timeout(
        Duration::from_secs(30),
        stream_session.connect(&stream_dest),
    )
    .await
    .unwrap()
    .unwrap();

    // ensure streaming works
    {
        stream.write_all(b"goodbye, world!\n").await.unwrap();
        let mut buffer = vec![0u8; 14];
        let nread = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::str::from_utf8(&buffer[..nread]), Ok("hello, world!\n"));
    }

    // ensure reliable datagrams work
    {
        datagram_session.send_to(b"hello, world!", &datagram_dest).await.unwrap();

        let mut buffer = vec![0u8; 128];
        let (nread, _destination) = tokio::time::timeout(
            Duration::from_secs(15),
            datagram_session.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..nread], b"goodbye, world!");
    }
}

#[tokio::test]
async fn primary_session_with_repliable_and_anonymous_ntcp2() {
    primary_session_with_repliable_and_anonymous(TransportKind::Ntcp2).await
}

#[tokio::test]
async fn primary_session_with_repliable_and_anonymous_ssu2() {
    primary_session_with_repliable_and_anonymous(TransportKind::Ssu2).await
}

// yosemite currently doesn't support specifying datagram options, meaning `FROM_PORT` will always
// be the default port, meaning two datagrams listeners would be listening to the same port which is
// not supported by emissary (and by the SAMv3 spec?)
//
// this causes the second sub-session to b erejected
async fn primary_session_with_repliable_and_anonymous(kind: TransportKind) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), kind).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create two more routers, fetch their sam tcp ports and spawn them in the background
    let mut ports = Vec::<(u16, u16)>::new();

    for _ in 0..2 {
        let router = make_router(false, net_id, router_infos.clone(), kind).await.0;

        ports.push((
            router.protocol_address_info().sam_tcp.unwrap().port(),
            router.protocol_address_info().sam_udp.unwrap().port(),
        ));
        tokio::spawn(router);
    }

    // let the network boot up
    tokio::time::sleep(Duration::from_secs(20)).await;

    let mut session2 = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Primary>::new(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let _stream_session = tokio::time::timeout(
        Duration::from_secs(5),
        session2.create_subsession::<Repliable>(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();

    match tokio::time::timeout(
        Duration::from_secs(5),
        session2.create_subsession::<Anonymous>(SessionOptions {
            samv3_tcp_port: ports[1].0,
            samv3_udp_port: ports[1].1,
            ..Default::default()
        }),
    )
    .await
    {
        Err(_) => panic!("unexpected timeout"),
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("duplicate session id should've been rejected"),
    }
}

#[tokio::test]
async fn active_session_destroyed_and_recreated() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..4 {
        let (router, _events, router_info) =
            make_router(i < 2, net_id, router_infos.clone(), TransportKind::Ntcp2).await;

        router_infos.push(router_info);
        tokio::spawn(router);
    }

    // create the sam router and fetch the random sam tcp port from the router
    let router = make_router(false, net_id, router_infos.clone(), TransportKind::Ntcp2).await.0;
    let sam_tcp = router.protocol_address_info().sam_tcp.unwrap().port();

    // spawn the router inte background and wait a moment for the network to boot
    tokio::spawn(router);
    tokio::time::sleep(Duration::from_secs(15)).await;

    // generate new destination and create new session using the destination
    let (_destination, private_key) = tokio::time::timeout(
        Duration::from_secs(5),
        RouterApi::new(sam_tcp).generate_destination(),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    let mut session = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            destination: DestinationKind::Persistent {
                private_key: private_key.clone(),
            },
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");

    // destroy session and verify it's closed
    let _ = session.send_command("QUIT\n").await;
    assert!(session
        .connect("lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua.b32.i2p")
        .await
        .is_err());

    // verify that the session can be recreated with the same key
    let _session = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            destination: DestinationKind::Persistent {
                private_key: private_key.clone(),
            },
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
}
