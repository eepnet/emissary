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

use emissary_core::{events::EventSubscriber, router::Router, Config, Ntcp2Config, TransitConfig};
use emissary_util::runtime::tokio::Runtime;
use tempfile::tempdir;

use std::path::PathBuf;

/// Network ID for devnet.
///
/// Used only if local network is used.
pub const DEVNET_ID: u8 = 0xab;

/// Make a router.
///
/// `floodfill` indicates whether the router should start as a floodfill router
/// `routers` are the other known routers of the network, used to reseed this router
async fn make_router(
    floodfill: bool,
    routers: Vec<Vec<u8>>,
    router_number: u8,
) -> (Router<Runtime>, EventSubscriber, Vec<u8>) {
    let config = Config {
        net_id: Some(DEVNET_ID),
        floodfill,
        insecure_tunnels: true,
        allow_local: true,
        caps: if floodfill {
            Some(String::from("XfR"))
        } else {
            Some(String::from("XR"))
        },
        ntcp2: Some(Ntcp2Config {
            port: 0u16,
            iv: [router_number; 16],
            key: [router_number; 32],
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
        }),
        routers,
        transit: Some(TransitConfig {
            max_tunnels: Some(5000),
        }),
        ..Default::default()
    };

    Router::<Runtime>::new(config, None, None).await.unwrap()
}

/// Spawn an isolated, local I2P network.
pub async fn spawn_network(num_floodfills: usize, num_routers: usize, path: Option<String>) {
    let (path, _dir) = match path {
        Some(path) => {
            if let Err(error) = tokio::fs::create_dir_all(&path).await {
                eprintln!("failed to create directory ({path}): {error:?}");
                std::process::exit(1)
            }

            (PathBuf::from(path), None)
        }
        None => {
            let dir = tempdir().expect("to succeed");
            (dir.path().to_owned(), Some(dir))
        }
    };
    let mut router_infos = Vec::<Vec<u8>>::new();

    for i in 0..(num_floodfills + num_routers) {
        let (router, _events, router_info) =
            make_router(i < num_floodfills, router_infos.clone(), i as u8).await;

        // save the router info so it can be given to other routers of the network
        router_infos.push(router_info);

        // spawn the event loop of the router in the background
        tokio::spawn(router);
    }

    // store the router files in the temporary directory
    for (i, router_info) in router_infos.into_iter().enumerate() {
        if let Err(error) =
            tokio::fs::write(path.join(format!("routerInfo{i}.dat")), router_info).await
        {
            eprintln!("failed to write router info for router {i} to disk: {error:?}");
        }
    }

    println!("devnet started, path = {}", path.display());

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}
