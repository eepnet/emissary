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

use std::sync::Arc;

use anyhow::anyhow;
use emissary_core::{
    router::{ProtocolAddressInfo, Router},
    Config, Ntcp2Config, SamConfig, TransitConfig,
};
use emissary_util::{
    port_mapper::{PortMapper, PortMapperConfig},
    reseeder::Reseeder,
    runtime::tokio::Runtime,
    storage::{Storage, StorageBundle},
};
use futures::StreamExt;
use tempfile::tempdir;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // initialize logger
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // this examples uses a temporary directory but for a real use-case `dir` should be
    // the directory where the application stores its files
    let dir = tempdir()?;

    // the application directory needs to have a subdirectory for emissary's files
    // (netDb, peerProfiles, router and transport keys)
    let base_path = dir.path().join(".emissary");

    // initialize storage from the base path
    //
    // if emissary is started for the first time, this creates directories
    // for router infos and profiles, and generates transport and router keys
    //
    // if `None` is passed, `Storage` defaults to using `$HOME/.emissary`
    let storage = Storage::new(Some(base_path)).await?;

    // read storage bundle from disk
    //
    // this contains all on-disk information needed by the router, including
    // router and transport keys and stored router infos
    let StorageBundle {
        ntcp2_iv,
        ntcp2_key,
        profiles,
        router_info,
        mut routers,
        signing_key,
        static_key,
        ssu2_intro_key: _,
        ssu2_static_key: _,
    } = storage.load().await;

    // reseed if there are no routers
    if routers.is_empty() {
        match Reseeder::reseed(None, false).await {
            // if reseeding succeeded, store the router infos to disk so next time the
            // router starts, it doesn't have to reeseed
            Ok(reseed_routers) =>
                for info in reseed_routers {
                    storage
                        .store_router_info(info.name.to_string(), info.router_info.clone())
                        .await?;
                    routers.push(info.router_info);
                },

            // the router cannot be started if reseeding failed and there are no routers
            Err(_) if routers.is_empty() => return Err(anyhow!("unable to start emissary")),

            // attempt to start the router even if reseeding failed since there are some routers
            Err(error) => tracing::warn!(
                num_routers = routers.len(),
                ?error,
                "failed to reseed router",
            ),
        }
    }

    // create configuration for the router
    let config = Config {
        // enable NTCP2
        ntcp2: Some(Ntcp2Config {
            // port should be random but the same across restarts
            port: 25515,

            // provide NTCP2 key and IV that were read from the disk
            key: ntcp2_key,
            iv: ntcp2_iv,

            // publish NTCP2 address of the router in the router info that's published to NetDb
            //
            // this allows the embedded router to accept incoming NTCP2 connections
            publish: true,

            // set host to `None` and use NAT-PMP/UPnP to resolve external address of the router
            host: None,
        }),

        // enable SAMv3 and bind TCP and UDP to random, OS-assigned ports
        samv3_config: Some(SamConfig {
            tcp_port: 0,
            udp_port: 0,
            host: "127.0.0.1".to_string(),
        }),

        // provide router infos and profiles that were read from the disk
        routers,
        profiles,

        // provide our local router info (from a previous boot) if it exists
        //
        // if the router info doesn't exist, emissary will create a new router info
        // which should be stored on disk
        router_info,

        // provide router static and signing keys
        //
        // this can be `None` which means emissary will generate new keys for the router
        // eveery time it starts
        //
        // not recommended outside of testing, unless there's a reason to run an ephemeral router
        static_key: Some(static_key),
        signing_key: Some(signing_key),

        // allow the router to accept at most 1000 transit tunnels
        transit: Some(TransitConfig {
            max_tunnels: Some(1000),
        }),

        // use defaults for the rest
        ..Default::default()
    };

    // instantiate router
    let (mut router, _events, router_info) =
        Router::<Runtime>::new(config, None, Some(Arc::new(storage.clone())))
            .await
            .map_err(|error| anyhow!("failed to start router: {error}"))?;

    // store local router info to disk so it can be used the next time the router starts
    //
    // the first time emissary boots it creates a `RouterInfo` object for itself which
    // contains a `RouterIdentity` object and the identity object contains random padding
    // which, in addition to other fields of the identity, determines the router ID
    //
    // in order to have a stable router ID, the same router info object must be used
    // (stored on disk and passed to `Config`) every time the router boots
    storage.store_local_router_info(router_info).await?;

    // get protocol address information from the router
    let ProtocolAddressInfo { ntcp2_port, .. } = router.protocol_address_info();

    // create port mapper
    //
    // enable both NAT-PMP and UPnP and create a mapping for the router's NTCP2 port
    //
    // `port_mapper` is also used to discover the external address that must be given
    // to the router so it can publish a router info with a correct external addres
    //
    // this step is not strictly necessary if the port has been manually forwarded
    // or if the router shouldn't accept inbound connections
    //
    // inability to accept inbound connections will severely harm the router's ability
    // to build tunnels and accept transit tunnels
    let mut port_mapper = PortMapper::new(
        Some(PortMapperConfig {
            nat_pmp: true,
            upnp: true,
            ..Default::default()
        }),
        *ntcp2_port,
        None,
    );

    // spawn the router and the port mapper in the background
    tokio::spawn(async move {
        loop {
            tokio::select! {
                address = port_mapper.next() => {
                    // the value must exist since the stream never terminates
                    router.add_external_address(address.expect("value"));
                },
                _ = &mut router => {
                    break;
                }
            }
        }
    });

    // now the router can be interacted with using SAMv3 and I2CP
    //
    // `ProtocolAddressInfo` provides the SAMv3 UDP and TCP ports and
    // `examples/rust-chat` demonstrates how to host and connect to
    // hidden services using an embedded router

    Ok(())
}
