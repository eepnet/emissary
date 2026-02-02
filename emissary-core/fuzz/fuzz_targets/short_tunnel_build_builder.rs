#![no_main]

use emissary_core::{
    i2np::{
        tunnel::build::short::{TunnelBuildRecord, TunnelBuildRecordBuilder},
        HopRole,
    },
    primitives::{MessageId, TunnelId},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: Vec<(u32, u32, [u8; 32], u32, u32, u32)>| {
    for values in buffer {
        let serialized = TunnelBuildRecordBuilder::default()
            .with_tunnel_id(TunnelId::from(values.0))
            .with_next_tunnel_id(TunnelId::from(values.1))
            .with_next_router_hash(&values.2)
            .with_hop_role(match values.0 % 2 == 0 {
                true => HopRole::InboundGateway,
                false => match values.0 % 3 == 0 {
                    true => HopRole::OutboundEndpoint,
                    false => HopRole::Participant,
                },
            })
            .with_request_time(values.3)
            .with_request_expiration(values.4)
            .with_next_message_id(MessageId::from(values.5))
            .serialize(&mut rand_core::OsRng);

        assert!(TunnelBuildRecord::parse(&serialized).is_ok());
    }
});
