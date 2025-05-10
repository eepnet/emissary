#![no_main]

use emissary_core::i2np::{
    database::{lookup::DatabaseLookup, search_reply::DatabaseSearchReply, store::DatabaseStore},
    garlic::GarlicMessage,
    tunnel::{
        build::{short, variable},
        data::{EncryptedTunnelData, TunnelData},
        gateway::TunnelGateway,
    },
    Message,
};
use emissary_util::runtime::tokio::Runtime;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = DatabaseLookup::parse(buffer);
    let _ = DatabaseSearchReply::parse(buffer);
    let _ = DatabaseStore::<Runtime>::parse(buffer);
    let _ = EncryptedTunnelData::parse(buffer);
    let _ = GarlicMessage::parse(buffer);
    let _ = Message::parse_short(buffer);
    let _ = Message::parse_standard(buffer);
    let _ = short::TunnelBuildRecord::parse(buffer);
    let _ = TunnelData::parse(buffer);
    let _ = TunnelGateway::parse(buffer);
    let _ = variable::TunnelBuildRecord::parse(buffer);
});
