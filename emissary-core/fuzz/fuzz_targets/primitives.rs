#![no_main]

use emissary_core::primitives::{
    Date, Destination, LeaseSet2, Mapping, RouterAddress, RouterIdentity, RouterInfo, Str,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = Date::parse(buffer);
    let _ = Destination::parse(buffer);
    let _ = LeaseSet2::parse(buffer);
    let _ = Mapping::parse(buffer);
    let _ = RouterAddress::parse(buffer);
    let _ = RouterIdentity::parse(buffer);
    let _ = RouterInfo::parse(buffer);
    let _ = Str::parse(buffer);
});
