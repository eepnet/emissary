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
    crypto::{
        chachapoly::{ChaCha, ChaChaPoly},
        sha256::Sha256,
        EphemeralPrivateKey,
    },
    error::TunnelError,
    i2np::{
        garlic::{DeliveryInstructions, GarlicMessage, GarlicMessageBlock, GarlicMessageBuilder},
        tunnel::build::short,
        Message, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    primitives::{RouterId, Str, TunnelId},
    runtime::Runtime,
    tunnel::hop::{
        outbound::OutboundTunnel, ReceiverKind, Tunnel, TunnelBuildParameters, TunnelBuilder,
        TunnelDirection, TunnelHop, TunnelInfo,
    },
    util::shuffle,
};

use bytes::{BufMut, Bytes, BytesMut};
use hashbrown::HashSet;
use rand_core::RngCore;

use alloc::{collections::VecDeque, vec::Vec};
use core::{iter, marker::PhantomData, num::NonZeroUsize, time::Duration};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::pending";

/// How many records fit into a single [`TunnelData`] without having to fragment the tunnel build
/// request.
///
/// Used to clamp down the amount of fake records for inbound tunnel builds.
const UNFRAGMENTED_MAX_RECORDS: usize = 4usize;

/// Maximum build records.
const MAX_BUILD_RECORDS: usize = 8usize;

/// How long is reply waited for a build request until it's considered expired.
const TUNNEL_BUILD_EXPIRATION: Duration = Duration::from_secs(10);

/// Short tunnel build request record size.
const SHORT_RECORD_LEN: usize = 218;

/// Context for the local fake record placed into inbound TBRMs.
struct FakeRecordContext {
    /// Local router short hash.
    local_hash: Vec<u8>,

    /// Checksum for our fake record.
    checksum: [u8; 32],
}

/// Pending tunnel.
pub struct PendingTunnel<T: Tunnel> {
    /// Context for local fake record.
    ///
    /// Set only for inbound builds.
    fake_record_ctx: Option<FakeRecordContext>,

    /// Pending tunnel hops.
    hops: VecDeque<TunnelHop>,

    /// Name of the tunnel pool.
    name: Str,

    /// Number of build records (real and fake).
    num_records: usize,

    /// Message receiver for the tunnel.
    receiver: ReceiverKind,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Marker for `Tunnel`.
    _tunnel: PhantomData<T>,
}

impl<R: Runtime> PendingTunnel<OutboundTunnel<R>> {
    /// Get garlic tag of the outbound endpoint.
    pub fn garlic_tag(&self) -> Bytes {
        // obep must exist since it was created by us
        self.hops.back().expect("tunnel to exist").key_context.garlic_tag_owned()
    }
}

impl<T: Tunnel> PendingTunnel<T> {
    /// Get reference to [`PendingTunnel`]'s `TunnelId`.
    pub fn tunnel_id(&self) -> &TunnelId {
        &self.tunnel_id
    }

    /// Create new [`PendingTunnel`].
    pub fn create_tunnel<R: Runtime>(
        parameters: TunnelBuildParameters,
    ) -> Result<(Self, RouterId, Message), TunnelError> {
        let TunnelBuildParameters {
            hops,
            message_id,
            name,
            noise,
            receiver,
            tunnel_info,
        } = parameters;

        // inbound tnnels always have one fake local record
        match T::direction() {
            TunnelDirection::Outbound =>
                if hops.len() > MAX_BUILD_RECORDS {
                    return Err(TunnelError::TooManyHops(hops.len()));
                },
            TunnelDirection::Inbound =>
                if hops.len() > MAX_BUILD_RECORDS - 1 {
                    return Err(TunnelError::TooManyHops(hops.len()));
                },
        }

        // extract pending tunnel's id and id of the tunnel that's used for reception of the reply
        //
        // inbound tunnel build responses don't come through a tunnel so those build requests can
        // use the same tunnel id that's used for the actual tunnel
        //
        // outbound tunnel build responses are received through a channel which is different from
        // the actual tunnel that is being created and will thus have a different tunnel id
        let (gateway, tunnel_id, router_id) = match (tunnel_info, T::direction()) {
            (info @ TunnelInfo::Outbound { .. }, TunnelDirection::Outbound) => info.destruct(),
            (info @ TunnelInfo::Inbound { .. }, TunnelDirection::Inbound) => info.destruct(),
            (_, _) => unreachable!(),
        };

        tracing::trace!(
            target: LOG_TARGET,
            direction = ?T::direction(),
            %message_id,
            %tunnel_id,
            num_hops = ?hops.len(),
            "create tunnel",
        );

        // set build record to expire 10 seconds from now
        let time_now = R::time_since_epoch();
        let build_expiration = time_now + TUNNEL_BUILD_EXPIRATION;
        let num_hops =
            NonZeroUsize::new(hops.len()).ok_or(TunnelError::NotEnoughHops(hops.len()))?;

        // calculate record count for the tunnel build message
        //
        // if the number of requested records is less than 4, the record count is set to 4,
        // as recommended by the specification
        //
        // if more than 4 hops were requested, the upper bound for clamp is set to 8 which is
        // the maximum amount of records a `ShortTunnelBuild` message can hold
        let num_records = if hops.len() < UNFRAGMENTED_MAX_RECORDS {
            UNFRAGMENTED_MAX_RECORDS
        } else {
            (hops.len() + (R::rng().next_u32() % 3) as usize).clamp(0, MAX_BUILD_RECORDS)
        };

        // save the first hop's static key in case this is an inbound tunnel build so that the
        // tunnel build message can be garlic-encrypted, preventing OBEP from reading the message
        let first_hop_static_key = hops[0].1.clone();

        // fake local record for inbound tunnel builds, from specification:
        //
        // For inbound tunnel builds, there must always be one "fake" record for the originating
        // router, with the correct 16-byte hash prefix, otherwise the closest hop will know that
        // the next hop is the originator. The MSB of the ephemeral key (data[47] & 0x80) must also
        // be cleared so it looks like a real X25519 public key.
        let (fake_inbound_record_checksum, fake_inbound_record) = match T::direction() {
            TunnelDirection::Outbound => (None, None),
            TunnelDirection::Inbound => {
                let mut record = router_id[..16].to_vec();

                record.extend_from_slice(&{
                    let mut fake_key = [0u8; 32];
                    R::rng().fill_bytes(&mut fake_key);

                    fake_key[31] &= 0x80;
                    fake_key
                });
                record.extend_from_slice(&{
                    // record len - short router hash - public key
                    let mut fake_record = [0u8; SHORT_RECORD_LEN - 16 - 32];
                    R::rng().fill_bytes(&mut fake_record);

                    fake_record
                });

                (
                    Some(Sha256::new().update(&record).finalize_new()),
                    Some(record),
                )
            }
        };

        // prepare router info for build records
        //
        // each hop is generated a random tunnel id and local info is chained at the end
        let (tunnel_ids, router_hashes): (Vec<_>, Vec<_>) = hops
            .iter()
            .map(|(router_hash, _)| (TunnelId::from(R::rng().next_u32()), router_hash.clone()))
            .chain(iter::once((gateway, router_id.clone())))
            .unzip();

        // create build records and generate key contexts for each hop
        let (mut tunnel_hops, mut build_records): (VecDeque<TunnelHop>, Vec<Vec<u8>>) = tunnel_ids
            .iter()
            .zip(router_hashes.iter())
            .zip(tunnel_ids.iter().skip(1))
            .zip(router_hashes.iter().skip(1))
            .zip(T::hop_roles(num_hops))
            .zip(hops.into_iter().map(|(_, key)| key))
            .map(
                |(
                    ((((tunnel_id, router_hash), next_tunnel_id), next_router_hash), hop_role),
                    key,
                )| {
                    (
                        TunnelHop {
                            key_context: noise.create_outbound_session::<R>(key, hop_role),
                            record_idx: None,
                            router: RouterId::from(router_hash),
                            tunnel_id: *tunnel_id,
                        },
                        short::TunnelBuildRecordBuilder::default()
                            .with_tunnel_id(*tunnel_id)
                            .with_next_tunnel_id(*next_tunnel_id)
                            .with_next_router_hash(next_router_hash.as_ref())
                            .with_hop_role(hop_role)
                            .with_request_time((time_now.as_secs() / 60) as u32)
                            .with_request_expiration(build_expiration.as_secs() as u32)
                            .with_next_message_id(message_id)
                            .serialize(&mut R::rng()),
                    )
                },
            )
            .unzip();

        // encrypt build records with each hop's aead key and extend the build record into full
        // `ShortTunnelBuildRecord` by prepending hop's truncated router hash and ephemeral public
        // key of the local router
        let mut encrypted_records = router_hashes
            .iter()
            .zip(build_records.iter_mut())
            .zip(tunnel_hops.iter_mut())
            .filter_map(|((router_hash, record), tunnel_hop)| {
                ChaChaPoly::new(tunnel_hop.key_context.aead_key())
                    .encrypt_with_ad_new(tunnel_hop.key_context.state(), record)
                    .ok()
                    .map(|_| {
                        // update associated data to include the encrypted record
                        // which is used when decrypting the build reply
                        tunnel_hop.key_context.set_state(
                            Sha256::new()
                                .update(tunnel_hop.key_context.state())
                                .update(&record)
                                .finalize(),
                        );

                        let mut full_record = router_hash[..16].to_vec();
                        full_record.extend_from_slice(tunnel_hop.key_context.ephemeral_key());
                        full_record.extend_from_slice(record);

                        full_record
                    })
            })
            .collect::<Vec<_>>();

        // append fake records at the end so that the length of the tunnel build request message
        // is `num_records` many records long
        //
        // the inbound tunnel build message also contains our fake record and one fewer "actual"
        // fake record
        match fake_inbound_record {
            Some(record) => {
                encrypted_records.push(record);
                encrypted_records.extend(
                    (1..num_records - num_hops.get())
                        .map(|_| short::TunnelBuildRecordBuilder::random(&mut R::rng())),
                );
            }
            None => {
                encrypted_records.extend(
                    (0..num_records - num_hops.get())
                        .map(|_| short::TunnelBuildRecordBuilder::random(&mut R::rng())),
                );
            }
        }

        // shuffle records and assign record index for each hop
        let (mut encrypted_records, mut record_indexes): (Vec<_>, HashSet<_>) = {
            let mut records = encrypted_records.into_iter().enumerate().collect::<Vec<_>>();
            shuffle(&mut records, &mut R::rng());

            records
                .into_iter()
                .enumerate()
                .map(|(record_idx, (hop, record))| {
                    // `record_idx` denotes the hop's record's index in the TBRM
                    //
                    // `hop` is the index of the hop inside `tunnel_hops` and denotes hop's order
                    // in the tunnel
                    //
                    // note that `TunnelHop` for `hop` does not exist if `record` is a fake record
                    if let Some(tunnel_hop) = tunnel_hops.get_mut(hop) {
                        tunnel_hop.set_record_index(record_idx);
                    }

                    (record, record_idx)
                })
                .unzip()
        };

        // double-encrypt build records
        //
        // note that the number of the times the record is encrypted is tied to the hop's position
        // in the tunnel: 1st hop is not encrypted, 2nd is encrypted once, 3rd hop twice and so on
        tunnel_hops.iter().for_each(|hop| {
            encrypted_records.iter_mut().enumerate().for_each(|(record_idx, record)| {
                // don't encrypt hop's own record or records preceeding this record
                if record_indexes.contains(&record_idx) && record_idx != hop.record_index() {
                    ChaCha::with_nonce(hop.key_context.reply_key(), record_idx as u64)
                        .decrypt_ref(record);
                }
            });

            // mark hop as "encrypted" by removing it from `record_indexes` so hops that follow this
            // hop won't encrypt the hop's record with their key
            record_indexes.remove(&hop.record_index());
        });

        Ok((
            Self {
                fake_record_ctx: fake_inbound_record_checksum.map(|checksum| FakeRecordContext {
                    checksum,
                    local_hash: router_id[..16].to_vec(),
                }),
                hops: tunnel_hops,
                name,
                num_records,
                receiver,
                tunnel_id,
                _tunnel: Default::default(),
            },
            RouterId::from(router_hashes[0].clone().to_vec()),
            match T::direction() {
                TunnelDirection::Outbound => Message {
                    message_id: *message_id,
                    expiration: build_expiration,
                    message_type: MessageType::ShortTunnelBuild,
                    payload: short::TunnelBuildReplyBuilder::from_records(encrypted_records),
                },
                TunnelDirection::Inbound => {
                    let mut message = GarlicMessageBuilder::default()
                        .with_date_time(R::time_since_epoch().as_secs() as u32)
                        .with_garlic_clove(
                            MessageType::ShortTunnelBuild,
                            message_id,
                            R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                            DeliveryInstructions::Local,
                            &short::TunnelBuildReplyBuilder::from_records(encrypted_records),
                        )
                        .build();

                    let ephemeral_secret = EphemeralPrivateKey::random(R::rng());
                    let ephemeral_public = ephemeral_secret.public();
                    let (key, tag) =
                        noise.derive_outbound_garlic_key(first_hop_static_key, ephemeral_secret);

                    // message length + poly13055 tg + ephemeral key + garlic message length
                    let mut out = BytesMut::with_capacity(message.len() + 16 + 32 + 4);

                    // encryption must succeed since the parameters are managed by us
                    ChaChaPoly::new(&key)
                        .encrypt_with_ad_new(&tag, &mut message)
                        .expect("to succeed");

                    out.put_u32(message.len() as u32 + 32);
                    out.put_slice(&ephemeral_public.to_vec());
                    out.put_slice(&message);

                    Message {
                        message_type: MessageType::Garlic,
                        message_id: *message_id,
                        expiration: R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                        payload: out.to_vec(),
                    }
                }
            },
        ))
    }

    /// Try to build tunnel from the tunnel build response contained in `payload`.
    ///
    /// This function consumes `self` and returns either a `Tunnel` which can then be used
    /// for tunnel messaging, or a `TunnelError` if the received message was malformed or one of the
    /// tunnel participants rejected the build request.
    ///
    /// On success the function returns the built tunnel.
    ///
    /// This function can error out in different ways:
    ///  * build message is of invalid type
    ///  * build message, if garlic-encrypted, fails to decrypt (OBEP only)
    ///  * build message is of incorrect length
    ///  * one of the routers incorrectly encrypted their record
    ///  * one of the routers rejected the tunnel
    ///
    /// If the I2NP message is invalid, the last hop of the tunnel is marked as failed and the
    /// participation status for other hops is ignored as it cannot be determined. If one of the hop
    /// records fails to decrypt, hops preceeding that are marked as accepted/rejected based on
    /// their self-reported status and all hops following the hop whose record failed to decrypt are
    /// ignored as the records cannot be decrypted. In other words, on error, this function returns
    /// a vector of (`RouterId`, Option<Result<(), TunnelError>)` where `None` means the
    /// accept/reject status of the tunnel could not be determined, `Some(Ok(()))`, means that
    /// the tunnel build request was accepted and `Ok(Err(error))` means the tunnel was rejected
    /// or the tunnel build response record was malformed in some way. This allows the tunnel
    /// pool to reward/penalize the selected routers fairly.
    pub fn try_build_tunnel(
        self,
        message: Message,
    ) -> Result<T, Vec<(RouterId, Option<Result<(), TunnelError>>)>> {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel = %self.tunnel_id,
            direction = ?T::direction(),
            "handle tunnel build reply",
        );

        // initialize the return value for a possible tunnel build failure
        //
        // each value in `hop_results` contains the `RouterId` of the hop and the result of handling
        // their response to the build request. `None` indicates that the record could not be parsed
        // because a hop preceeding this hop failed to parse
        //
        // the hops are in reverse order as the tunnel's last hop (participant for inbound tunnels
        // and OBEP for outbound tunnels) is the router from whom the tunnel build response is
        // received and their record is decrypted and handled first
        let mut hop_results = Vec::<(RouterId, Option<Result<(), TunnelError>>)>::from_iter(
            self.hops.iter().rev().map(|hop| (hop.router_id().clone(), None)),
        );

        let mut payload = match (T::direction(), message.message_type) {
            // for inbound build the message type doesn't change from `ShortTunnelBuild`
            (TunnelDirection::Inbound, MessageType::ShortTunnelBuild) => {
                // context must exist since the tunnel was created by us
                let FakeRecordContext {
                    local_hash,
                    checksum,
                } = self.fake_record_ctx.expect("to exist");

                // length + at least one real record + local fake record
                if message.payload.len() < 1 + 2 * SHORT_RECORD_LEN
                    || message.payload[1..].len() % SHORT_RECORD_LEN != 0
                {
                    tracing::warn!(
                        target: LOG_TARGET,
                        tunnel = %self.tunnel_id,
                        direction = ?T::direction(),
                        "tunnel build record is too short",
                    );

                    hop_results[0].1 = Some(Err(TunnelError::InvalidMessage));
                    return Err(hop_results);
                }

                // make sure the message contains our record and that it has remained untampered
                match message.payload[1..]
                    .chunks(SHORT_RECORD_LEN)
                    .find(|chunk| &chunk[..16] == &local_hash)
                {
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel = %self.tunnel_id,
                            direction = ?T::direction(),
                            "fake local record not found in tunnel build reply",
                        );

                        hop_results[0].1 = Some(Err(TunnelError::InvalidMessage));
                        return Err(hop_results);
                    }
                    Some(record) =>
                        if Sha256::new().update(&record).finalize_new() != checksum {
                            tracing::warn!(
                                target: LOG_TARGET,
                                tunnel = %self.tunnel_id,
                                direction = ?T::direction(),
                                "fake local record has been modified",
                            );

                            hop_results[0].1 = Some(Err(TunnelError::InvalidMessage));
                            return Err(hop_results);
                        },
                }

                message.payload.to_vec()
            }

            // for outbound builds the reply can be received in `OutboundTunnelBuildReply`
            (TunnelDirection::Outbound, MessageType::OutboundTunnelBuildReply) =>
                message.payload.to_vec(),

            // outbound reply can also be wrapped in a `GarlicMessage`
            (TunnelDirection::Outbound, MessageType::Garlic) => {
                // tunnel must exist since it was created by us
                let outbound_endpoint = self.hops.back().expect("tunnel to exist");

                // garlic overhead + length + at least one record + poly1305 auth tag
                if message.payload.len() < 12 + 1 + SHORT_RECORD_LEN + 16 {
                    tracing::warn!(
                        target: LOG_TARGET,
                        tunnel = %self.tunnel_id,
                        direction = ?T::direction(),
                        "tunnel build record is too short",
                    );

                    hop_results[0].1 = Some(Err(TunnelError::InvalidMessage));
                    return Err(hop_results);
                }

                // garlic decrypt the payload with OBEP's garlic key and tag
                // and try to parse the plaintext into a `GarlicMessage`
                let mut record = message.payload[12..].to_vec();
                if let Err(error) = ChaChaPoly::new(&outbound_endpoint.key_context.garlic_key())
                    .decrypt_with_ad(&outbound_endpoint.key_context.garlic_tag(), &mut record)
                {
                    tracing::warn!(
                        target: LOG_TARGET,
                        router_id = %hop_results[0].0,
                        ?error,
                        "failed to decrypt tunnel build reply garlic message",
                    );

                    hop_results[0].1 = Some(Err(TunnelError::InvalidMessage));
                    return Err(hop_results);
                }

                let Some(message) = GarlicMessage::parse(&record) else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "malformed garlic message as tunnel build reply",
                    );

                    hop_results[0].1 = Some(Err(TunnelError::InvalidMessage));
                    return Err(hop_results);
                };

                // try to locate a garlic glove containing `OutboundTunnelBuildReply`
                // and discard any other cloves as they're no interesting at this time
                match message.blocks.into_iter().find(|message| {
                    core::matches!(
                        message,
                        GarlicMessageBlock::GarlicClove {
                            message_type: MessageType::OutboundTunnelBuildReply,
                            ..
                        }
                    )
                }) {
                    Some(GarlicMessageBlock::GarlicClove { message_body, .. }) =>
                        message_body.to_vec(),
                    _ => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            "garlic messge didn't contain valid tunnel reply",
                        );

                        hop_results[0].1 = Some(Err(TunnelError::InvalidMessage));
                        return Err(hop_results);
                    }
                }
            }
            (direction, message_type) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    tunnel_id = %self.tunnel_id,
                    ?direction,
                    ?message_type,
                    "invalid build message reply",
                );

                hop_results[0].1 = Some(Err(TunnelError::InvalidMessage));
                return Err(hop_results);
            }
        };

        if payload.len() != (self.num_records * SHORT_RECORD_LEN + 1) {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel = %self.tunnel_id,
                direction = ?T::direction(),
                expected_size = ?(self.hops.len() * SHORT_RECORD_LEN + 1),
                actual_size = ?payload.len(),
                "malformed tunnel build reply"
            );

            hop_results[0].1 = Some(Err(TunnelError::InvalidMessage));
            return Err(hop_results);
        }

        // process the tunnel build records in reverse order, processing the reply from the last hop
        // first
        //
        // if one of the records fail to decrypt, the processing is short-circuited and an error is
        // returned, indicating that not all responses were handled
        //
        // if all responses were decrypted successfully, the processing may still error if one of
        // the hops rejected the tunnel
        let mut accepted_hops = Vec::<TunnelHop>::new();
        let num_hops = self.hops.len();

        for (hop_idx, hop) in self.hops.into_iter().enumerate().rev() {
            let mut record = payload[1 + (hop.record_index() * SHORT_RECORD_LEN)
                ..1 + ((1 + hop.record_index()) * SHORT_RECORD_LEN)]
                .to_vec();

            if let Err(error) =
                ChaChaPoly::with_nonce(hop.key_context.reply_key(), hop.record_index() as u64)
                    .decrypt_with_ad(hop.key_context.state(), &mut record)
            {
                tracing::debug!(
                    target: LOG_TARGET,
                    router_id = %hop.router_id(),
                    tunnel_id = ?self.tunnel_id,
                    hop_tunnel_id = ?hop.tunnel_id,
                    ?error,
                    "failed to decrypt build record"
                );

                hop_results[hop_idx].1 = Some(Err(TunnelError::InvalidMessage));
                return Err(hop_results);
            }

            // was the tunnel accepted or rejected
            let hop_status = record[201];

            payload[1..]
                .chunks_mut(SHORT_RECORD_LEN)
                .enumerate()
                .filter(|(index, _)| index != &hop.record_index())
                .for_each(|(index, record)| {
                    ChaCha::with_nonce(hop.key_context.reply_key(), index as u64)
                        .encrypt_ref(record);
                });

            match hop_status {
                0x00 => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        tunnel_id = ?self.tunnel_id,
                        hop_tunnel_id = ?hop.tunnel_id,
                        direction = ?T::direction(),
                        "tunnel accepted",
                    );
                    hop_results[hop_idx].1 = Some(Ok(()));
                    accepted_hops.push(hop);
                }
                reason => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        tunnel_id = ?self.tunnel_id,
                        hop_tunnel_id = ?hop.tunnel_id,
                        direction = ?T::direction(),
                        ?reason,
                        "tunnel rejected",
                    );
                    hop_results[hop_idx].1 = Some(Err(TunnelError::TunnelRejected(reason)));
                }
            }
        }

        // if all hops accepted the tunnel build request, build the the tunnel
        //
        // otherwise return an error since one or more hops rejected the tunnel
        if accepted_hops.len() != num_hops {
            return Err(hop_results);
        }

        Ok(accepted_hops
            .into_iter()
            .fold(
                TunnelBuilder::new(self.name, self.tunnel_id, self.receiver),
                |builder, hop| builder.with_hop(hop),
            )
            .build())
    }

    /// Get reference to pending tunnel's hops.
    pub fn hops(&self) -> &VecDeque<TunnelHop> {
        &self.hops
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        config::TransitConfig,
        crypto::{EphemeralPublicKey, StaticPublicKey},
        events::EventManager,
        i2np::{tunnel::gateway::TunnelGateway, MessageBuilder},
        primitives::MessageId,
        profile::ProfileStorage,
        router::context::RouterContext,
        runtime::mock::MockRuntime,
        shutdown::ShutdownContext,
        tunnel::{
            garlic::{DeliveryInstructions as GarlicDeliveryInstructions, GarlicHandler},
            hop::inbound::InboundTunnel,
            noise::NoiseContext,
            pool::TunnelPoolBuildParameters,
            routing_table::{RoutingKindRecycle, RoutingTable},
            tests::{make_router, TestTransitTunnelManager},
            transit::TransitTunnelManager,
        },
    };
    use bytes::Bytes;
    use thingbuf::mpsc::{channel, with_recycle};

    #[tokio::test]
    async fn create_outbound_tunnel() {
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TestTransitTunnelManager>,
        ) = (0..3)
            .map(|i| {
                let manager = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

                ((manager.router_hash(), manager.public_key()), manager)
            })
            .unzip();

        let (local_hash, _, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[1..].len() % 218, 0);

        let message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), transit_manager)| {
                let (_, message, _) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );
        assert_eq!(message.message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&message.payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);

        let message = Message::parse_standard(&payload).unwrap();
        assert!(pending_tunnel.try_build_tunnel(message).is_ok());
    }

    #[tokio::test]
    async fn create_inbound_tunnel() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<(
                GarlicHandler<MockRuntime>,
                TransitTunnelManager<MockRuntime>,
            )>,
        ) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(
                |(router_hash, static_key, signing_key, noise_context, router_info)| {
                    let (transit_tx, transit_rx) = channel(16);
                    let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                    let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                    let shutdown_handle = shutdown_ctx.handle();
                    let routing_table =
                        RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                    (
                        (router_hash, static_key.public(), shutdown_ctx),
                        (
                            GarlicHandler::new(noise_context.clone(), handle.clone()),
                            TransitTunnelManager::new(
                                Some(TransitConfig {
                                    max_tunnels: Some(5000),
                                }),
                                RouterContext::new(
                                    handle.clone(),
                                    ProfileStorage::new(&[], &[]),
                                    router_info.identity.id(),
                                    Bytes::from(router_info.serialize(&signing_key)),
                                    static_key,
                                    signing_key,
                                    2u8,
                                    event_handle.clone(),
                                ),
                                routing_table,
                                transit_rx,
                                shutdown_handle,
                            ),
                        ),
                    )
                },
            )
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let _gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());
        let (_tx, rx) = channel(64);

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<InboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Inbound {
                        tunnel_id,
                        router_id: local_hash.clone(),
                    },
                    receiver: ReceiverKind::Inbound {
                        message_rx: rx,
                        handle,
                    },
                },
            )
            .unwrap();

        let message = match transit_managers[0].0.handle_message(message).unwrap().next() {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[1..].len() % 218, 0);
        assert_eq!(message.payload[1..].len() / 218, 4);
        assert_eq!(message.payload[0], 4u8);

        let message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), (_, transit_manager))| {
                let (_, message, _) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );

        // verify that our fake record can be found
        assert!(message.payload[1..]
            .chunks(218)
            .find(|chunk| &chunk[..16] == &local_hash[..16])
            .is_some());

        assert_eq!(message.message_type, MessageType::ShortTunnelBuild);
        assert!(pending_tunnel.try_build_tunnel(message).is_ok());
    }

    #[test]
    fn tunnel_rejected() {
        let (hops, noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, sk, _, noise_context, _)| {
                ((router_hash, sk.public()), noise_context)
            })
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        let Message {
            message_type: MessageType::ShortTunnelBuild,
            message_id: parsed_message_id,
            expiration,
            mut payload,
        } = message
        else {
            panic!("invalid message");
        };

        assert_eq!(parsed_message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(payload[1..].len() % 218, 0);

        fn find_own_record<'a>(
            hash: &Bytes,
            payload: &'a mut [u8],
        ) -> Option<(usize, &'a mut [u8])> {
            payload
                .chunks_mut(218)
                .enumerate()
                .find(|(_, chunk)| &chunk[..16] == &hash[..16])
        }

        for (i, ((router_hash, _), noise)) in hops.iter().zip(noise_contexts.iter()).enumerate() {
            let (record_idx, record) = find_own_record(&router_hash, &mut payload[1..]).unwrap();

            let new_record = record[..].to_vec();

            let pk = EphemeralPublicKey::from_bytes(&new_record[16..48]).unwrap();

            let mut session = noise.create_short_inbound_session(pk);
            let decrypted_record = session.decrypt_build_record(record[48..].to_vec()).unwrap();

            let (_tunnel_id, role) = {
                let record = short::TunnelBuildRecord::parse(&decrypted_record).unwrap();
                (record.tunnel_id(), record.role())
            };

            if i % 2 == 0 {
                record[201] = 30;
            } else {
                record[201] = 0x00;
            }

            session.create_tunnel_keys(role).unwrap();
            session.encrypt_build_records(&mut payload, record_idx).unwrap();
        }

        let message = Message {
            message_type: MessageType::OutboundTunnelBuildReply,
            message_id: message_id.into(),
            expiration,
            payload,
        };

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) =>
                for (i, (_, result)) in error.into_iter().enumerate() {
                    if i % 2 == 0 {
                        assert_eq!(result, Some(Err(TunnelError::TunnelRejected(30))));
                    } else {
                        assert_eq!(result, Some(Ok(())));
                    }
                },
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn invalid_ciphertext() {
        let (hops, _noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, sk, _, noise_context, _)| {
                ((router_hash, sk.public()), noise_context)
            })
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[1..].len() % 218, 0);

        // try to parse the tunnel build request as a reply, ciphertexsts won't decrypt correctly
        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));

                // cipher text for the first hop was invalid so the status of later hops couldn't be
                // determined
                assert_eq!(error[1].1, None);
                assert_eq!(error[2].1, None);
            }
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn malformed_tunnel_build_reply() {
        let (hops, _noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, sk, _, noise_context, _)| {
                ((router_hash, sk.public()), noise_context)
            })
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, mut message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));

        // set random data as payload which causes the length check to fail
        message.message_type = MessageType::OutboundTunnelBuildReply;
        message.payload = vec![0u8; 123];

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));

                // length was too short so the records couldn't be parsed
                assert_eq!(error[1].1, None);
                assert_eq!(error[2].1, None);
            }
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn create_long_outbound_tunnel() {
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TestTransitTunnelManager>,
        ) = (0..8)
            .map(|i| {
                let manager = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

                ((manager.router_hash(), manager.public_key()), manager)
            })
            .unzip();

        let (local_hash, _, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[0], 8u8);
        assert_eq!(message.payload[1..].len() % 218, 0);

        let message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), transit_manager)| {
                let (_, message, _) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );
        assert_eq!(message.message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&message.payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);

        let message = Message::parse_standard(&payload).unwrap();
        assert!(pending_tunnel.try_build_tunnel(message).is_ok());
    }

    #[test]
    fn wrong_build_message_type() {
        let (hops, _noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, sk, _, noise_context, _)| {
                ((router_hash, sk.public()), noise_context)
            })
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, mut message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));

        // invalid message type
        message.message_type = MessageType::DatabaseStore;

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));

                // only the last hop is penalized
                assert_eq!(error[1].1, None);
                assert_eq!(error[2].1, None);
            }
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn build_message_garlic_decrypt_error() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let mut hops = Vec::<(Bytes, StaticPublicKey)>::new();
        let mut ctxs = Vec::<ShutdownContext<MockRuntime>>::new();
        let mut transit_managers = Vec::<TransitTunnelManager<MockRuntime>>::new();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        for _ in 0..3 {
            let (router_hash, static_key, signing_key, _noise_context, router_info) =
                make_router(true);

            let (transit_tx, transit_rx) = channel(16);
            let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
            let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
            let shutdown_handle = shutdown_ctx.handle();

            let routing_table =
                RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

            hops.push((router_hash, static_key.public()));
            ctxs.push(shutdown_ctx);
            transit_managers.push(TransitTunnelManager::new(
                Some(TransitConfig {
                    max_tunnels: Some(5000),
                }),
                RouterContext::new(
                    handle.clone(),
                    ProfileStorage::new(&[], &[]),
                    router_info.identity.id(),
                    Bytes::from(router_info.serialize(&signing_key)),
                    static_key,
                    signing_key,
                    2u8,
                    event_handle.clone(),
                ),
                routing_table,
                transit_rx,
                shutdown_handle,
            ));
        }

        let (local_hash, _local_sk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise.clone(),
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        let message = (0..transit_managers.len() - 1).fold(message, |message, i| {
            let (_, msg, _) = transit_managers[i].handle_short_tunnel_build(message).unwrap();

            Message::parse_short(&msg).unwrap()
        });

        let (_, msg, _) = transit_managers[2].handle_short_tunnel_build(message).unwrap();

        let Message {
            message_type,
            payload,
            ..
        } = Message::parse_short(&msg).unwrap();

        assert_eq!(message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);
        let mut message = Message::parse_standard(&payload).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);

        // write garbage at the start of the garlic message so it fails to decrypt
        for i in 0..10 {
            message.payload[5 + i] = i as u8;
        }

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));

                // only the last hop is penalized
                assert_eq!(error[1].1, None);
                assert_eq!(error[2].1, None);
            }
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn build_message_not_a_valid_garlic_message() {
        let (hops, _noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, sk, _, noise_context, _)| {
                ((router_hash, sk.public()), noise_context)
            })
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));

        let mut msg = MessageBuilder::short()
            .with_expiration(MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::Garlic)
            .with_message_id(MockRuntime::rng().next_u32())
            .with_payload(&vec![1, 2, 3, 4, 5])
            .build();

        let garlic_tag = pending_tunnel.hops.back().as_ref().unwrap().key_context.garlic_tag();
        let garlic_key = pending_tunnel.hops.back().as_ref().unwrap().key_context.garlic_key();

        // message length + poly13055 tag + garlic tag + garlic message length
        let mut out = BytesMut::with_capacity(msg.len() + 16 + 8 + 4);

        // encryption must succeed since the parameters are managed by us
        ChaChaPoly::new(&garlic_key)
            .encrypt_with_ad_new(&garlic_tag, &mut msg)
            .expect("to succeed");

        out.put_u32(msg.len() as u32 + 8);
        out.put_slice(&garlic_tag);
        out.put_slice(&msg);

        let message = Message {
            message_type: MessageType::Garlic,
            message_id: message.message_id,
            expiration: message.expiration,
            payload: out.to_vec(),
        };

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));

                // only the last hop is penalized
                assert_eq!(error[1].1, None);
                assert_eq!(error[2].1, None);
            }
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn build_message_clove_not_found() {
        let (hops, _noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, sk, _, noise_context, _)| {
                ((router_hash, sk.public()), noise_context)
            })
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));

        let mut msg = GarlicMessageBuilder::default().with_date_time(1337u32).build();

        let garlic_tag = pending_tunnel.hops.back().as_ref().unwrap().key_context.garlic_tag();
        let garlic_key = pending_tunnel.hops.back().as_ref().unwrap().key_context.garlic_key();

        // message length + poly13055 tag + garlic tag + garlic message length
        let mut out = BytesMut::with_capacity(msg.len() + 16 + 8 + 4);

        // encryption must succeed since the parameters are managed by us
        ChaChaPoly::new(&garlic_key)
            .encrypt_with_ad_new(&garlic_tag, &mut msg)
            .expect("to succeed");

        out.put_u32(msg.len() as u32 + 8);
        out.put_slice(&garlic_tag);
        out.put_slice(&msg);

        let message = Message {
            message_type: MessageType::Garlic,
            message_id: message.message_id,
            expiration: message.expiration,
            payload: out.to_vec(),
        };

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));

                // only the last hop is penalized
                assert_eq!(error[1].1, None);
                assert_eq!(error[2].1, None);
            }
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn hop_record_decrypt_error() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<(
                GarlicHandler<MockRuntime>,
                TransitTunnelManager<MockRuntime>,
            )>,
        ) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(
                |(router_hash, static_key, signing_key, noise_context, router_info)| {
                    let (transit_tx, transit_rx) = channel(16);
                    let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                    let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                    let shutdown_handle = shutdown_ctx.handle();
                    let routing_table =
                        RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                    (
                        (router_hash, static_key.public(), shutdown_ctx),
                        (
                            GarlicHandler::new(noise_context.clone(), handle.clone()),
                            TransitTunnelManager::new(
                                Some(TransitConfig {
                                    max_tunnels: Some(5000),
                                }),
                                RouterContext::new(
                                    handle.clone(),
                                    ProfileStorage::new(&[], &[]),
                                    router_info.identity.id(),
                                    Bytes::from(router_info.serialize(&signing_key)),
                                    static_key,
                                    signing_key,
                                    2u8,
                                    event_handle.clone(),
                                ),
                                routing_table,
                                transit_rx,
                                shutdown_handle,
                            ),
                        ),
                    )
                },
            )
            .unzip();

        let (local_hash, _local_sk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let _gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());
        let (_tx, rx) = channel(64);

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<InboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Inbound {
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Inbound {
                        message_rx: rx,
                        handle,
                    },
                },
            )
            .unwrap();

        let message = match transit_managers[0].0.handle_message(message).unwrap().next() {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[1..].len() % 218, 0);

        let mut message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), (_, transit_manager))| {
                let (_, message, _) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );

        assert_eq!(message.message_type, MessageType::ShortTunnelBuild);

        // write garbage into first build record
        for i in 1..20 {
            message.payload[i + SHORT_RECORD_LEN * pending_tunnel.hops[0].record_index()] = 0u8;
        }

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));
                assert_eq!(error[1].1, Some(Ok(())));
                assert_eq!(error[2].1, Some(Ok(())));
            }
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn too_long_inbound_tunnel() {
        let hops: Vec<(Bytes, StaticPublicKey)> = (0..8)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, static_key, _, _, _)| (router_hash, static_key.public()))
            .collect();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let _gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());
        let (_tx, rx) = channel(64);

        match PendingTunnel::<InboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
            TunnelBuildParameters {
                hops: hops.clone(),
                name: Str::from("tunnel-pool"),
                noise: local_noise,
                message_id,
                tunnel_info: TunnelInfo::Inbound {
                    tunnel_id,
                    router_id: local_hash.clone(),
                },
                receiver: ReceiverKind::Inbound {
                    message_rx: rx,
                    handle,
                },
            },
        ) {
            Err(TunnelError::TooManyHops(8usize)) => {}
            _ => panic!("unexpected result"),
        }
    }

    #[tokio::test]
    async fn inbound_fake_record_router_hash_modified() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<(
                GarlicHandler<MockRuntime>,
                TransitTunnelManager<MockRuntime>,
            )>,
        ) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(
                |(router_hash, static_key, signing_key, noise_context, router_info)| {
                    let (transit_tx, transit_rx) = channel(16);
                    let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                    let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                    let shutdown_handle = shutdown_ctx.handle();
                    let routing_table =
                        RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                    (
                        (router_hash, static_key.public(), shutdown_ctx),
                        (
                            GarlicHandler::new(noise_context.clone(), handle.clone()),
                            TransitTunnelManager::new(
                                Some(TransitConfig {
                                    max_tunnels: Some(5000),
                                }),
                                RouterContext::new(
                                    handle.clone(),
                                    ProfileStorage::new(&[], &[]),
                                    router_info.identity.id(),
                                    Bytes::from(router_info.serialize(&signing_key)),
                                    static_key,
                                    signing_key,
                                    2u8,
                                    event_handle.clone(),
                                ),
                                routing_table,
                                transit_rx,
                                shutdown_handle,
                            ),
                        ),
                    )
                },
            )
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let _gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());
        let (_tx, rx) = channel(64);

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<InboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Inbound {
                        tunnel_id,
                        router_id: local_hash.clone(),
                    },
                    receiver: ReceiverKind::Inbound {
                        message_rx: rx,
                        handle,
                    },
                },
            )
            .unwrap();

        let message = match transit_managers[0].0.handle_message(message).unwrap().next() {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[1..].len() % 218, 0);
        assert_eq!(message.payload[1..].len() / 218, 4);
        assert_eq!(message.payload[0], 4u8);

        let mut message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), (_, transit_manager))| {
                let (_, message, _) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );

        // modify local router hash so it's not found
        let record = message.payload[1..]
            .chunks_mut(218)
            .find(|chunk| &chunk[..16] == &local_hash[..16])
            .unwrap();
        record[0] = record[0].wrapping_add(1);

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));
                assert_eq!(error[1].1, None);
                assert_eq!(error[2].1, None);
            }
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn inbound_fake_record_modified() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<(
                GarlicHandler<MockRuntime>,
                TransitTunnelManager<MockRuntime>,
            )>,
        ) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(
                |(router_hash, static_key, signing_key, noise_context, router_info)| {
                    let (transit_tx, transit_rx) = channel(16);
                    let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                    let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                    let shutdown_handle = shutdown_ctx.handle();
                    let routing_table =
                        RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                    (
                        (router_hash, static_key.public(), shutdown_ctx),
                        (
                            GarlicHandler::new(noise_context.clone(), handle.clone()),
                            TransitTunnelManager::new(
                                Some(TransitConfig {
                                    max_tunnels: Some(5000),
                                }),
                                RouterContext::new(
                                    handle.clone(),
                                    ProfileStorage::new(&[], &[]),
                                    router_info.identity.id(),
                                    Bytes::from(router_info.serialize(&signing_key)),
                                    static_key,
                                    signing_key,
                                    2u8,
                                    event_handle.clone(),
                                ),
                                routing_table,
                                transit_rx,
                                shutdown_handle,
                            ),
                        ),
                    )
                },
            )
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let _gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());
        let (_tx, rx) = channel(64);

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<InboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Inbound {
                        tunnel_id,
                        router_id: local_hash.clone(),
                    },
                    receiver: ReceiverKind::Inbound {
                        message_rx: rx,
                        handle,
                    },
                },
            )
            .unwrap();

        let message = match transit_managers[0].0.handle_message(message).unwrap().next() {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[1..].len() % 218, 0);
        assert_eq!(message.payload[1..].len() / 218, 4);
        assert_eq!(message.payload[0], 4u8);

        let mut message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), (_, transit_manager))| {
                let (_, message, _) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );

        // keep router hash unmodified but modify the key so that checksum verificatin fails
        let record = message.payload[1..]
            .chunks_mut(218)
            .find(|chunk| &chunk[..16] == &local_hash[..16])
            .unwrap();
        record[20] = record[20].wrapping_add(1);

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));
                assert_eq!(error[1].1, None);
                assert_eq!(error[2].1, None);
            }
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn empty_payload_inbound() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<(
                GarlicHandler<MockRuntime>,
                TransitTunnelManager<MockRuntime>,
            )>,
        ) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(
                |(router_hash, static_key, signing_key, noise_context, router_info)| {
                    let (transit_tx, transit_rx) = channel(16);
                    let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                    let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                    let shutdown_handle = shutdown_ctx.handle();
                    let routing_table =
                        RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                    (
                        (router_hash, static_key.public(), shutdown_ctx),
                        (
                            GarlicHandler::new(noise_context.clone(), handle.clone()),
                            TransitTunnelManager::new(
                                Some(TransitConfig {
                                    max_tunnels: Some(5000),
                                }),
                                RouterContext::new(
                                    handle.clone(),
                                    ProfileStorage::new(&[], &[]),
                                    router_info.identity.id(),
                                    Bytes::from(router_info.serialize(&signing_key)),
                                    static_key,
                                    signing_key,
                                    2u8,
                                    event_handle.clone(),
                                ),
                                routing_table,
                                transit_rx,
                                shutdown_handle,
                            ),
                        ),
                    )
                },
            )
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let _gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());
        let (_tx, rx) = channel(64);

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<InboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Inbound {
                        tunnel_id,
                        router_id: local_hash.clone(),
                    },
                    receiver: ReceiverKind::Inbound {
                        message_rx: rx,
                        handle,
                    },
                },
            )
            .unwrap();

        let message = match transit_managers[0].0.handle_message(message).unwrap().next() {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[1..].len() % 218, 0);
        assert_eq!(message.payload[1..].len() / 218, 4);
        assert_eq!(message.payload[0], 4u8);

        let mut message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), (_, transit_manager))| {
                let (_, message, _) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );

        // make payload empty
        message.payload = Vec::new();

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));
                assert_eq!(error[1].1, None);
                assert_eq!(error[2].1, None);
            }
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn empty_payload_outbound_garlic() {
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey)>,
            Vec<TestTransitTunnelManager>,
        ) = (0..3)
            .map(|i| {
                let manager = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

                ((manager.router_hash(), manager.public_key()), manager)
            })
            .unzip();

        let (local_hash, _, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(message.message_id, message_id.into());
        assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
        assert_eq!(message.payload[1..].len() % 218, 0);

        let message = hops.iter().zip(transit_managers.iter_mut()).fold(
            message,
            |acc, ((_, _), transit_manager)| {
                let (_, message, _) = transit_manager.handle_short_tunnel_build(acc).unwrap();
                Message::parse_short(&message).unwrap()
            },
        );
        assert_eq!(message.message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&message.payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);

        let mut message = Message::parse_standard(&payload).unwrap();

        // make payload empty
        message.payload = Vec::new();

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::InvalidMessage)));
                assert_eq!(error[1].1, None);
                assert_eq!(error[2].1, None);
            }
            _ => panic!("invalid result"),
        }
    }
}
