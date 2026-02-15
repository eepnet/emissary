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

use crate::transport::FirewallStatus;

use core::net::SocketAddr;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::detector";

/// Number of consecutive confirmations required before changing state.
const CONFIRMATION_THRESHOLD: usize = 3usize;

/// Firewall/external address detector.
///
/// https://geti2p.net/spec/ssu2#results-state-machine
pub struct Detector {
    /// Our external address.
    external_address: Option<SocketAddr>,

    /// Firewall status.
    firewall_status: FirewallStatus,

    /// Pending status that needs confirmation.
    pending_status: Option<FirewallStatus>,

    /// Number of consecutive confirmations for the pending status.
    confirmation_count: usize,
}

impl Detector {
    /// Create new `Detector`.
    pub fn new() -> Self {
        Self {
            external_address: None,
            firewall_status: FirewallStatus::Unknown,
            pending_status: None,
            confirmation_count: 0usize,
        }
    }

    /// Register new external address to detector.
    pub fn add_external_address(&mut self, address: SocketAddr) -> Option<SocketAddr> {
        if self.external_address.is_none() {
            tracing::info!(
                target: LOG_TARGET,
                ?address,
                "discovered external address",
            );

            self.external_address = Some(address);
            return self.external_address;
        }

        self.external_address = Some(address);
        None
    }

    /// Determine the result of a peer test based on received messages.
    ///
    /// Returns `Some(FirewallStatus)` if the status has changed.
    pub fn add_peer_test_result(
        &mut self,
        message4: bool,
        message5: bool,
        message7: Option<SocketAddr>,
    ) -> Option<FirewallStatus> {
        let detected = self.determine_status(message4, message5, message7);

        tracing::debug!(
            target: LOG_TARGET,
            ?message4,
            ?message5,
            ?message7,
            ?detected,
            current = ?self.firewall_status,
            "peer test result",
        );

        match self.pending_status {
            // status has changed
            None if self.firewall_status != detected => {
                self.pending_status = Some(detected);
                self.confirmation_count = 1;
                return None;
            }

            // detected status is the same as current status
            None => return None,

            // pending doesn't match detected, reset current status to detected
            Some(pending) if pending != detected => {
                self.pending_status = Some(detected);
                self.confirmation_count = 1;
                return None;
            }

            // detected status is the same as pending stattus
            Some(_) => {
                self.confirmation_count += 1;
            }
        }

        if self.confirmation_count >= CONFIRMATION_THRESHOLD {
            let old_status = self.firewall_status;
            self.firewall_status = detected;
            self.pending_status = None;
            self.confirmation_count = 0;

            if old_status != detected {
                tracing::info!(
                    target: LOG_TARGET,
                    ?old_status,
                    new_status = ?detected,
                    "firewall status changed",
                );
                return Some(detected);
            }
        }

        None
    }

    /// Determine the firewall status based on the peer test messages received.
    fn determine_status(
        &self,
        message4: bool,
        message5: bool,
        message7: Option<SocketAddr>,
    ) -> FirewallStatus {
        match (message4, message5, message7) {
            // n n n: unknown
            (false, false, None) => FirewallStatus::Unknown,

            // y n n: firewalled (unless currently symnat)
            (true, false, None) =>
                if self.firewall_status == FirewallStatus::SymmetricNat {
                    FirewallStatus::SymmetricNat
                } else {
                    FirewallStatus::Firewalled
                },

            // n y n: ok (unless currently symnat)
            (false, true, None) =>
                if self.firewall_status == FirewallStatus::SymmetricNat {
                    FirewallStatus::Unknown
                } else {
                    FirewallStatus::Ok
                },

            // y y n: ok (unless currently symnat)
            (true, true, None) =>
                if self.firewall_status == FirewallStatus::SymmetricNat {
                    FirewallStatus::Unknown
                } else {
                    FirewallStatus::Ok
                },

            // n n y: n/a (can't send message 6 without message 4)
            (false, false, Some(_)) => FirewallStatus::Unknown,

            // y n y: firewalled or symnat (requires sending message 6 without receiving message 5)
            (true, false, Some(reported_address)) => match self.external_address {
                None => FirewallStatus::Firewalled,
                Some(external_address) => match (
                    external_address.ip() == reported_address.ip(),
                    external_address.port() == reported_address.port(),
                ) {
                    (true, true) => FirewallStatus::Firewalled,
                    (true, false) => FirewallStatus::SymmetricNat,
                    (false, true) => FirewallStatus::Firewalled,
                    (false, false) => FirewallStatus::SymmetricNat,
                },
            },

            // n y y: n/a (can't send message 6 without message 4)
            (false, true, Some(_)) => FirewallStatus::Unknown,

            // y y y: ok
            (true, true, Some(_)) => FirewallStatus::Ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_result<const NUM: usize>(
        detector: &mut Detector,
        message4: bool,
        message5: bool,
        message7: Option<SocketAddr>,
    ) -> Option<FirewallStatus> {
        (0..NUM).fold(None, |_, _x| {
            detector.add_peer_test_result(message4, message5, message7)
        })
    }

    #[test]
    fn no_messages_received_returns_none() {
        let mut detector = Detector::new();
        let result = detector.add_peer_test_result(false, false, None);
        assert!(result.is_none());
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);
    }

    #[test]
    fn confirmation_threshold_required() {
        let mut detector = Detector::new();

        assert!(detector.add_peer_test_result(true, false, None).is_none());
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);

        assert!(detector.add_peer_test_result(true, false, None).is_none());
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);

        assert_eq!(
            detector.add_peer_test_result(true, false, None),
            Some(FirewallStatus::Firewalled)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Firewalled);
    }

    #[test]
    fn mixed_results_reset_confirmation() {
        let mut detector = Detector::new();

        assert!(detector.add_peer_test_result(true, false, None).is_none());
        assert!(detector.add_peer_test_result(true, false, None).is_none());

        // different detected status (firewalled vs ok)
        assert!(detector.add_peer_test_result(false, true, None).is_none());

        // two ore ok results
        assert!(detector.add_peer_test_result(false, true, None).is_none());
        assert_eq!(
            detector.add_peer_test_result(false, true, None),
            Some(FirewallStatus::Ok)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Ok);
    }

    #[test]
    fn msg4_only_firewalled() {
        let mut detector = Detector::new();

        assert_eq!(
            apply_result::<3>(&mut detector, true, false, None),
            Some(FirewallStatus::Firewalled)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Firewalled);
    }

    #[test]
    fn msg4_only_stays_symnat_if_currently_symnat() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        // set status to symnat
        let msg7 = SocketAddr::new("1.2.3.4".parse().unwrap(), 8889);
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, Some(msg7)),
            Some(FirewallStatus::SymmetricNat)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::SymmetricNat);

        // stays as symnat
        assert!(apply_result::<3>(&mut detector, true, false, None).is_none());
        assert_eq!(detector.firewall_status, FirewallStatus::SymmetricNat);
    }

    #[test]
    fn msg5_only_ok() {
        let mut detector = Detector::new();

        // msg 5 received -> ok since not currently symnat
        assert_eq!(
            apply_result::<3>(&mut detector, false, true, None),
            Some(FirewallStatus::Ok)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Ok);
    }

    #[test]
    fn msg5_only_unknown_if_currently_symnat() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        // router is symnatted
        let msg7 = SocketAddr::new("1.2.3.4".parse().unwrap(), 8889);
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, Some(msg7)),
            Some(FirewallStatus::SymmetricNat)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::SymmetricNat);

        // message 5 received, since symnatted, status is unknown
        assert_eq!(
            apply_result::<3>(&mut detector, false, true, None),
            Some(FirewallStatus::Unknown)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);
    }

    #[test]
    fn msg4_msg5_ok() {
        let mut detector = Detector::new();

        // ok
        assert_eq!(
            apply_result::<3>(&mut detector, true, true, None),
            Some(FirewallStatus::Ok)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Ok);
    }

    #[test]
    fn msg4_msg5_unknown_if_currently_symnat() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        // router is symnatted
        let msg7 = SocketAddr::new("1.2.3.4".parse().unwrap(), 8889);
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, Some(msg7)),
            Some(FirewallStatus::SymmetricNat)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::SymmetricNat);

        // msg4 + msg5 will make the status unknown
        assert_eq!(
            apply_result::<3>(&mut detector, true, true, None),
            Some(FirewallStatus::Unknown)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);
    }

    #[test]
    fn msg4_msg7_ip_port_match_firewalled() {
        let mut detector = Detector::new();
        let address = SocketAddr::new("1.2.3.4".parse().unwrap(), 8888);
        detector.add_external_address(address);

        assert_eq!(
            apply_result::<3>(&mut detector, true, false, Some(address)),
            Some(FirewallStatus::Firewalled)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Firewalled);
    }

    #[test]
    fn msg4_msg7_ip_match_port_mismatch_symnat() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        // same address, different prot
        let msg7 = SocketAddr::new("1.2.3.4".parse().unwrap(), 8889);
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, Some(msg7)),
            Some(FirewallStatus::SymmetricNat)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::SymmetricNat);
    }

    #[test]
    fn msg4_msg7_ip_mismatch_port_match_firewalled() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        // same port, different address
        let msg7 = SocketAddr::new("5.6.7.8".parse().unwrap(), 8888);
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, Some(msg7)),
            Some(FirewallStatus::Firewalled)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Firewalled);
    }

    #[test]
    fn msg4_msg7_both_mismatch_symnat() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        // different ip and port
        let msg7 = SocketAddr::new("5.6.7.8".parse().unwrap(), 8889);
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, Some(msg7)),
            Some(FirewallStatus::SymmetricNat)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::SymmetricNat);
    }

    #[test]
    fn msg4_msg5_msg7_ip_port_match_ok() {
        let mut detector = Detector::new();
        let address = SocketAddr::new("1.2.3.4".parse().unwrap(), 8888);
        detector.add_external_address(address);

        assert_eq!(
            apply_result::<3>(&mut detector, true, true, Some(address)),
            Some(FirewallStatus::Ok)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Ok);
    }

    #[test]
    fn msg4_msg5_msg7_ip_match_port_mismatch_ok() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        let msg7 = SocketAddr::new("1.2.3.4".parse().unwrap(), 8889);
        assert_eq!(
            apply_result::<3>(&mut detector, true, true, Some(msg7)),
            Some(FirewallStatus::Ok)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Ok);
    }

    #[test]
    fn msg4_msg5_msg7_ip_mismatch_port_match_ok() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        let msg7 = SocketAddr::new("5.6.7.8".parse().unwrap(), 8888);
        assert_eq!(
            apply_result::<3>(&mut detector, true, true, Some(msg7)),
            Some(FirewallStatus::Ok)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Ok);
    }

    #[test]
    fn msg4_msg5_msg7_both_mismatch_ok() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        let msg7 = SocketAddr::new("5.6.7.8".parse().unwrap(), 8889);
        assert_eq!(
            apply_result::<3>(&mut detector, true, true, Some(msg7)),
            Some(FirewallStatus::Ok)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Ok);
    }

    #[test]
    fn transition_firewalled_to_ok() {
        let mut detector = Detector::new();

        // firewalled
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, None),
            Some(FirewallStatus::Firewalled)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Firewalled);

        // ok
        assert_eq!(
            apply_result::<3>(&mut detector, true, true, None),
            Some(FirewallStatus::Ok)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Ok);
    }

    #[test]
    fn transition_ok_to_firewalled() {
        let mut detector = Detector::new();

        // ok
        assert_eq!(
            apply_result::<3>(&mut detector, true, true, None),
            Some(FirewallStatus::Ok)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Ok);

        // firewalled
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, None),
            Some(FirewallStatus::Firewalled)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Firewalled);
    }

    #[test]
    fn transition_symnat_to_ok() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        // symnat
        let msg7 = SocketAddr::new("1.2.3.4".parse().unwrap(), 8889);
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, Some(msg7)),
            Some(FirewallStatus::SymmetricNat)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::SymmetricNat);

        // ok
        assert_eq!(
            apply_result::<3>(&mut detector, true, true, Some(msg7)),
            Some(FirewallStatus::Ok)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Ok);
    }

    #[test]
    fn exactly_three_confirmations_needed() {
        let mut detector = Detector::new();

        // first confirmation
        assert!(detector.add_peer_test_result(true, false, None).is_none());
        assert_eq!(detector.confirmation_count, 1);

        // second confirmation
        assert!(detector.add_peer_test_result(true, false, None).is_none());
        assert_eq!(detector.confirmation_count, 2);

        // third confirmation
        assert_eq!(
            detector.add_peer_test_result(true, false, None),
            Some(FirewallStatus::Firewalled)
        );
        assert_eq!(detector.confirmation_count, 0);
        assert!(detector.pending_status.is_none());
    }

    #[test]
    fn confirmation_resets_on_different_result() {
        let mut detector = Detector::new();
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);

        // two firewalled results
        assert!(detector.add_peer_test_result(true, false, None).is_none());
        assert!(detector.add_peer_test_result(true, false, None).is_none());
        assert_eq!(detector.confirmation_count, 2);
        assert_eq!(detector.pending_status, Some(FirewallStatus::Firewalled));
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);

        // ok result will reset
        assert!(detector.add_peer_test_result(false, true, None).is_none());
        assert_eq!(detector.confirmation_count, 1);
        assert_eq!(detector.pending_status, Some(FirewallStatus::Ok));
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);
    }

    #[test]
    fn no_change_when_same_status_confirmed() {
        let mut detector = Detector::new();
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);

        // firewalled
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, None),
            Some(FirewallStatus::Firewalled)
        );
        assert_eq!(detector.firewall_status, FirewallStatus::Firewalled);

        // verify status doesn't change
        for _ in 0..10 {
            assert!(detector.add_peer_test_result(true, false, None).is_none());
            assert_eq!(detector.firewall_status, FirewallStatus::Firewalled);
        }
    }

    #[test]
    fn add_external_address_first_time() {
        let mut detector = Detector::new();
        let address = SocketAddr::new("1.2.3.4".parse().unwrap(), 8889);

        assert_eq!(detector.add_external_address(address), Some(address));
        assert_eq!(detector.external_address, Some(address));
    }

    #[test]
    fn alternating_results_never_confirm() {
        let mut detector = Detector::new();
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);

        for _ in 0..10 {
            // firewalled
            detector.add_peer_test_result(true, false, None);

            // ok
            detector.add_peer_test_result(false, true, None);
        }

        // still unknown
        assert_eq!(detector.firewall_status, FirewallStatus::Unknown);
    }

    #[test]
    fn same_status_doesnt_start_pending_process() {
        let mut detector = Detector::new();
        detector.add_external_address(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888));

        // firewalled
        //
        // verify there is no pending status
        assert_eq!(
            apply_result::<3>(&mut detector, true, false, None),
            Some(FirewallStatus::Firewalled)
        );
        assert!(detector.pending_status.is_none());
        assert_eq!(detector.confirmation_count, 0);

        // add new but same test result and verify that pending is still none
        assert!(detector.add_peer_test_result(true, false, None).is_none());
        assert!(detector.pending_status.is_none());
        assert_eq!(detector.confirmation_count, 0);

        // add new and different test result and verify pending is updated
        assert!(detector
            .add_peer_test_result(
                true,
                true,
                Some(SocketAddr::new("1.2.3.4".parse().unwrap(), 8888))
            )
            .is_none());
        assert_eq!(detector.pending_status, Some(FirewallStatus::Ok));
        assert_eq!(detector.confirmation_count, 1);
    }
}
