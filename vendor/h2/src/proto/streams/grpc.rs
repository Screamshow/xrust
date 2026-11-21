// SPDX-License-Identifier: Apache-2.0
// BDP algorithm and receive-flow semantics derived from grpc-go v1.85.0,
// Copyright 2014-2018 gRPC authors. See ../../../GRPC_LICENSE.
// Kept opt-in for the gRPC client; ordinary h2 client/server policies are unchanged.

use crate::frame::StreamId;
use std::collections::VecDeque;
use std::time::Instant;

pub(super) const BDP_PING: [u8; 8] = [2, 4, 16, 16, 9, 14, 7, 7];
const LIMIT: u32 = 16 << 20;

#[derive(Debug)]
pub(super) enum Control {
    Credit(StreamId, u32),
    Ping,
    Settings(u32),
}

#[derive(Debug)]
pub(super) struct GrpcRecv {
    pub conn_limit: u32,
    pub controls: VecDeque<Control>,
    pub flushing: bool,
    bdp: Option<Bdp>,
}

impl GrpcRecv {
    pub fn new(dynamic: bool, _stream_limit: u32) -> Self {
        Self {
            conn_limit: 65_535,
            controls: VecDeque::new(),
            flushing: false,
            bdp: dynamic.then(Bdp::new),
        }
    }

    pub fn add(&mut self, n: u32) -> bool {
        self.bdp.as_mut().is_some_and(|b| b.add(n))
    }

    pub fn sent(&mut self) {
        if let Some(b) = &mut self.bdp {
            b.sent = Some(Instant::now());
        }
    }

    pub fn pong(&mut self, payload: [u8; 8]) -> Option<u32> {
        if payload != BDP_PING {
            return None;
        }
        let b = self.bdp.as_mut()?;
        let elapsed = b.sent?.elapsed().as_secs_f64();
        b.calculate(elapsed)
    }
}

#[derive(Debug)]
struct Bdp {
    estimate: u32,
    sample: u32,
    samples: u64,
    pending: bool,
    sent: Option<Instant>,
    rtt: f64,
    bandwidth: f64,
}

impl Bdp {
    fn new() -> Self {
        Self {
            estimate: 65_535,
            sample: 0,
            samples: 0,
            pending: false,
            sent: None,
            rtt: 0.0,
            bandwidth: 0.0,
        }
    }

    fn add(&mut self, n: u32) -> bool {
        if self.estimate == LIMIT {
            return false;
        }
        if !self.pending {
            self.pending = true;
            self.sample = n;
            self.samples += 1;
            self.sent = None;
            true
        } else {
            // Reference samples are u32. Saturation prevents arithmetic wrap
            // from hostile traffic while a peer withholds the matching ACK.
            self.sample = self.sample.saturating_add(n);
            false
        }
    }

    fn calculate(&mut self, elapsed: f64) -> Option<u32> {
        if !self.pending || elapsed <= 0.0 {
            return None;
        }
        self.sent = None;
        self.pending = false;
        if self.samples < 10 {
            self.rtt += (elapsed - self.rtt) / self.samples as f64;
        } else {
            self.rtt += (elapsed - self.rtt) * 0.9;
        }
        let bandwidth = self.sample as f64 / (self.rtt * 1.5);
        self.bandwidth = self.bandwidth.max(bandwidth);
        if self.sample as f64 >= 0.66 * self.estimate as f64
            && bandwidth == self.bandwidth
            && self.estimate != LIMIT
        {
            self.estimate = (u64::from(self.sample) * 2).min(u64::from(LIMIT)) as u32;
            Some(self.estimate)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quarter_threshold_does_not_shrink_with_the_remaining_window() {
        let mut flow = super::super::flow_control::FlowControl::new();
        flow.inc_window(65535).unwrap();
        flow.assign_capacity(65535).unwrap();
        flow.set_grpc_refresh(65535);
        flow.send_data(65000).unwrap();
        flow.assign_capacity(600).unwrap();
        assert_eq!(flow.unclaimed_capacity(), None);
        flow.assign_capacity(15783).unwrap();
        assert_eq!(flow.unclaimed_capacity(), Some(16383));
    }
    #[test]
    fn probe_is_data_driven_and_growth_matches_reference_equations() {
        let mut b = Bdp::new();
        assert!(b.add(32768));
        assert!(!b.add(32767));
        assert_eq!(b.calculate(0.01), Some(131070));
        assert!(b.add(10));
        assert_eq!(b.calculate(0.01), None);
        assert_eq!(b.calculate(0.01), None);
        assert!(b.add(LIMIT));
        assert_eq!(b.calculate(0.001), Some(LIMIT));
        assert!(!b.add(1));
    }
    #[test]
    fn unmatched_or_unsent_pong_cannot_grow_windows() {
        let mut g = GrpcRecv::new(true, 65535);
        assert!(g.add(65535));
        assert_eq!(g.pong(BDP_PING), None);
        g.sent();
        assert_eq!(g.pong([0; 8]), None);
        assert!(g.pong(BDP_PING).is_some());
        assert_eq!(g.pong(BDP_PING), None);
    }
}
