// Chrome Initial packet layout, adapted for quinn's retransmission accounting.
// Algorithm reference: apernet/quic-go, commit 184d081eef3e, packet_packer.go
// (Copyright (c) 2016 the quic-go authors & Google, Inc., MIT; see LICENSE-MIT).
// Xrust adaptation retains quinn's licenses.
use crate::{
    VarInt,
    coding::BufMutExt,
    frame::{self, Crypto},
};
use rand::{Rng, RngExt, seq::SliceRandom};
use std::collections::VecDeque;

fn header(offset: u64, len: usize) -> usize {
    1 + VarInt::from_u64(offset).expect("CRYPTO offset").size()
        + VarInt::from_u64(len as u64).expect("CRYPTO length").size()
}
fn size(frame: &Crypto) -> usize {
    header(frame.offset, frame.data.len()) + frame.data.len()
}

pub(super) fn write(
    pending: &mut VecDeque<Crypto>,
    out: &mut Vec<u8>,
    limit: usize,
    rng: &mut impl Rng,
) -> (Vec<Crypto>, usize) {
    let available = limit.saturating_sub(out.len());
    let mut frames = Vec::new();
    if let Some(first) = pending.front() {
        let n = first.data.len();
        if first.offset == 0 && n > 0 {
            let h = header((n - 1) as u64, n);
            if available > 2 * h && n > available - 2 * h {
                let other = available - h;
                let packets = (n + h).div_ceil(other);
                let first_data = (n + h).div_ceil(packets).saturating_sub(h);
                let head = 55 + rng.random_range(0..32);
                if first_data > head && n > first_data {
                    let tail = first_data - head;
                    let whole = pending.pop_front().expect("front exists");
                    frames.push(Crypto {
                        offset: 0,
                        data: whole.data.slice(..head),
                    });
                    frames.push(Crypto {
                        offset: (n - tail) as u64,
                        data: whole.data.slice(n - tail..),
                    });
                    pending.push_front(Crypto {
                        offset: head as u64,
                        data: whole.data.slice(head..n - tail),
                    });
                }
            }
        }
    }
    if frames.is_empty() {
        let mut room = available;
        while let Some(mut f) = pending.pop_front() {
            let h = header(f.offset, room.min(16383));
            if room <= h {
                pending.push_front(f);
                break;
            }
            let n = f.data.len().min(16383).min(room - h);
            let part = Crypto {
                offset: f.offset,
                data: f.data.split_to(n),
            };
            room -= size(&part);
            frames.push(part);
            if !f.data.is_empty() {
                f.offset += n as u64;
                pending.push_front(f);
                break;
            }
        }
    }
    if frames.is_empty() {
        return (frames, 0);
    }
    let mut budget = available - frames.iter().map(size).sum::<usize>();
    let lo = frames.iter().map(|f| f.offset).min().unwrap();
    let hi = frames
        .iter()
        .map(|f| f.offset + f.data.len() as u64)
        .max()
        .unwrap();
    let max_overhead = header(hi, (hi - lo) as usize);
    for _ in 0..rng.random_range(2..=10) {
        if budget < max_overhead {
            break;
        }
        let index = rng.random_range(0..frames.len());
        if frames[index].data.len() <= 1 {
            continue;
        }
        let cut = rng.random_range(1..frames[index].data.len());
        let old = size(&frames[index]);
        let tail = Crypto {
            offset: frames[index].offset + cut as u64,
            data: frames[index].data.slice(cut..),
        };
        frames[index].data.truncate(cut);
        budget = budget + old - size(&frames[index]) - size(&tail);
        frames.push(tail);
    }
    enum Item {
        Crypto(usize),
        Ping,
        Padding(usize),
    }
    let pings = rng.random_range(2..=10).min(budget);
    budget -= pings;
    let mut items: Vec<Item> = (0..frames.len()).map(Item::Crypto).collect();
    items.extend((0..pings).map(|_| Item::Ping));
    let positions = items.len();
    for _ in 0..positions {
        if budget == 0 {
            break;
        }
        let n = rng.random_range(0..=budget);
        if n > 0 {
            items.push(Item::Padding(n));
            budget -= n;
        }
    }
    if budget > 0 {
        items.push(Item::Padding(budget));
    }
    items.shuffle(rng);
    for item in items {
        match item {
            Item::Crypto(i) => frames[i].encode(out),
            Item::Ping => out.write(frame::FrameType::PING),
            Item::Padding(n) => out.resize(out.len() + n, 0),
        }
    }
    debug_assert_eq!(out.len(), limit);
    (frames, pings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    #[test]
    fn fragmented_crypto_reassembles_and_fills_packets() {
        for seed in 0..64 {
            let original: Vec<u8> = (0..1800).map(|i| (i % 251) as u8).collect();
            let mut pending = VecDeque::from([Crypto {
                offset: 0,
                data: original.clone().into(),
            }]);
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let mut recovered = vec![None; original.len()];
            let mut packets = 0;
            while !pending.is_empty() {
                let mut out = Vec::new();
                let (frames, pings) = write(&mut pending, &mut out, 1216, &mut rng);
                assert_eq!(out.len(), 1216);
                assert!((2..=10).contains(&pings));
                if packets == 0 {
                    assert!(frames.iter().any(|f| f.offset == 0));
                    assert!(
                        frames
                            .iter()
                            .any(|f| f.offset + f.data.len() as u64 == 1800)
                    );
                }
                for f in frames {
                    for (i, b) in f.data.iter().enumerate() {
                        let slot = &mut recovered[f.offset as usize + i];
                        assert!(slot.is_none());
                        *slot = Some(*b);
                    }
                }
                packets += 1;
                assert!(packets <= 3);
            }
            assert_eq!(
                recovered.into_iter().collect::<Option<Vec<_>>>().unwrap(),
                original
            );
            assert_eq!(packets, 2);
        }
    }
}
