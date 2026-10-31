//! VLESS `flow: xtls-rprx-vision` (Xray's Vision).
//!
//! Vision frames the payload instead of encrypting it: the client writes the
//! user UUID once, then wraps every write as
//! `[command, content_len:u16, padding_len:u16, content, padding]`, and strips
//! the same framing on the way back. Padding keeps the small writes of a TLS
//! handshake looking like record traffic, which is the point of the flow.
//!
//! The framing is *transient*, and getting that wrong breaks the flow in both
//! directions. `CommandPaddingEnd` does not mean "this frame is the last one",
//! it means "the framing stops here, treat the rest of the stream as raw"; the
//! sender only sends it once, on the way out of the padding phase, and writes
//! nothing but payload after that. So the writer here sends
//! `CommandPaddingContinue` on every frame of the phase and exactly one
//! `CommandPaddingEnd` on the transition, and the phase ends either at the
//! first TLS 1.3 application-data record or, for traffic that never looked
//! like TLS, after `PACKETS_TO_FILTER` writes. `XtlsUnpadding` in the
//! reference is the other half: `Continue` keeps parsing frames, anything else
//! hands the rest through untouched.
//!
//! Ported from `sing-vmess/vless/vision.go`.
//!
//! Receivers and writers can enter Direct independently. The client checks the
//! inner ServerHello for TLS 1.3 and a supported cipher before initiating Direct.
//! Otherwise it retains the compatible PaddingEnd path. Raw writes start only after the final
//! padded frame has been completely accepted by the TLS writer.

use std::io;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::inbound::AnyStream;

/// The three commands of the reference (`proxy.go`).
const PADDING_CONTINUE: u8 = 0x00;
const PADDING_END: u8 = 0x01;
const PADDING_DIRECT: u8 = 0x02;

/// Keep small writes padded to roughly a TLS record, as the reference does.
const TLS_PADDING_FLOOR: usize = 900;
const TLS_PADDING_SPREAD: usize = 500;
const PLAIN_PADDING_SPREAD: usize = 256;

/// The reference's `numberOfPacketToFilter`: how many writes of traffic that
/// never looked like TLS stay in the padding phase before the compatibility
/// escape hatch ends it.
const PACKETS_TO_FILTER: usize = 8;

/// Content is a `u16` on the wire, so a bigger write is more than one frame.
const MAX_CONTENT: usize = u16::MAX as usize;

/// The size the reference bounds a padded frame to: its `buf.Size`, the size
/// of the buffer every frame is built in. `ReshapeMultiBuffer` splits a write
/// that would not fit and `XtlsPadding` trims the padding to the rest of the
/// buffer, so no frame of the reference's ever passes this, and with it no
/// record of its TLS writer either. A larger frame is a length no Xray client
/// sends.
const MAX_FRAME: usize = 8192;

/// What a frame costs besides its content: the user UUID of the first frame
/// and the five bytes of command and lengths. The reference reserves this on
/// every frame, UUID or not.
const FRAME_OVERHEAD: usize = 16 + 5;

/// Where the reference splits a write with no record boundary to split at:
/// `buf.Size / 2`.
const BLIND_SPLIT: usize = MAX_FRAME / 2;

/// How much is asked of the inner stream per read. It lands straight in the
/// framing buffer, so there is nothing to copy it out of.
const READ_CHUNK: usize = 32 * 1024;

/// TLS 1.3 application data, `TlsApplicationDataStart` in the reference. Its
/// arrival is what takes the padding phase out.
const TLS_APP_DATA: [u8; 3] = [0x17, 0x03, 0x03];

/// Inner TLS record boundaries survive both TCP reads and Vision frame splits.
/// Retain only a header and a byte count, never the application's record body.
#[derive(Clone, Default)]
struct WriteRecords {
    header: [u8; 5],
    header_len: usize,
    remaining: usize,
    disabled: bool,
    saw_handshake: bool,
}

impl WriteRecords {
    /// Stop at the first complete application record so the final padded frame
    /// cannot carry the start of the next record past the Direct boundary.
    fn feed(&mut self, input: &[u8]) -> (usize, bool) {
        if self.disabled {
            return (input.len(), false);
        }
        let mut at = 0;
        while at < input.len() {
            if self.header_len < 5 {
                let n = (5 - self.header_len).min(input.len() - at);
                self.header[self.header_len..self.header_len + n]
                    .copy_from_slice(&input[at..at + n]);
                self.header_len += n;
                at += n;
                if self.header_len < 5 {
                    break;
                }
                self.remaining = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                if !matches!(self.header[0], 0x14..=0x17)
                    || self.header[1] != 3
                    || self.header[2] > 3
                    || self.remaining == 0
                    || self.remaining > 18432
                {
                    self.disabled = true;
                    return (input.len(), false);
                }
                self.saw_handshake |= self.header[0] == 0x16;
            }
            let n = self.remaining.min(input.len() - at);
            self.remaining -= n;
            at += n;
            if self.remaining == 0 {
                self.header_len = 0;
                if self.header[..3] == TLS_APP_DATA {
                    return (at, true);
                }
            }
        }
        (at, false)
    }
}

/// Inspect only the first inner ServerHello. Both TCP and TLS handshake
/// fragmentation are allowed; malformed or oversized input disables detection.
#[derive(Default)]
struct ServerHello {
    record: Vec<u8>,
    handshake: Vec<u8>,
    done: bool,
    eligible: bool,
}

impl ServerHello {
    fn stop(&mut self, eligible: bool) {
        self.done = true;
        self.eligible = eligible;
        self.record = Vec::new();
        self.handshake = Vec::new();
    }

    fn feed(&mut self, mut input: &[u8]) {
        while !self.done && !input.is_empty() {
            let target = if self.record.len() < 5 {
                5
            } else {
                5 + usize::from(u16::from_be_bytes([self.record[3], self.record[4]]))
            };
            let take = (target - self.record.len()).min(input.len());
            self.record.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.record.len() < 5 {
                continue;
            }
            let size = usize::from(u16::from_be_bytes([self.record[3], self.record[4]]));
            if self.record[..3] != [0x16, 0x03, 0x03] || size == 0 || size > 16384 {
                self.stop(false);
                return;
            }
            if self.record.len() < size + 5 {
                continue;
            }
            if self.handshake.len() + size > 65536 {
                self.stop(false);
                return;
            }
            self.handshake.extend_from_slice(&self.record[5..]);
            self.record.clear();
            if self.handshake.len() < 4 {
                continue;
            }
            let size = (usize::from(self.handshake[1]) << 16)
                | (usize::from(self.handshake[2]) << 8)
                | usize::from(self.handshake[3]);
            if self.handshake[0] != 2 || size > 65532 {
                self.stop(false);
                return;
            }
            if self.handshake.len() >= size + 4 {
                let eligible = Self::parse(&self.handshake[4..size + 4]);
                self.stop(eligible);
            }
        }
    }

    fn parse(body: &[u8]) -> bool {
        if body.len() < 38 || body[..2] != [3, 3] {
            return false;
        }
        // HelloRetryRequest is not the negotiated ServerHello. Conservatively
        // keep outer encryption for this uncommon path.
        const RETRY: [u8; 32] = [
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ];
        if body[2..34] == RETRY || body[34] > 32 {
            return false;
        }
        let at = 35 + usize::from(body[34]);
        if body.len() < at + 5 || body[at + 2] != 0 {
            return false;
        }
        let cipher = u16::from_be_bytes([body[at], body[at + 1]]);
        // Match Xray's supported set, excluding CCM_8 (0x1305).
        if !matches!(cipher, 0x1301..=0x1304) {
            return false;
        }
        let extensions = usize::from(u16::from_be_bytes([body[at + 3], body[at + 4]]));
        let mut rest = &body[at + 5..];
        if rest.len() != extensions {
            return false;
        }
        let mut tls13 = false;
        while !rest.is_empty() {
            if rest.len() < 4 {
                return false;
            }
            let kind = u16::from_be_bytes([rest[0], rest[1]]);
            let size = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
            rest = &rest[4..];
            if rest.len() < size {
                return false;
            }
            if kind == 43 {
                if tls13 || rest[..size] != [3, 4] {
                    return false;
                }
                tls13 = true;
            }
            rest = &rest[size..];
        }
        tls13
    }
}

pub struct VisionStream {
    inner: AnyStream,
    uuid: [u8; 16],
    /// the UUID goes out in front of the first padded block
    write_uuid: bool,
    /// the reference's `isPadding`: framing covers the first packets only, and
    /// every write after the transition is the payload itself
    padding: bool,
    /// once a TLS handshake has passed through, padding grows to record size
    saw_tls: bool,
    /// the reference's `numberOfPacketToFilter`
    packets_to_filter: usize,
    /// a frame handed to the inner stream that it has not taken whole yet
    framed: Vec<u8>,
    /// how much of `framed` is already on the wire
    framed_at: usize,
    /// bytes of the caller's buffer the frame in flight stands for
    pending: usize,
    // inbound framing state, straight from the reference field names
    remaining_content: i64,
    remaining_padding: i64,
    current_command: u8,
    /// bytes read from `inner` but not framed yet
    raw: BytesMut,
    /// framed payload waiting for the caller
    payload: BytesMut,
    eof: bool,
    direct_read: bool,
    direct_write_pending: bool,
    server_hello: ServerHello,
    write_records: WriteRecords,
}

impl VisionStream {
    pub fn new(inner: AnyStream, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            write_uuid: true,
            padding: true,
            saw_tls: false,
            packets_to_filter: PACKETS_TO_FILTER,
            framed: Vec::new(),
            framed_at: 0,
            pending: 0,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            raw: BytesMut::new(),
            payload: BytesMut::new(),
            eof: false,
            direct_read: false,
            direct_write_pending: false,
            server_hello: ServerHello::default(),
            write_records: WriteRecords::default(),
        }
    }

    /// Whether this stream sits on a transport that can go Direct.
    #[cfg(target_os = "linux")]
    pub(crate) fn supports_direct(&mut self) -> bool {
        crate::inbound::supports_vision_direct(&mut self.inner)
    }

    /// The stream underneath, once reads are Direct and nothing read off it
    /// still waits here: every later byte comes straight from it.
    #[cfg(target_os = "linux")]
    pub(crate) fn direct_read_inner(&self) -> Option<&AnyStream> {
        let drained = self.raw.is_empty()
            && self.payload.is_empty()
            && self.current_command == PADDING_DIRECT
            && self.remaining_content == 0
            && self.remaining_padding == 0;
        (self.direct_read && drained).then_some(&self.inner)
    }

    fn random_below(limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        let mut byte = [0u8; 8];
        getrandom::fill(&mut byte).unwrap_or_default();
        (u64::from_le_bytes(byte) % limit as u64) as usize
    }

    /// How much of a write the next frame carries, `ReshapeMultiBuffer` in the
    /// reference: content enough to leave the frame inside [`MAX_FRAME`], cut
    /// at the last record boundary that fits so a frame ends where a record
    /// does, and at [`BLIND_SPLIT`] when there is no boundary to cut at.
    fn frame_take(buf: &[u8]) -> usize {
        const MAX_FRAME_CONTENT: usize = MAX_FRAME - FRAME_OVERHEAD;
        const { assert!(MAX_FRAME_CONTENT <= MAX_CONTENT) };
        if buf.len() <= MAX_FRAME_CONTENT {
            return buf.len();
        }
        let window = &buf[..MAX_FRAME_CONTENT];
        match window
            .windows(TLS_APP_DATA.len())
            .rposition(|bytes| bytes == TLS_APP_DATA)
            .filter(|index| *index >= FRAME_OVERHEAD)
        {
            Some(index) => index,
            None => BLIND_SPLIT,
        }
    }

    /// `VisionConn.padding`, built into `self.framed` so the phase costs no
    /// allocation per write.
    fn build_frame(&mut self, content: &[u8], command: u8) {
        let padding_len = if content.len() < TLS_PADDING_FLOOR && self.saw_tls {
            Self::random_below(TLS_PADDING_SPREAD) + TLS_PADDING_FLOOR - content.len()
        } else {
            Self::random_below(PLAIN_PADDING_SPREAD)
        };
        // `XtlsPadding` trims the padding to what is left of the frame buffer
        let padding_len = padding_len.min(MAX_FRAME.saturating_sub(FRAME_OVERHEAD + content.len()));
        let uuid = self.write_uuid;
        self.framed.clear();
        self.framed
            .reserve(usize::from(uuid) * 16 + 5 + content.len() + padding_len);
        if uuid {
            self.framed.extend_from_slice(&self.uuid);
            self.write_uuid = false;
        }
        self.framed.push(command);
        self.framed
            .extend_from_slice(&(content.len() as u16).to_be_bytes());
        self.framed
            .extend_from_slice(&(padding_len as u16).to_be_bytes());
        self.framed.extend_from_slice(content);
        self.framed.resize(self.framed.len() + padding_len, 0);
    }

    /// The reference filters the first packets to tell TLS 1.3 from TLS 1.2;
    /// we only need the coarse "is TLS involved" answer for the padding profile.
    fn looks_like_tls(buffer: &[u8]) -> bool {
        buffer.len() > 5 && (buffer[0] == 0x16 || (buffer[0] == 0x01 && buffer[5] == 0x01))
    }

    /// One complete TLS record, `IsCompleteRecord` in the reference: a partial
    /// record must not be what takes the padding phase out.
    #[cfg(test)]
    fn is_tls_app_data(buffer: &[u8]) -> bool {
        if buffer.len() < 5 || buffer[..3] != TLS_APP_DATA {
            return false;
        }
        let body = usize::from(u16::from_be_bytes([buffer[3], buffer[4]]));
        buffer.len() >= 5 + body
    }

    /// `VisionConn.Write`'s choice of command for the frame it is about to
    /// build, and the decision to leave the padding phase for good.
    fn next_command(&mut self, content: &[u8]) -> u8 {
        let (_, application_end) = self.write_records.feed(content);
        self.saw_tls |= self.write_records.saw_handshake;
        let command = if self.saw_tls && application_end {
            // The negotiated inner TLS version/cipher qualifies uploads even
            // when the peer has not sent its own Direct command yet.
            if self.direct_read
                || (self.server_hello.eligible
                    && crate::inbound::supports_vision_direct(&mut self.inner))
            {
                self.direct_write_pending = true;
                PADDING_DIRECT
            } else {
                PADDING_END
            }
        } else if !self.saw_tls && self.packets_to_filter <= 1 {
            // traffic that never turned out to be TLS leaves the phase early, for
            // compatibility with receivers that gave up waiting
            PADDING_END
        } else {
            PADDING_CONTINUE
        };
        if command != PADDING_CONTINUE {
            self.padding = false;
            self.server_hello.stop(false);
        }
        command
    }

    /// `VisionConn.filterTLS`, run once per write on the way out.
    fn filter(&mut self, buffer: &[u8]) {
        if !self.saw_tls {
            self.saw_tls = Self::looks_like_tls(buffer);
        }
        if self.packets_to_filter > 0 {
            self.packets_to_filter -= 1;
        }
    }

    /// `VisionConn.unPadding` over `raw`, moving payload into `self.payload`.
    fn unpad(&mut self) {
        let mut index = 0usize;
        if self.remaining_content == -1
            && self.remaining_padding == -1
            && self.raw.len() >= 21
            && self.raw[..16] == self.uuid
        {
            index = 16;
            self.remaining_content = 0;
            self.remaining_padding = 0;
            self.current_command = 0;
        }
        if self.remaining_content == -1 && self.remaining_padding == -1 {
            // a peer that does not frame at all: the reference decides that from
            // the first bytes, so a short read must wait rather than guess
            if index == 0 && self.raw.len() < 21 && !self.eof {
                return;
            }
            self.payload.extend_from_slice(&self.raw[index..]);
            self.raw.clear();
            return;
        }
        while index < self.raw.len() {
            if self.remaining_content <= 0 && self.remaining_padding <= 0 {
                // any command but Continue ends the framing, and whatever
                // follows it is payload
                if self.current_command != PADDING_CONTINUE {
                    self.payload.extend_from_slice(&self.raw[index..]);
                    index = self.raw.len();
                    break;
                }
                if self.raw.len() < index + 5 {
                    break;
                }
                let header = &self.raw[index..index + 5];
                self.current_command = header[0];
                self.remaining_content = i64::from(u16::from_be_bytes([header[1], header[2]]));
                self.remaining_padding = i64::from(u16::from_be_bytes([header[3], header[4]]));
                index += 5;
            } else if self.remaining_content > 0 {
                let end = (self.remaining_content as usize).min(self.raw.len() - index);
                self.payload
                    .extend_from_slice(&self.raw[index..index + end]);
                self.remaining_content -= end as i64;
                index += end;
            } else {
                let end = (self.remaining_padding as usize).min(self.raw.len() - index);
                self.remaining_padding -= end as i64;
                index += end;
            }
        }
        // split_to moves the consumption point instead of memmoving the
        // remainder to the front of the buffer on every unpad
        if index > 0 {
            let _ = self.raw.split_to(index);
        }
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            this.unpad();
            if !this.direct_read
                && this.current_command == PADDING_DIRECT
                && this.remaining_content == 0
                && this.remaining_padding == 0
            {
                if !crate::inbound::enable_vision_direct_read(&mut this.inner) {
                    return std::task::Poll::Ready(Err(io::Error::other(
                        "Vision Direct requires a raw-capable TLS stream",
                    )));
                }
                this.direct_read = true;
            }
            if !this.payload.is_empty() {
                let take = this.payload.len().min(out.remaining());
                this.server_hello.feed(&this.payload[..take]);
                out.put_slice(&this.payload[..take]);
                let _ = this.payload.split_to(take);
                if this.payload.is_empty()
                    && this.raw.is_empty()
                    && this.current_command != PADDING_CONTINUE
                    && this.remaining_content == 0
                    && this.remaining_padding == 0
                {
                    this.raw = BytesMut::new();
                    this.payload = BytesMut::new();
                }
                return std::task::Poll::Ready(Ok(()));
            }
            if this.current_command != PADDING_CONTINUE
                && this.remaining_content == 0
                && this.remaining_padding == 0
                && this.raw.is_empty()
            {
                // Framing ended and its last payload was delivered. Subsequent
                // bytes belong to the inner stream; retain neither staging buffer.
                this.raw = BytesMut::new();
                this.payload = BytesMut::new();
                let start = out.filled().len();
                let result = std::pin::Pin::new(&mut this.inner).poll_read(cx, out);
                if matches!(result, std::task::Poll::Ready(Ok(()))) {
                    this.server_hello.feed(&out.filled()[start..]);
                }
                return result;
            }
            if this.eof {
                return std::task::Poll::Ready(Ok(()));
            }
            if this.raw.capacity() - this.raw.len() < READ_CHUNK {
                this.raw.reserve(READ_CHUNK);
            }
            // read straight into the framing buffer: a staging array and a copy
            // out of it per read is what the server TLS path stopped doing
            let base = this.raw.len();
            let got = {
                let spare = this.raw.spare_capacity_mut();
                let mut buf = ReadBuf::uninit(&mut spare[..READ_CHUNK]);
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                    std::task::Poll::Ready(Ok(())) => buf.filled().len(),
                    std::task::Poll::Ready(Err(error)) => {
                        return std::task::Poll::Ready(Err(error));
                    }
                    std::task::Poll::Pending => {
                        // a partial frame stays in `raw` for the next poll
                        return std::task::Poll::Pending;
                    }
                }
            };
            if got == 0 {
                this.eof = true;
                // a closed peer may still leave a tail in the framing
                this.unpad();
            } else {
                // SAFETY: `got` bytes past `base` were just initialised by the
                // read above, inside the buffer `spare` pointed into
                unsafe { this.raw.set_len(base + got) };
            }
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            // a frame the inner stream has only taken part of: the rest of it
            // still has to go out before anything else may be framed
            if this.framed_at < this.framed.len() {
                match std::pin::Pin::new(&mut this.inner)
                    .poll_write(cx, &this.framed[this.framed_at..])
                {
                    std::task::Poll::Ready(Ok(0)) => {
                        return std::task::Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    std::task::Poll::Ready(Ok(n)) => {
                        this.framed_at += n;
                        if this.framed_at == this.framed.len() {
                            if this.direct_write_pending {
                                if !crate::inbound::enable_vision_direct_write(&mut this.inner) {
                                    return std::task::Poll::Ready(Err(io::Error::other(
                                        "Vision Direct write requires a drained raw-capable TLS stream",
                                    )));
                                }
                                this.direct_write_pending = false;
                            }
                            this.framed.clear();
                            if !this.padding {
                                this.framed = Vec::new();
                            }
                            this.framed_at = 0;
                            let done = this.pending;
                            this.pending = 0;
                            return std::task::Poll::Ready(Ok(done));
                        }
                        // the frame is still going out: reporting the payload
                        // written now would drop the tail of the frame
                        continue;
                    }
                    std::task::Poll::Ready(Err(error)) => {
                        return std::task::Poll::Ready(Err(error));
                    }
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
            if this.pending > 0 {
                let done = this.pending;
                this.pending = 0;
                return std::task::Poll::Ready(Ok(done));
            }
            if buf.is_empty() {
                return std::task::Poll::Ready(Ok(0));
            }
            if !this.padding {
                // the phase is over: the payload goes out as it is, with no
                // header, no padding and no copy
                return std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            let take = Self::frame_take(buf);
            // Preview the tiny parser state to limit the frame at a real inner
            // record boundary, then commit it exactly once in next_command.
            let (take, _) = this.write_records.clone().feed(&buf[..take]);
            this.filter(&buf[..take]);
            let command = this.next_command(&buf[..take]);
            this.build_frame(&buf[..take], command);
            this.pending = take;
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn hello(cipher: u16, version: [u8; 2]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0x42; 32]);
        body.push(0);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.extend_from_slice(&[0, 0, 6, 0, 43, 0, 2]);
        body.extend_from_slice(&version);
        let mut handshake = vec![2, 0, 0, body.len() as u8];
        handshake.extend_from_slice(&body);
        handshake
    }

    fn handshake_record(body: &[u8]) -> Vec<u8> {
        let mut record = vec![0x16, 3, 3];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(body);
        record
    }

    #[test]
    fn server_hello_qualification_and_fragmentation() {
        for cipher in 0x1301..=0x1304 {
            let handshake = hello(cipher, [3, 4]);
            for split in 1..handshake.len() {
                let mut wire = handshake_record(&handshake[..split]);
                wire.extend(handshake_record(&handshake[split..]));
                let mut detector = ServerHello::default();
                for byte in wire {
                    detector.feed(&[byte]);
                }
                assert!(detector.eligible);
                assert!(detector.done);
                assert_eq!(detector.record.capacity(), 0);
                assert_eq!(detector.handshake.capacity(), 0);
            }
        }
    }

    #[test]
    fn unsupported_and_malformed_hellos_keep_outer_tls() {
        for (cipher, version) in [(0x1305, [3, 4]), (0xffff, [3, 4]), (0x1301, [3, 3])] {
            let mut detector = ServerHello::default();
            detector.feed(&handshake_record(&hello(cipher, version)));
            assert!(detector.done && !detector.eligible);
        }
        let mut bad = hello(0x1301, [3, 4]);
        bad[4 + 34] = 255;
        assert!(!ServerHello::parse(&bad[4..]));
        let good = hello(0x1301, [3, 4]);
        for length in 0..good.len() - 4 {
            assert!(!ServerHello::parse(&good[4..4 + length]));
        }
        for wire in [vec![0x16, 3, 3, 0xff, 0xff], vec![0x17, 3, 3, 0, 1, 0]] {
            let mut detector = ServerHello::default();
            detector.feed(&wire);
            assert!(detector.done && !detector.eligible);
        }
    }

    #[tokio::test]
    async fn inner_server_hello_is_detected_before_peer_direct() {
        let (mut client, mut peer) = pair();
        let wire = wire_frame(
            true,
            PADDING_CONTINUE,
            &handshake_record(&hello(0x1301, [3, 4])),
            0,
        );
        peer.write_all(&wire).await.unwrap();
        let mut received = vec![0; handshake_record(&hello(0x1301, [3, 4])).len()];
        client.read_exact(&mut received).await.unwrap();
        assert!(client.server_hello.eligible);
        assert!(!client.direct_read);
        // A duplex/unsupported outer transport must never advertise raw mode.
        client.saw_tls = true;
        assert_eq!(client.next_command(&[0x17, 3, 3, 0, 1, 0]), PADDING_END);
    }

    fn uuid() -> [u8; 16] {
        [7u8; 16]
    }

    fn pair() -> (VisionStream, tokio::io::DuplexStream) {
        let (client, server) = tokio::io::duplex(8192);
        let boxed: AnyStream = Box::new(client);
        (VisionStream::new(boxed, uuid()), server)
    }

    /// A frame built by hand, the way the reference puts it on the wire.
    fn wire_frame(with_uuid: bool, command: u8, content: &[u8], padding: usize) -> BytesMut {
        let mut out = Vec::new();
        if with_uuid {
            out.extend_from_slice(&uuid());
        }
        out.push(command);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(padding as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding, 0);
        BytesMut::from(out.as_slice())
    }

    /// A frame as it goes on the wire, always with the uuid prefix so the header
    /// sits at the same offset in every frame the tests look at.
    fn frame_of(stream: &mut VisionStream, content: &[u8]) -> Vec<u8> {
        stream.write_uuid = true;
        stream.build_frame(content, PADDING_CONTINUE);
        stream.framed.clone()
    }

    fn padding_of(frame: &[u8]) -> usize {
        usize::from(u16::from_be_bytes([frame[19], frame[20]]))
    }

    #[test]
    fn first_frame_carries_the_uuid_then_the_header() {
        let (mut vision, _) = pair();
        let frame = frame_of(&mut vision, b"hello");
        assert_eq!(&frame[..16], &uuid()[..], "the uuid is written once");
        assert_eq!(frame[16], PADDING_CONTINUE, "command");
        assert_eq!(u16::from_be_bytes([frame[17], frame[18]]), 5);
        let padding = u16::from_be_bytes([frame[19], frame[20]]) as usize;
        assert_eq!(&frame[21..26], b"hello");
        assert_eq!(frame.len(), 21 + 5 + padding);
        assert!(
            frame[26..].iter().all(|byte| *byte == 0),
            "padding is zeroed"
        );
    }

    /// `frame()` used to take `&self`, so the uuid went out with every frame
    /// while the reader strips it only from the first one.
    #[test]
    fn the_uuid_goes_out_with_the_first_frame_only() {
        let (mut vision, _) = pair();
        vision.build_frame(b"one", PADDING_CONTINUE);
        let first = vision.framed.clone();
        vision.build_frame(b"two", PADDING_CONTINUE);
        let second = vision.framed.clone();
        assert_eq!(&first[..16], &uuid()[..], "the uuid opens the stream");
        assert_eq!(
            second[0], PADDING_CONTINUE,
            "the second frame starts at the header"
        );
        assert_eq!(u16::from_be_bytes([second[1], second[2]]), 3);
    }

    #[test]
    fn padding_grows_to_a_tls_record_only_after_tls() {
        let (mut vision, _) = pair();
        let small = frame_of(&mut vision, b"x");
        let padding = padding_of(&small);
        assert!(
            padding < PLAIN_PADDING_SPREAD,
            "before a handshake is seen the padding stays plain"
        );
        vision.saw_tls = true;
        let padded = frame_of(&mut vision, &[0u8; 100]);
        let padding = padding_of(&padded);
        assert!(
            (TLS_PADDING_FLOOR - 100..TLS_PADDING_FLOOR + TLS_PADDING_SPREAD).contains(&padding),
            "with TLS the padding fills the record, got {padding}"
        );
    }

    /// The bug that made vision unusable in both directions: End on every frame
    /// tells the peer to stop parsing, so the second frame's header and padding
    /// reach the application.
    #[test]
    fn the_padding_phase_is_transient_and_then_writes_are_raw() {
        let (mut source, _) = pair();
        let mut wire = BytesMut::new();
        let mut commands = Vec::new();
        let mut writes = 0usize;
        while source.padding && writes < PACKETS_TO_FILTER + 2 {
            // spaces, so `looks_like_tls` does not mistake the payload for a
            // handshake and hold the phase open
            let payload = vec![b' '; 32];
            source.filter(&payload);
            let command = source.next_command(&payload);
            commands.push(command);
            source.build_frame(&payload, command);
            wire.extend_from_slice(&source.framed);
            writes += 1;
        }
        assert!(
            writes <= PACKETS_TO_FILTER,
            "the phase ends inside the filter window, took {writes} writes"
        );
        assert_eq!(
            commands.iter().filter(|c| **c == PADDING_END).count(),
            1,
            "End goes out exactly once, got {commands:?}"
        );
        assert_eq!(
            *commands.last().expect("at least one write"),
            PADDING_END,
            "and it is the last frame of the phase"
        );
        assert!(!source.padding, "the phase stays ended");

        // the peer sees every payload byte and no framing past the phase
        let (mut sink, _) = pair();
        sink.raw = wire;
        sink.unpad();
        assert_eq!(sink.payload.len(), writes * 32);
        assert!(sink.raw.is_empty(), "the framing is fully consumed");
    }

    /// A reader must treat anything but Continue as "framing over", which is
    /// what the reference does with End and with Direct.
    #[test]
    fn any_command_but_continue_hands_the_rest_through() {
        for command in [PADDING_END, 0x02] {
            let mut wire = wire_frame(true, PADDING_CONTINUE, b"framed", 4);
            wire.extend_from_slice(&wire_frame(false, command, b"last", 2));
            wire.extend_from_slice(b"raw tail");
            let (mut sink, _) = pair();
            sink.raw = wire;
            sink.unpad();
            assert_eq!(
                &sink.payload[..],
                &b"framedlastraw tail"[..],
                "command {command} must end the framing"
            );
            assert!(sink.raw.is_empty());
        }
    }

    /// The transition the reference keys on: the first complete TLS 1.3
    /// application-data record.
    #[test]
    fn tls_application_data_ends_the_phase_and_a_partial_record_does_not() {
        let (mut vision, _) = pair();
        vision.saw_tls = true;
        let mut record = TLS_APP_DATA.to_vec();
        record.extend_from_slice(&40u16.to_be_bytes());
        record.extend_from_slice(&[0u8; 40]);
        assert!(VisionStream::is_tls_app_data(&record));
        assert_eq!(vision.next_command(&record), PADDING_END);
        assert!(
            !VisionStream::is_tls_app_data(&record[..20]),
            "half a record is not a reason to stop padding"
        );
    }

    /// No frame passes the reference's frame buffer, padding included, so no
    /// record of the TLS writer under it carries a length no Xray client
    /// sends. `XtlsPadding` trims the padding for that.
    #[test]
    fn a_frame_stays_inside_the_reference_buffer() {
        let (mut vision, _) = pair();
        // long padding applies under the floor, so the clamp is what bounds
        // the frames above it
        vision.saw_tls = true;
        for len in [0, 1, 899, 900, 4096, MAX_FRAME - FRAME_OVERHEAD] {
            let content = vec![0x5Au8; len];
            let frame = frame_of(&mut vision, &content);
            assert!(
                frame.len() <= MAX_FRAME,
                "{len} bytes of content made a {}-byte frame",
                frame.len()
            );
            assert_eq!(
                frame.len(),
                FRAME_OVERHEAD + len + padding_of(&frame),
                "the header still describes the frame"
            );
        }
        // the largest content leaves no room for padding at all
        let full = vec![0x5Au8; MAX_FRAME - FRAME_OVERHEAD];
        let frame = frame_of(&mut vision, &full);
        assert_eq!(padding_of(&frame), 0);
        assert_eq!(frame.len(), MAX_FRAME);
    }

    /// `ReshapeMultiBuffer`: a write that would not fit one frame is cut at
    /// the last record boundary inside the frame, and halfway through the
    /// buffer when there is no boundary to cut at.
    #[test]
    fn an_oversized_write_is_cut_like_the_reference() {
        let small = vec![0u8; 100];
        assert_eq!(VisionStream::frame_take(&small), 100);
        let exact = vec![0u8; MAX_FRAME - FRAME_OVERHEAD];
        assert_eq!(VisionStream::frame_take(&exact), exact.len());

        // nothing that looks like a record start: the blind split
        let blind = vec![0xABu8; MAX_FRAME * 3];
        assert_eq!(VisionStream::frame_take(&blind), BLIND_SPLIT);

        // two record starts inside the frame: the last one is the cut
        let mut records = vec![0xABu8; MAX_FRAME * 3];
        records[1000..1003].copy_from_slice(&TLS_APP_DATA);
        records[7000..7003].copy_from_slice(&TLS_APP_DATA);
        assert_eq!(VisionStream::frame_take(&records), 7000);

        // a record start past the frame does not count, nor one at the very
        // front: the reference refuses an index under its header length
        let mut late = vec![0xABu8; MAX_FRAME * 3];
        late[MAX_FRAME..MAX_FRAME + 3].copy_from_slice(&TLS_APP_DATA);
        late[3..6].copy_from_slice(&TLS_APP_DATA);
        assert_eq!(VisionStream::frame_take(&late), BLIND_SPLIT);
    }

    /// A frame larger than a `u16` is two frames, and no byte of the second is
    /// dropped on the floor.
    #[tokio::test]
    async fn content_larger_than_a_u16_is_framed_in_pieces() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut source = VisionStream::new(Box::new(a), uuid());
        let mut sink = VisionStream::new(Box::new(b), uuid());
        let payload = vec![0xABu8; MAX_CONTENT + 100];
        let want = payload.len();
        let writer = tokio::spawn(async move {
            let mut sent = 0usize;
            while sent < payload.len() {
                sent += source.write(&payload[sent..]).await.expect("write");
            }
        });
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            sink.read_to_end(&mut got),
        )
        .await
        .expect("no hang")
        .expect("read back");
        writer.await.expect("writer");
        assert_eq!(got.len(), want, "no byte of an oversized write is lost");
        assert!(got.iter().all(|byte| *byte == 0xAB), "and none is mangled");
    }

    /// A frame the socket takes in pieces must still go out whole: reporting
    /// success while the tail of the frame is unwritten loses it.
    #[tokio::test]
    async fn a_partially_written_frame_is_finished() {
        let (client, server) = tokio::io::duplex(64);
        let boxed: AnyStream = Box::new(client);
        let mut vision = VisionStream::new(boxed, uuid());
        let mut server = server;
        let want = 40usize;
        let writer = tokio::spawn(async move {
            let payload = vec![0x5Au8; want];
            let mut sent = 0usize;
            while sent < payload.len() {
                sent += vision.write(&payload[sent..]).await.expect("write");
            }
        });
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.read_to_end(&mut got),
        )
        .await
        .expect("no hang")
        .expect("read back");
        writer.await.expect("writer");

        assert_eq!(&got[..16], &uuid()[..], "the uuid opens the stream");
        assert_eq!(got[16], PADDING_CONTINUE, "command");
        assert_eq!(
            usize::from(u16::from_be_bytes([got[17], got[18]])),
            want,
            "content length"
        );
        let padding = usize::from(u16::from_be_bytes([got[19], got[20]]));
        assert_eq!(
            got.len(),
            21 + want + padding,
            "the frame went out whole, padding and all"
        );
        assert!(got[21..21 + want].iter().all(|byte| *byte == 0x5A));
    }

    #[test]
    fn unpadding_strips_headers_and_padding() {
        let mut bytes = wire_frame(true, PADDING_CONTINUE, b"first", 3);
        bytes.extend_from_slice(&wire_frame(false, PADDING_CONTINUE, b"second", 5));

        let (mut sink, _) = pair();
        sink.raw = bytes;
        sink.unpad();
        assert_eq!(&sink.payload[..], &b"firstsecond"[..]);
        assert!(sink.raw.is_empty(), "the framing is fully consumed");
    }

    #[tokio::test]
    async fn ended_framing_drains_tail_then_releases_staging_buffers() {
        let (client, mut peer) = tokio::io::duplex(1 << 18);
        let mut stream = VisionStream::new(Box::new(client), uuid());
        let mut wire = wire_frame(true, PADDING_END, b"last", 3);
        wire.extend_from_slice(b"tail");
        peer.write_all(&wire).await.unwrap();
        let mut first = [0; 8];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"lasttail");
        assert_eq!(stream.raw.capacity(), 0);
        assert_eq!(stream.payload.capacity(), 0);
        let payload = vec![0x5a; 65536];
        peer.write_all(&payload).await.unwrap();
        let mut received = vec![0; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        assert_eq!(stream.raw.capacity(), 0);
        assert_eq!(stream.payload.capacity(), 0);
    }

    #[test]
    fn uuid_is_stripped_from_the_first_inbound_frame() {
        let framed = wire_frame(true, PADDING_CONTINUE, b"payload", 1);
        let (mut sink, _) = pair();
        sink.raw = framed;
        sink.unpad();
        assert_eq!(&sink.payload[..], &b"payload"[..]);
    }

    #[test]
    fn unframed_traffic_passes_through() {
        let (mut sink, _) = pair();
        sink.raw = BytesMut::from(&b"plain bytes"[..]);
        sink.eof = true;
        sink.unpad();
        assert_eq!(&sink.payload[..], &b"plain bytes"[..]);
    }

    #[test]
    fn direct_write_requires_peer_direct_and_a_complete_inner_record() {
        let record = [0x17, 0x03, 0x03, 0, 2, 1, 2];
        let (mut ordinary, _) = pair();
        ordinary.saw_tls = true;
        assert_eq!(ordinary.next_command(&record), PADDING_END);
        let (mut direct, _) = pair();
        direct.saw_tls = true;
        direct.direct_read = true;
        assert_eq!(direct.next_command(&record[..6]), PADDING_CONTINUE);
        assert!(!direct.direct_write_pending);
        assert_eq!(direct.next_command(&record[6..]), PADDING_DIRECT);
        assert!(direct.direct_write_pending);
    }

    #[test]
    fn tls_detection() {
        assert!(VisionStream::looks_like_tls(&[
            0x16, 0x03, 0x01, 0x00, 0x05, 0x00
        ]));
        assert!(VisionStream::looks_like_tls(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x01
        ]));
        assert!(!VisionStream::looks_like_tls(b"GET / HTTP/1.1"));
    }

    #[test]
    fn large_inner_record_split_into_frames_must_reach_direct() {
        for ccs in [false, true] {
            let (mut stream, _) = pair();
            stream.saw_tls = true;
            stream.direct_read = true;
            let mut record = if ccs {
                vec![0x14, 3, 3, 0, 1, 1]
            } else {
                vec![]
            };
            record.extend_from_slice(&[0x17, 3, 3, 0x40, 0]);
            record.extend_from_slice(&vec![0x77; 16384]);
            let mut offset = 0;
            while offset < record.len() {
                let take = VisionStream::frame_take(&record[offset..]);
                let command = stream.next_command(&record[offset..offset + take]);
                offset += take;
                assert_eq!(
                    command,
                    if offset == record.len() {
                        PADDING_DIRECT
                    } else {
                        PADDING_CONTINUE
                    }
                );
            }
            assert!(!stream.padding);
        }
    }

    #[test]
    fn inner_record_boundaries_survive_every_header_split_and_reject_bad_lengths() {
        let mut wire = vec![
            0x16, 3, 1, 0, 1, 1, 0x14, 3, 3, 0, 1, 1, 0x17, 3, 3, 0, 2, 9, 8,
        ];
        let boundary = wire.len();
        wire.extend_from_slice(&[0x17, 3, 3, 0, 1, 7]);
        for split in 1..boundary {
            let mut records = WriteRecords::default();
            assert_eq!(records.feed(&wire[..split]), (split, false));
            assert_eq!(records.feed(&wire[split..]), (boundary - split, true));
            assert!(records.saw_handshake);
            assert_eq!(records.feed(&wire[boundary..]), (6, true));
        }
        for bad in [
            [0x17, 3, 3, 0, 0],
            [0x17, 3, 3, 0xff, 0xff],
            [0x17, 2, 3, 0, 1],
        ] {
            let mut records = WriteRecords::default();
            assert!(!records.feed(&bad).1);
            assert!(!records.feed(&[0x17, 3, 3, 0, 1, 7]).1);
        }
    }

    #[tokio::test]
    async fn reads_back_what_the_peer_wrote() {
        // two frames, delivered in pieces
        let mut framed = wire_frame(true, PADDING_CONTINUE, b"alpha", 2);
        framed.extend_from_slice(&wire_frame(false, PADDING_CONTINUE, b"beta", 7));
        let (client, server) = tokio::io::duplex(4096);
        let mut sink = VisionStream::new(Box::new(client), uuid());
        let mut server = server;
        tokio::spawn(async move {
            for chunk in framed.chunks(7) {
                let _ = server.write_all(chunk).await;
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            let _ = server.shutdown().await;
        });
        let mut out = Vec::new();
        sink.read_to_end(&mut out)
            .await
            .expect("read through the framing");
        assert_eq!(out, b"alphabeta");
    }
}
