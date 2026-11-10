use std::task::{Context, Poll};

use bytes::Buf;

#[cfg(feature = "tracing")]
use tracing::trace;

use crate::error::Code;
use crate::proto::frame::SettingsError;
use crate::proto::push::InvalidPushId;
use crate::quic::{InvalidStreamId, StreamErrorIncoming};
use crate::stream::{BufRecvStream, WriteBuf};
use crate::{
    buf::BufList,
    proto::{
        frame::{self, Frame, FrameType, PayloadLen},
        stream::StreamId,
    },
    quic::{BidiStream, RecvStream, SendStream},
};

/// Decodes Frames from the underlying QUIC stream
pub struct FrameStream<S, B> {
    pub stream: BufRecvStream<S, B>,
    // Already read data from the stream
    decoder: FrameDecoder,
    remaining_data: usize,
    // A connection error observed while frame bytes were still buffered.
    // Those bytes are delivered first, then this error is surfaced exactly once.
    pending_quic_error: Option<FrameStreamError>,
}

impl<S, B> FrameStream<S, B> {
    pub fn new(stream: BufRecvStream<S, B>) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::default(),
            remaining_data: 0,
            pending_quic_error: None,
        }
    }

    /// A frame stream that accepts frames other than DATA with a payload of
    /// at most `max_payload` bytes (see [`FrameStreamError::TooLarge`]).
    pub fn with_max_payload(stream: BufRecvStream<S, B>, max_payload: u64) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::with_max_payload(max_payload),
            remaining_data: 0,
            pending_quic_error: None,
        }
    }

    /// Unwraps the Framed streamer and returns the underlying stream **without** data loss for
    /// partially received/read frames.
    pub fn into_inner(self) -> BufRecvStream<S, B> {
        self.stream
    }
}

impl<S, B> FrameStream<S, B>
where
    S: RecvStream,
{
    /// Polls the stream for the next frame header
    ///
    /// When a frame header is received use `poll_data` to retrieve the frame's data.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        assert!(
            self.remaining_data == 0,
            "There is still data to read, please call poll_data() until it returns None."
        );

        loop {
            // A connection error must not discard frames that are already buffered: defer it
            // until they are decoded. Any other error, notably a peer stream reset, surfaces now.
            // While an error is pending the transport is not polled again.
            let end = if self.pending_quic_error.is_some() {
                Poll::Ready(true)
            } else {
                match self.try_recv(cx) {
                    Poll::Ready(Ok(end)) => Poll::Ready(end),
                    Poll::Ready(Err(e)) if e.is_connection_error() => {
                        self.pending_quic_error = Some(e);
                        Poll::Ready(true)
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            };

            return match self.decoder.decode(self.stream.buf_mut())? {
                Some(Frame::Data(PayloadLen(len))) => {
                    self.remaining_data = len;
                    Poll::Ready(Ok(Some(Frame::Data(PayloadLen(len)))))
                }
                frame @ Some(Frame::WebTransportStream(_)) => {
                    self.remaining_data = usize::MAX;
                    Poll::Ready(Ok(frame))
                }
                Some(frame) => Poll::Ready(Ok(Some(frame))),
                None => match end {
                    // Received a chunk but frame is incomplete, poll until we get `Pending`.
                    Poll::Ready(false) => continue,
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(true) => {
                        if let Some(error) = self.pending_quic_error.take() {
                            // Every buffered frame has been delivered: surface the deferred
                            // connection error.
                            Poll::Ready(Err(error))
                        } else if self.stream.buf_mut().has_remaining() || self.decoder.skip > 0 {
                            // Reached the end of receive stream, but there is still some data:
                            // The frame is incomplete.
                            Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
                        } else {
                            Poll::Ready(Ok(None))
                        }
                    }
                },
            };
        }
    }

    /// Retrieves the next piece of data in an incoming data packet or webtransport stream
    ///
    ///
    /// WebTransport bidirectional payload has no finite length and is processed until the end of the stream.
    pub fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, FrameStreamError>> {
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        };

        // A connection error must not discard body bytes that are already buffered: defer it
        // until they are drained. Any other error, notably a peer stream reset, surfaces now.
        let end = if self.pending_quic_error.is_some() {
            true
        } else {
            match self.try_recv(cx) {
                Poll::Ready(Ok(end)) => end,
                Poll::Ready(Err(e)) if e.is_connection_error() => {
                    self.pending_quic_error = Some(e);
                    true
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => false,
            }
        };
        let data = self.stream.buf_mut().take_chunk(self.remaining_data);

        match (data, end) {
            (None, true) => match self.pending_quic_error.take() {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Ready(Ok(None)),
            },
            (None, false) => Poll::Pending,
            // The stream finished cleanly in the middle of the frame. After a connection
            // error, the partial body is delivered and the connection error follows instead.
            (Some(d), true)
                if self.pending_quic_error.is_none()
                    && d.remaining() < self.remaining_data
                    && !self.stream.buf_mut().has_remaining() =>
            {
                Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
            }
            (Some(d), _) => {
                self.remaining_data -= d.remaining();
                Poll::Ready(Ok(Some(d)))
            }
        }
    }

    /// Stops the underlying stream with the provided error code
    pub(crate) fn stop_sending(&mut self, error_code: Code) {
        self.stream.stop_sending(error_code.into());
    }

    pub(crate) fn has_data(&self) -> bool {
        self.remaining_data != 0
    }

    pub(crate) fn is_eos(&self) -> bool {
        self.stream.is_eos() && !self.stream.buf().has_remaining()
    }

    fn try_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, FrameStreamError>> {
        if self.stream.is_eos() {
            return Poll::Ready(Ok(true));
        }
        match self.stream.poll_read(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(FrameStreamError::Quic(e))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(eos)) => Poll::Ready(Ok(eos)),
        }
    }

    pub fn id(&self) -> StreamId {
        self.stream.recv_id()
    }
}

impl<T, B> SendStream<B> for FrameStream<T, B>
where
    T: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_ready(cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.stream.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.stream.send_id()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: BidiStream<B>,
    B: Buf,
{
    pub(crate) fn split(self) -> (FrameStream<S::SendStream, B>, FrameStream<S::RecvStream, B>) {
        let (send, recv) = self.stream.split();
        (
            FrameStream {
                stream: send,
                decoder: FrameDecoder::default(),
                remaining_data: 0,
                pending_quic_error: None,
            },
            FrameStream {
                stream: recv,
                decoder: self.decoder,
                remaining_data: self.remaining_data,
                pending_quic_error: self.pending_quic_error,
            },
        )
    }
}

/// The largest payload of a frame other than DATA that a stream without its
/// own limit (the control stream) buffers: those frames carry a few integers.
pub const DEFAULT_MAX_FRAME_PAYLOAD: u64 = 64 * 1024;

pub struct FrameDecoder {
    expected: Option<usize>,
    /// The largest payload of a frame other than DATA buffered for decoding.
    max_payload: u64,
    /// Payload bytes of an unknown frame over `max_payload` still to discard.
    skip: u64,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::with_max_payload(DEFAULT_MAX_FRAME_PAYLOAD)
    }
}

impl FrameDecoder {
    fn with_max_payload(max_payload: u64) -> Self {
        Self {
            expected: None,
            max_payload,
            skip: 0,
        }
    }

    fn decode<B: Buf>(
        &mut self,
        src: &mut BufList<B>,
    ) -> Result<Option<Frame<PayloadLen>>, FrameStreamError> {
        // Decode in a loop since we ignore unknown frames, and there may be
        // other frames already in our BufList.
        loop {
            if !src.has_remaining() {
                return Ok(None);
            }

            if self.skip > 0 {
                // An unknown frame too large to buffer: its payload is
                // dropped as it arrives.
                let n = src
                    .remaining()
                    .min(usize::try_from(self.skip).unwrap_or(usize::MAX));
                src.advance(n);
                self.skip -= n as u64;
                continue;
            }

            if let Some(min) = self.expected {
                if src.remaining() < min {
                    return Ok(None);
                }
            }

            // The declared payload length is checked before the payload is
            // buffered: a frame other than DATA is only decoded once all of
            // it has arrived.
            let header = {
                let mut cur = src.cursor();
                Frame::peek_header(&mut cur).map(|(ty, len)| (ty, len, cur.position()))
            };
            if let Some((ty, len, header_len)) = header {
                if ty != FrameType::DATA && len > self.max_payload {
                    if !ty.is_known() {
                        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
                        //# Endpoints MUST
                        //# NOT consider these frames to have any meaning upon receipt.
                        src.advance(header_len);
                        self.expected = None;
                        self.skip = len;
                        continue;
                    }
                    return Err(FrameStreamError::TooLarge {
                        frame_type: ty.value(),
                        size: len,
                        max_size: self.max_payload,
                    });
                }
            }

            let (pos, decoded) = {
                let mut cur = src.cursor();
                let decoded = Frame::decode(&mut cur);
                (cur.position(), decoded)
            };

            match decoded {
                Err(frame::FrameError::UnknownFrame(_ty)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
                    //# Endpoints MUST
                    //# NOT consider these frames to have any meaning upon receipt.
                    #[cfg(feature = "tracing")]
                    trace!("ignore unknown frame type {:#x}", _ty);

                    src.advance(pos);
                    self.expected = None;
                    continue;
                }
                Err(frame::FrameError::Incomplete(min)) => {
                    self.expected = Some(min);
                    return Ok(None);
                }
                Ok(frame) => {
                    src.advance(pos);
                    self.expected = None;
                    return Ok(Some(frame));
                }
                // -------------- Map the error Values --------------
                Err(frame::FrameError::InvalidStreamId(e)) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidStreamId(e),
                    ));
                }
                Err(frame::FrameError::InvalidPushId(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::InvalidPushId(
                        e,
                    )));
                }
                Err(frame::FrameError::Settings(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Settings(e)));
                }
                Err(frame::FrameError::UnsupportedFrame(ty)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(
                        ty,
                    )));
                }
                Err(frame::FrameError::InvalidFrameValue) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidFrameValue,
                    ));
                }
                Err(frame::FrameError::Malformed) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Malformed));
                }
            }
        }
    }
}

#[derive(Debug)]
/// Errors that can occur while decoding frames
pub enum FrameStreamError {
    Proto(FrameProtocolError),
    Quic(StreamErrorIncoming),
    UnexpectedEnd,
    /// A frame other than DATA declared a payload larger than the stream
    /// accepts; it was not buffered.
    TooLarge {
        /// The frame type
        frame_type: u64,
        /// The declared payload length
        size: u64,
        /// The largest payload the stream accepts
        max_size: u64,
    },
}

impl FrameStreamError {
    /// Whether this error closed the whole QUIC connection, not just this stream.
    ///
    /// Only a connection error is deferred behind buffered bytes. A peer stream reset is
    /// reported once and frees the stream, and RFC 9114 section 7.1 only treats a truncated
    /// frame as a connection error when the stream terminates cleanly. Holding a reset back
    /// would turn a DATA frame it truncated into `UnexpectedEnd`, a connection-level
    /// H3_FRAME_ERROR that tears down every other stream on the connection.
    ///
    /// Every other stream-level error surfaces immediately too. h3-quinn maps a read of
    /// rejected 0-RTT data (`ZeroRttRejected`) and a read of a freed stream (`ClosedStream`)
    /// to `Unknown`: deferring those would hand the application bytes the transport has
    /// already disowned, such as data from rejected 0-RTT.
    fn is_connection_error(&self) -> bool {
        matches!(
            self,
            FrameStreamError::Quic(StreamErrorIncoming::ConnectionErrorIncoming { .. })
        )
    }
}

#[derive(Debug, PartialEq)]
/// Protocol specific errors that can occur while decoding frames in a stream
pub enum FrameProtocolError {
    Malformed,
    ForbiddenFrame(u64), // Known (http2) frames that should generate an error
    InvalidFrameValue,
    Settings(SettingsError),
    InvalidStreamId(InvalidStreamId),
    InvalidPushId(InvalidPushId),
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use bytes::{BufMut, Bytes, BytesMut};
    use futures_util::future::poll_fn;
    use std::{cell::Cell, collections::VecDeque, rc::Rc};

    use crate::proto::{coding::Encode, frame::FrameType, varint::VarInt};
    use crate::quic::ConnectionErrorIncoming;

    // Decoder

    #[test]
    fn one_frame() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn incomplete_frame() {
        let frame = Frame::headers(&b"salut"[..]);

        let mut buf = BytesMut::with_capacity(16);
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    #[test]
    fn header_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf_list = BufList::new();
        // Cut buffer between type and length
        buf_list.push(&buf[..1]);
        buf_list.push(&buf[1..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn varint_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers("salut".repeat(1024)).encode_with_payload(&mut buf);

        let mut buf_list = BufList::new();
        // Cut buffer in the middle of length's varint
        buf_list.push(&buf[..2]);
        buf_list.push(&buf[2..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn two_frames_then_incomplete() {
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);

        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    // FrameStream

    macro_rules! assert_poll_matches {
        ($poll_fn:expr, $match:pat) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match
            );
        };
        ($poll_fn:expr, $match:pat if $cond:expr ) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match if $cond
            );
        }
    }

    #[tokio::test]
    async fn poll_full_request() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk(buf.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 4
        );
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
    }

    /// Regression: a connection error read while a complete HEADERS frame is still buffered must
    /// not discard it. The `poll_data` that drains the body reads the error with the trailing
    /// HEADERS frame in the buffer.
    #[tokio::test]
    async fn poll_next_drains_buffered_headers_before_quic_close() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk_then_error(buf.freeze(), connection_close());
        let transport_polls = recv.poll_count.clone();
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        // This poll reads the connection error, with the body and the trailers still buffered.
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
        assert_eq!(transport_polls.get(), 2);
        assert_poll_matches!(|cx| to_bytes(stream.poll_data(cx)), Ok(None));
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_poll_matches!(|cx| stream.poll_next(cx), Err(FrameStreamError::Quic(_)));
        // The saved error is surfaced exactly once, without polling the transport again.
        assert_eq!(transport_polls.get(), 2);
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(None));
    }

    /// Regression: h3 0.0.8's `poll_next` polls the transport before it decodes, so it can read
    /// the connection error itself while a complete frame is still buffered. The frame is
    /// delivered, then the error follows exactly once without another transport poll.
    #[tokio::test]
    async fn poll_next_drains_a_buffered_frame_when_it_reads_the_quic_close() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk_then_error(buf.freeze(), connection_close());
        let transport_polls = recv.poll_count.clone();
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        // This poll reads the connection error with the second HEADERS frame still buffered.
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_eq!(transport_polls.get(), 2);
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::Quic(StreamErrorIncoming::ConnectionErrorIncoming { .. }))
        );
        assert_eq!(transport_polls.get(), 2);
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(None));
    }

    /// Regression: a connection error must not strand DATA frame body bytes that were buffered
    /// before it arrived, and must still be reported once the body is delivered.
    #[tokio::test]
    async fn poll_data_drains_buffered_body_before_quic_close() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);
        recv.chunk_then_error(buf.freeze(), connection_close());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        // This poll reads the connection error but still returns the buffered body.
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 4
        );
        // Otherwise the close would look like a clean end of stream to the caller.
        assert_poll_matches!(|cx| stream.poll_next(cx), Err(FrameStreamError::Quic(_)));
    }

    /// A connection error that truncates a DATA frame delivers the buffered part of the body,
    /// then surfaces as the connection error rather than as `UnexpectedEnd`.
    #[tokio::test]
    async fn poll_data_surfaces_quic_close_over_a_truncated_buffered_body() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        FrameType::DATA.encode(&mut buf);
        VarInt::from(8u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.freeze());
        recv.chunk_then_error(Bytes::from_static(b"dy"), connection_close());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(8))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );
        // This poll reads the connection error with "dy" buffered and the frame 4 bytes short.
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::Quic(StreamErrorIncoming::ConnectionErrorIncoming { .. }))
        );
    }

    /// Regression: a peer RESET_STREAM that truncates a DATA frame while part of that frame is
    /// still buffered must surface as the reset. Holding it back to drain the buffer would end
    /// the body in `UnexpectedEnd`, which the request stream escalates to a connection-level
    /// H3_FRAME_ERROR ("received incomplete frame").
    #[tokio::test]
    async fn poll_data_surfaces_stream_reset_over_a_truncated_buffered_body() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        FrameType::DATA.encode(&mut buf);
        VarInt::from(8u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.freeze());
        recv.chunk_then_error(Bytes::from_static(b"dy"), stream_reset());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(8))))
        );
        // This poll pulls "dy" into the buffer behind "bo".
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );
        // The reset arrives with "dy" buffered and the frame 4 bytes short.
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated { error_code }))
                if error_code == RESET_CODE
        );
    }

    /// Regression: a peer RESET_STREAM read while whole frames are still buffered surfaces as the
    /// reset instead of those frames. Quinn reports a reset only once, so holding it back would
    /// lose its error code.
    #[tokio::test]
    async fn poll_data_surfaces_stream_reset_over_a_buffered_frame() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk_then_error(buf.freeze(), stream_reset());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated { error_code }))
                if error_code == RESET_CODE
        );
    }

    /// Regression: a peer RESET_STREAM observed by `poll_next` with a decodable frame buffered
    /// surfaces as the reset instead of the frame. Returning the frame first lost the one-shot
    /// reset: the next read of the freed QUIC stream no longer carries its code.
    #[tokio::test]
    async fn poll_next_surfaces_stream_reset_over_a_buffered_frame() {
        let recv = FakeRecv {
            pending_error: Some(stream_reset()),
            ..FakeRecv::default()
        };
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated { error_code }))
                if error_code == RESET_CODE
        );
    }

    /// Regression: only a connection error is deferred. h3-quinn reports a read of rejected
    /// 0-RTT data as `Unknown`; deferring it behind the buffered body handed the application
    /// bytes from a 0-RTT flight the server had rejected.
    #[tokio::test]
    async fn poll_data_surfaces_unknown_stream_error_over_a_buffered_body() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        recv.chunk_then_error(buf.freeze(), zero_rtt_rejected());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        // The error is read with the whole body buffered: none of it is delivered.
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::Quic(StreamErrorIncoming::Unknown(_)))
        );
    }

    /// Regression: the `poll_next` side of the same rule. An `Unknown` stream error read with a
    /// decodable HEADERS frame buffered surfaces ahead of that frame.
    #[tokio::test]
    async fn poll_next_surfaces_unknown_stream_error_over_a_buffered_frame() {
        let recv = FakeRecv {
            pending_error: Some(zero_rtt_rejected()),
            ..FakeRecv::default()
        };
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::Quic(StreamErrorIncoming::Unknown(_)))
        );
    }

    #[tokio::test]
    async fn poll_next_incomplete_frame() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 1));
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    #[should_panic(
        expected = "There is still data to read, please call poll_data() until it returns None"
    )]
    async fn poll_next_reamining_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // There is still data to consume, poll_next should panic
        let _ = poll_fn(|cx| stream.poll_next(cx)).await;
    }

    #[tokio::test]
    async fn poll_data_split() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Body is split into two bufs
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 2));
        recv.chunk(buf);
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // We get the total size of data about to be received
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // Then we get parts of body, chunked as they arrived
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
    }

    #[tokio::test]
    async fn poll_data_unexpected_end() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Truncated body
        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"b"[..]);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn poll_data_ignores_unknown_frames() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // grease a lil
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(0);

        // grease with some data
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(6);
        buf.put_slice(b"grease");

        // Body
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
    }

    #[tokio::test]
    async fn poll_data_eos_but_buffered_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.clone().freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        buf.truncate(0);
        buf.put_slice(&b"dy"[..]);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
    }

    // Helpers

    /// `H3_REQUEST_CANCELLED`, the code a peer that cuts a response resets the stream with.
    const RESET_CODE: u64 = 0x010c;

    fn connection_close() -> StreamErrorIncoming {
        StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: ConnectionErrorIncoming::ApplicationClose { error_code: 0x100 },
        }
    }

    fn stream_reset() -> StreamErrorIncoming {
        StreamErrorIncoming::StreamTerminated {
            error_code: RESET_CODE,
        }
    }

    /// The `Unknown` error h3-quinn reports for a read of rejected 0-RTT data.
    fn zero_rtt_rejected() -> StreamErrorIncoming {
        StreamErrorIncoming::Unknown(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "0-RTT rejected",
        )))
    }

    #[derive(Default)]
    struct FakeRecv {
        chunks: VecDeque<Bytes>,
        pending_error: Option<StreamErrorIncoming>,
        poll_count: Rc<Cell<usize>>,
    }

    impl FakeRecv {
        fn chunk(&mut self, buf: Bytes) -> &mut Self {
            self.chunks.push_back(buf);
            self
        }

        /// Queue a last chunk, after which the transport reports `err` instead of the end of the
        /// stream.
        fn chunk_then_error(&mut self, buf: Bytes, err: StreamErrorIncoming) -> &mut Self {
            self.chunks.push_back(buf);
            self.pending_error = Some(err);
            self
        }
    }

    impl RecvStream for FakeRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.poll_count.set(self.poll_count.get() + 1);
            if let Some(chunk) = self.chunks.pop_front() {
                return Poll::Ready(Ok(Some(chunk)));
            }
            match self.pending_error.take() {
                Some(err) => Poll::Ready(Err(err)),
                None => Poll::Ready(Ok(None)),
            }
        }

        fn stop_sending(&mut self, _: u64) {
            unimplemented!()
        }

        fn recv_id(&self) -> StreamId {
            unimplemented!()
        }
    }

    fn to_bytes(
        x: Poll<Result<Option<impl Buf>, FrameStreamError>>,
    ) -> Poll<Result<Option<Bytes>, FrameStreamError>> {
        x.map(|b| b.map(|b| b.map(|mut b| b.copy_to_bytes(b.remaining()))))
    }
}
