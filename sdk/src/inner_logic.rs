// Portal Hardware Wallet firmware and supporting software libraries
//
// Copyright (C) 2024 Alekos Filini
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::ops::DerefMut;
use std::time::Duration;

use async_std::channel;

use model::encryption::CipherState;
use rand::RngCore;

use model::reg::*;
use model::write_buffer::*;
use model::{Message, MessageFragment, Reply, Request};

const WRITE_CMD: u8 = 0xA2;

const SRAM_PAGE: u8 = 0xF0;

const WAIT_TIMEOUT: u64 = 5000;

async fn wait_next(
    nfc: &mut super::IndexedChannelPair,
    dir: Option<TransferDir>,
) -> Result<(), FutureError> {
    let mut accumulated_time = 0;

    for i in 0.. {
        if accumulated_time >= WAIT_TIMEOUT {
            return Err(FutureError::Timeout);
        }

        let reg = match async_std::future::timeout(
            Duration::from_millis(WAIT_TIMEOUT),
            nfc.send(vec![0x30, 0xED]),
        )
        .await
        {
            Ok(raw_data) => raw_data.map(|data| NS_REG::from_bytes([data[2]]))?,
            Err(_) => return Err(FutureError::Timeout),
        };
        match reg {
            // Garbage left by a previous transaction
            r if dir.is_none() && r.SRAM_RF_READY() => {
                // Read the last page
                nfc.send(vec![0x30, 0xFF]).await?;
            }

            // Wait for the card to be ready
            r if dir.is_none() && r.RF_LOCKED() => return Ok(()),

            // The memory is locked to the I2C bus
            r if !r.RF_LOCKED() => {}
            // We are waiting for a message from the host and it still isn't ready
            r if dir == Some(TransferDir::HostToNfc) && !r.SRAM_RF_READY() => {}
            // We need to write more data but the host hasn't finished reading it yet
            r if dir == Some(TransferDir::NfcToHost) && r.SRAM_I2C_READY() => {}

            // Yay
            _ => {
                // dbg!(r);

                return Ok(());
            }
        }

        let sleep_time = core::cmp::min(100, 25 * i);
        async_std::task::sleep(Duration::from_millis(sleep_time)).await;

        accumulated_time += sleep_time;
    }

    unreachable!()
}

pub(crate) async fn inner_future(
    requests: &channel::Receiver<Request>,
    replies: &channel::Sender<Result<Reply, FutureError>>,
    nfc: &mut super::IndexedChannelPair,
    use_fast_ops: bool,

    #[cfg(feature = "debug")] debug: &channel::Sender<super::DebugMessage>,
) -> Result<(), FutureError> {
    async fn send_message(
        nfc: &mut super::IndexedChannelPair,
        use_fast_ops: bool,
        msg: Message,
    ) -> Result<(), FutureError> {
        wait_next(nfc, None).await?;

        for fragment in msg.get_fragments() {
            // dbg!(&fragment);

            let mut buffer = if use_fast_ops {
                EitherNfcWriteBuffer::Fast(FastNfcWriteBuffer::new())
            } else {
                EitherNfcWriteBuffer::Slow(NfcWriteBuffer::new())
            };
            buffer.append(&fragment);

            for part in buffer.get_data() {
                let _resp = nfc.send(part.to_vec()).await?;
                // debug_assert_eq!(resp, Vec::<u8>::new());
            }

            if !fragment.is_eof() {
                wait_next(nfc, Some(TransferDir::NfcToHost)).await?;
            }
        }

        Ok(())
    }

    async fn recv_message(
        nfc: &mut super::IndexedChannelPair,
        use_fast_ops: bool,
    ) -> Result<Message, FutureError> {
        let mut msg = Message::empty();
        loop {
            let mut buf = Vec::with_capacity(64);

            if use_fast_ops {
                let data = [0x3A, 0xF0, 0xFF];
                let data_in = nfc.send(data.to_vec()).await?;
                buf.extend(data_in);
            } else {
                for i in 0..4 {
                    let data = [0x30, 0xF0 + (i * 4)];
                    let data_in = nfc.send(data.to_vec()).await?;
                    buf.extend(data_in);
                }
            }

            let fragment = MessageFragment::from(buf.as_slice());
            if msg.push_fragment(fragment)? {
                break Ok(msg);
            }

            wait_next(nfc, Some(TransferDir::HostToNfc)).await?;
        }
    }

    async fn process_request(
        nfc: &mut super::IndexedChannelPair,
        encrypt: &mut CipherState,
        decrypt: &mut CipherState,
        requests: &channel::Receiver<Request>,
        replies: &channel::Sender<Result<Reply, FutureError>>,
        use_fast_ops: bool,

        #[cfg(feature = "debug")] debug: &channel::Sender<super::DebugMessage>,
    ) -> Result<(), FutureError> {
        let request = requests.recv().await?;

        // Since we've popped the request from the channel at this point, if we fail
        // we need to send a reply
        let on_drop = OnDrop::new(|| {
            let _ = replies.send_blocking(Err(FutureError::Canceled));
        });

        #[cfg(feature = "debug")]
        debug
            .send(super::DebugMessage::Out(request.clone()))
            .await?;

        let msg = Message::new_serialize(&request, encrypt)?;
        send_message(nfc, use_fast_ops, msg).await?;

        wait_next(nfc, Some(TransferDir::HostToNfc)).await?;

        let msg = recv_message(nfc, use_fast_ops).await?;
        let mut decrypt_buf = Vec::new();
        let reply: Reply = msg.deserialize(&mut decrypt_buf, decrypt)?;

        #[cfg(feature = "debug")]
        debug.send(super::DebugMessage::In(reply.clone())).await?;

        replies.send(Ok(reply)).await?;

        on_drop.defuse();

        Ok(())
    }

    // Perform noise handshake first
    let mut ephemeral_key = model::encryption::wrap_sensitive([0; 32]);
    (rand::thread_rng()).fill_bytes(ephemeral_key.deref_mut());
    let mut handshake_state = model::encryption::handhake_state_initiator(ephemeral_key);

    let out_msg = handshake_state
        .write_message_vec(&[])
        .expect("Successful handshake msg");
    log::debug!("Sending Noise handshake message...");
    send_message(nfc, use_fast_ops, Message::from_slice(&out_msg)).await?;

    wait_next(nfc, Some(TransferDir::HostToNfc)).await?;

    let in_msg = recv_message(nfc, use_fast_ops).await?;
    match handshake_state.read_message_vec(in_msg.data()) {
        Ok(_) => {
            log::debug!("Valid handshake!");
        }
        Err(e) => {
            log::warn!("Invalid handshake: {:?}", e);
            return Err(FutureError::Canceled); // TODO: add specific error
        }
    }

    assert!(handshake_state.completed());
    log::debug!("Completed Noise handshake");

    let (mut encrypt, mut decrypt) = handshake_state.get_ciphers();

    loop {
        if let Err(e) = process_request(
            nfc,
            &mut encrypt,
            &mut decrypt,
            requests,
            replies,
            use_fast_ops,
            #[cfg(feature = "debug")]
            debug,
        )
        .await
        {
            replies.send(Err(e.clone())).await?;
            break Err(e);
        }
    }
}

/// Runs a closure on drop.
///
/// Taken from rtic-common
pub struct OnDrop<F: FnOnce()> {
    f: core::mem::MaybeUninit<F>,
}

impl<F: FnOnce()> OnDrop<F> {
    /// Make a new droppper given a closure.
    pub fn new(f: F) -> Self {
        Self {
            f: core::mem::MaybeUninit::new(f),
        }
    }

    /// Make it not run drop.
    pub fn defuse(self) {
        core::mem::forget(self)
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        unsafe { self.f.as_ptr().read()() }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum FutureError {
    Message(model::MessageError),
    ChannelError,
    Timeout,
    Canceled,
}
impl From<model::MessageError> for FutureError {
    fn from(value: model::MessageError) -> Self {
        FutureError::Message(value)
    }
}
impl From<async_std::channel::RecvError> for FutureError {
    fn from(_: async_std::channel::RecvError) -> Self {
        FutureError::ChannelError
    }
}
impl<T> From<async_std::channel::SendError<T>> for FutureError {
    fn from(_: async_std::channel::SendError<T>) -> Self {
        FutureError::ChannelError
    }
}

struct NfcWriteBuffer;

impl WriteBufferInit<6, 16, 1> for NfcWriteBuffer {
    fn new() -> WriteBuffer<6, 16, 1> {
        let mut b0 = [0u8; 6];
        b0[0] = WRITE_CMD;
        b0[1] = SRAM_PAGE;
        let mut b1 = [0u8; 6];
        b1[0] = WRITE_CMD;
        b1[1] = SRAM_PAGE + 1;
        let mut b2 = [0u8; 6];
        b2[0] = WRITE_CMD;
        b2[1] = SRAM_PAGE + 2;
        let mut b3 = [0u8; 6];
        b3[0] = WRITE_CMD;
        b3[1] = SRAM_PAGE + 3;
        let mut b4 = [0u8; 6];
        b4[0] = WRITE_CMD;
        b4[1] = SRAM_PAGE + 4;
        let mut b5 = [0u8; 6];
        b5[0] = WRITE_CMD;
        b5[1] = SRAM_PAGE + 5;
        let mut b6 = [0u8; 6];
        b6[0] = WRITE_CMD;
        b6[1] = SRAM_PAGE + 6;
        let mut b7 = [0u8; 6];
        b7[0] = WRITE_CMD;
        b7[1] = SRAM_PAGE + 7;
        let mut b8 = [0u8; 6];
        b8[0] = WRITE_CMD;
        b8[1] = SRAM_PAGE + 8;
        let mut b9 = [0u8; 6];
        b9[0] = WRITE_CMD;
        b9[1] = SRAM_PAGE + 9;
        let mut ba = [0u8; 6];
        ba[0] = WRITE_CMD;
        ba[1] = SRAM_PAGE + 0xa;
        let mut bb = [0u8; 6];
        bb[0] = WRITE_CMD;
        bb[1] = SRAM_PAGE + 0xb;
        let mut bc = [0u8; 6];
        bc[0] = WRITE_CMD;
        bc[1] = SRAM_PAGE + 0xc;
        let mut bd = [0u8; 6];
        bd[0] = WRITE_CMD;
        bd[1] = SRAM_PAGE + 0xd;
        let mut be = [0u8; 6];
        be[0] = WRITE_CMD;
        be[1] = SRAM_PAGE + 0xe;
        let mut bf = [0u8; 6];
        bf[0] = WRITE_CMD;
        bf[1] = SRAM_PAGE + 0xf;

        let buffer = [
            b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, ba, bb, bc, bd, be, bf,
        ];

        Self::init_fields(buffer)
    }
}

struct FastNfcWriteBuffer;

impl WriteBufferInit<67, 1, 2> for FastNfcWriteBuffer {
    fn new() -> WriteBuffer<67, 1, 2> {
        let mut b0 = [0u8; 67];
        b0[0] = 0xA6;
        b0[1] = 0xF0;
        b0[2] = 0xFF;

        let buffer = [b0];

        Self::init_fields(buffer)
    }
}

enum EitherNfcWriteBuffer {
    Slow(WriteBuffer<6, 16, 1>),
    Fast(WriteBuffer<67, 1, 2>),
}

impl EitherNfcWriteBuffer {
    pub fn get_data<'s>(&'s self) -> Box<dyn Iterator<Item = &[u8]> + Send + 's> {
        match self {
            EitherNfcWriteBuffer::Slow(inner) => Box::new(inner.get_data().map(|x| x.as_slice())),
            EitherNfcWriteBuffer::Fast(inner) => Box::new(inner.get_data().map(|x| x.as_slice())),
        }
    }

    pub fn append(&mut self, fragment: &MessageFragment) {
        match self {
            EitherNfcWriteBuffer::Slow(inner) => inner.append(fragment),
            EitherNfcWriteBuffer::Fast(inner) => inner.append(fragment),
        }
    }
}
