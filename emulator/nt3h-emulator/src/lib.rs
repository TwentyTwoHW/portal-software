use tokio::sync::{mpsc, Mutex};

use model::reg::NS_REG;

const NS_REG_INDEX: u8 = 0x06;

pub struct NT3H {
    sram: [u8; 64],
    ns_reg: NS_REG,

    interrupt: mpsc::Sender<()>,
}

impl NT3H {
    pub fn new() -> (Self, mpsc::Receiver<()>) {
        let (interrupt, receiver) = mpsc::channel(16);

        (
            NT3H {
                sram: [0; 64],
                ns_reg: NS_REG::new().with_RF_LOCKED(true),
                interrupt,
            },
            receiver,
        )
    }

    pub async fn nfc_command(&mut self, data: &[u8]) -> Vec<u8> {
        match data[0] {
            0x30 if data[1] == 0xED => {
                vec![
                    0x00,                                // WDT_MS
                    0x00,                                // I2C_CLOCK_STR
                    self.ns_reg.clone().into_bytes()[0], // NS_REG
                    0x00,                                // RFU
                ]
            }
            // Read last page
            0x30 if data[1] == 0xFF => {
                self.ns_reg = self.ns_reg.clone().with_SRAM_RF_READY(false);
                vec![0x00; 8]
            }

            // Write SRAM
            0xA6 => {
                assert!(data[1] == 0xF0 && data[2] == 0xFF);

                self.sram.copy_from_slice(&data[3..]);
                self.ns_reg = self.ns_reg.clone().with_SRAM_I2C_READY(true);
                self.interrupt.send(()).await.unwrap();

                vec![0x0a]
            }
            // Read SRAM
            0x3A => {
                assert!(data[1] == 0xF0 && data[2] == 0xFF);

                self.ns_reg = self.ns_reg.clone().with_SRAM_RF_READY(false);
                self.interrupt.send(()).await.unwrap();

                self.sram.into()
            }

            _ => vec![0x00],
        }
    }

    pub fn i2c_command<'b>(&mut self, data: &'b [u8]) -> (Vec<u8>, &'b [u8]) {
        match data[0] {
            // BLOCK_SESSION_REGISTERS
            0xFE => {
                if data.len() >= 4 {
                    // Write, we ignore all of them
                    //if data[2] == data[3] {
                    return (vec![], &data[4..]);
                    // }
                }

                // Read
                match data[1] {
                    NS_REG_INDEX => {
                        // dbg!(&self.ns_reg);
                        (vec![self.ns_reg.clone().into_bytes()[0]], &data[2..])
                    }
                    _ => (vec![0x00], &data[2..]),
                }
            }

            // BLOCK_SRAM Read
            0xF8..=0xFB => {
                let block = data[0] as usize - 0xF8;
                let start = block * 16;
                let end = start + 16;

                if data.len() == 1 {
                    if data[0] == 0xFB {
                        // Mark as finished reading
                        self.ns_reg = self.ns_reg.clone().with_SRAM_I2C_READY(false);
                    }

                    (self.sram[start..end].into(), &data[1..])
                } else {
                    self.sram[start..end].copy_from_slice(&data[1..17]);

                    if data[0] == 0xFB {
                        // Mark as finished writing
                        self.ns_reg = self.ns_reg.clone().with_SRAM_RF_READY(true);
                    }

                    (vec![], &data[17..])
                }
            }
            _ => (vec![], &data[1..]),
        }
    }
}

pub struct CommandStream<S1: Sized> {
    i2c: S1,
}

impl<S1> CommandStream<S1>
where
    S1: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    pub async fn new<S2>(i2c: S1, mut interrupt: S2, mut int_recv: mpsc::Receiver<()>) -> Self
    where
        S2: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        tokio::task::spawn(async move {
            use tokio::io::AsyncWriteExt;

            while let Some(_) = int_recv.recv().await {
                interrupt.write(&[0xFF]).await.unwrap();
            }
        });

        CommandStream { i2c }
    }

    pub async fn update_nt3h(&mut self, nt3h: &Mutex<NT3H>) -> tokio::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut data = [0u8; 256];
        let num_bytes = self.i2c.read(&mut data).await?;

        let mut nt3h = nt3h.lock().await;

        if num_bytes == 0 {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::BrokenPipe,
                "Connection closed",
            ));
        }

        let mut data = &data[..num_bytes];
        while !data.is_empty() {
            // println!("< {:02X?}", data);
            let (reply, new_data) = nt3h.i2c_command(&data);
            // println!("> {:02X?}", reply);
            self.i2c.write_all(&reply).await?;
            data = new_data;
        }

        Ok(())
    }
}
