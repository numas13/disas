use std::{
    io::{self, Write},
    sync::mpsc,
    thread,
};

use crate::App;

enum Message {
    Offset(usize),
    Print,
}

struct Parallel<'a> {
    app: &'a App<'a>,
    address: u64,
    data: &'a [u8],
    section_name: &'a str,
}

impl<'a> Parallel<'a> {
    fn new(app: &'a App<'a>, address: u64, data: &'a [u8], section_name: &'a str) -> Self {
        Self {
            app,
            address,
            data,
            section_name,
        }
    }

    fn disassemble_thread(
        &self,
        name: &str,
        rx: mpsc::Receiver<Message>,
        tx: mpsc::SyncSender<Message>,
    ) -> Result<(), io::Error> {
        let info = self.app.create_info();
        let block_size = self.app.threads_block_size;
        let mut dis = self
            .app
            .create_decoder(self.address)
            .printer(info, self.section_name);
        let mut buffer = Vec::with_capacity(8 * 1024);
        let mut block_address = 0;
        let mut block_len = 0;
        let mut decoded = 0;
        let stdout = std::io::stdout();

        while let Ok(msg) = rx.recv() {
            match msg {
                Message::Offset(start) => {
                    if start >= self.data.len() {
                        debug!("{name}: end of code");
                        return Ok(());
                    }

                    let skip = start as u64 - (dis.address() - self.address);
                    dis.skip(skip);
                    block_address = dis.address();

                    debug!("{name}: {block_address:#x} offset {start:#x}");

                    let tail = &self.data[start..];
                    let mut size = block_size;
                    let block;
                    loop {
                        if size > tail.len() {
                            block = tail;
                            break;
                        }
                        let n = dis.decode_len(&tail[..size]);
                        if n != 0 {
                            block = &tail[..n];
                            break;
                        }
                        // decode_len found big block of zeroes
                        size = tail.iter().position(|i| *i != 0).unwrap_or(tail.len());
                        debug!("{name}: {block_address:#x} found block of zeros, {size} bytes");
                        size += block_size;
                    }
                    block_len = block.len();

                    if tx.send(Message::Offset(start + block_len)).is_err() {
                        return Ok(());
                    }

                    debug!("{name}: {block_address:#x} disassemble {block_len} bytes");

                    buffer.clear();
                    let mut out = std::io::Cursor::new(&mut buffer);
                    dis.print(&mut out, block, start == 0)?;
                    decoded = (dis.address() - block_address) as usize;
                }
                Message::Print => {
                    debug!("{name}: {block_address:#x} print {} bytes", buffer.len());

                    if let Err(err) = stdout.lock().write_all(&buffer) {
                        if err.kind() == io::ErrorKind::BrokenPipe {
                            break;
                        } else {
                            return Err(err);
                        }
                    }

                    if decoded != block_len {
                        stdout.lock().flush()?;
                        let end = dis.address();
                        error!("{name}: {block_address:#x}:{end:#x} decoded {decoded} bytes, expect {block_len} bytes");
                        return Ok(());
                    }

                    if tx.send(Message::Print).is_err() {
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    fn disassemble_code(&self) -> Result<(), io::Error> {
        debug!("using ~{} bytes per block", self.app.threads_block_size);

        thread::scope(|s| {
            let mut tx = Vec::with_capacity(self.app.threads);
            let mut rx = Vec::with_capacity(self.app.threads);

            for _ in 0..self.app.threads {
                let (t, r) = mpsc::sync_channel::<Message>(2);
                tx.push(t);
                rx.push(r);
            }

            let first = tx.remove(0);
            // manually start first thread
            first.send(Message::Offset(0)).unwrap();
            first.send(Message::Print).unwrap();
            tx.push(first);

            for (id, (rx, tx)) in rx.into_iter().zip(tx).enumerate() {
                s.spawn(move || {
                    let name = format!("thread#{id}");
                    self.disassemble_thread(&name, rx, tx)
                });
            }
        });

        Ok(())
    }
}

pub fn disassemble_code(
    app: &App,
    address: u64,
    data: &[u8],
    section_name: &str,
) -> Result<(), io::Error> {
    Parallel::new(app, address, data, section_name).disassemble_code()
}
