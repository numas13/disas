#[macro_use]
extern crate log;

mod cli;

use std::{
    error::Error,
    fs,
    io::{self, Write},
    process,
};

use disasm::{Arch, Disasm, Options, PrinterInfo};
use object::{Object, ObjectSection, Section, SymbolMap, SymbolMapName};

use crate::cli::Cli;

#[derive(Copy, Clone)]
struct Info<'a> {
    symbols: &'a SymbolMap<SymbolMapName<'a>>,
}

impl PrinterInfo for Info<'_> {
    fn get_symbol(&self, address: u64) -> Option<(u64, &str)> {
        self.symbols.get(address).map(|s| (s.address(), s.name()))
    }

    fn get_symbol_after(&self, address: u64) -> Option<(u64, &str)> {
        let symbols = self.symbols.symbols();
        let symbol = match symbols.binary_search_by_key(&address, |symbol| symbol.address()) {
            Ok(index) => symbols.iter().skip(index).find(|i| i.address() != address),
            Err(index) => symbols.get(index),
        };
        symbol.map(|s| (s.address(), s.name()))
    }
}

struct App<'a> {
    file: &'a object::File<'a>,

    opts: Options,
    arch: Arch,

    threads: usize,
    threads_block_size: usize,
}

impl<'a> App<'a> {
    fn get_disasm_arch(file: &object::File, cli: &Cli) -> Arch {
        use disasm::arch::*;
        use object::Architecture as A;

        match file.architecture() {
            #[cfg(feature = "riscv")]
            A::Riscv32 | A::Riscv64 => Arch::Riscv(riscv::Options {
                ext: riscv::Extensions::all(),
                xlen: if file.architecture() == A::Riscv64 {
                    riscv::Xlen::X64
                } else {
                    riscv::Xlen::X32
                },
            }),
            #[cfg(feature = "x86")]
            A::I386 | A::X86_64 => {
                let mut opts = x86::Options {
                    ext: x86::Extensions::all(),
                    att: true,
                    ..x86::Options::default()
                };

                if file.architecture() == A::I386 {
                    opts.ext.amd64 = false;
                }

                for i in cli.disassembler_options.iter().rev() {
                    match i.as_str() {
                        "att" => opts.att = true,
                        "intel" => opts.att = false,
                        "suffix" => opts.suffix_always = true,
                        _ => eprintln!("warning: unsupported option `{i}`"),
                    }
                }

                Arch::X86(opts)
            }
            _ => {
                eprintln!("error: unsupported architecture");
                process::exit(1);
            }
        }
    }

    fn get_file_format(file: &object::File) -> String {
        use object::{Architecture as A, Endianness as E, File};

        let mut format = String::new();

        match file {
            File::Elf32(..) => format.push_str("elf32"),
            File::Elf64(..) => format.push_str("elf64"),
            _ => todo!(),
        }

        format.push('-');

        match file.architecture() {
            A::Riscv32 | A::Riscv64 => {
                let endianess = match file.endianness() {
                    E::Little => "little",
                    E::Big => "big",
                };
                format.push_str(endianess);
                format.push_str("riscv");
            }
            A::I386 => {
                format.push_str("i386");
            }
            A::X86_64 => {
                format.push_str("x86-64");
            }
            _ => todo!(),
        }

        format
    }

    fn new(cli: &'a Cli, file: &'a object::File<'a>) -> Self {
        let opts = Options {
            alias: !cli.disassembler_options.iter().any(|i| i == "no-aliases"),
            decode_zeroes: cli.disassemble_zeroes,
            ..Options::default()
        };

        let arch = Self::get_disasm_arch(file, cli);
        let format = Self::get_file_format(file);

        println!();
        println!("{}:     file format {format}", cli.path);
        println!();

        Self {
            file,
            opts,
            arch,
            threads: cli.threads,
            threads_block_size: cli.threads_block_size,
        }
    }

    fn disassemble_section(&self, section: Section) -> Result<(), Box<dyn Error>> {
        let section_name = section.name()?;

        // ignore broken pipe error
        fn helper(result: io::Result<()>) -> io::Result<()> {
            if matches!(result, Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe) {
                Ok(())
            } else {
                result
            }
        }

        helper({
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "\nDisassembly of section {section_name}:")
        })?;

        let data = section.data()?;
        let address = section.address();

        #[cfg(feature = "parallel")]
        if self.threads > 1 && data.len() >= 1024 * 64 {
            self.disassemble_code_parallel(address, data, section_name)?;
            return Ok(());
        }
        helper(self.disassemble_code(address, data, section_name))?;
        Ok(())
    }

    #[cfg(feature = "parallel")]
    fn disassemble_code_parallel(
        &self,
        address: u64,
        data: &[u8],
        section_name: &str,
    ) -> Result<(), io::Error> {
        use std::{io::Write, sync::mpsc, thread};

        enum Message {
            Offset(usize),
            Print,
        }

        let block_size = self.threads_block_size;
        debug!("using ~{block_size} bytes per block");

        thread::scope(|s| {
            let mut tx = Vec::with_capacity(self.threads);
            let mut rx = Vec::with_capacity(self.threads);

            for _ in 0..self.threads {
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
                    let mut dis = Disasm::new(self.arch, address, self.opts);
                    let mut buffer = Vec::with_capacity(8 * 1024);
                    let symbols = self.file.symbol_map();
                    let info = Info { symbols: &symbols };
                    let stdout = std::io::stdout();

                    while let Ok(msg) = rx.recv() {
                        match msg {
                            Message::Offset(start) => {
                                if start >= data.len() {
                                    debug!("thread#{id}: end of code");
                                    return Ok(());
                                }

                                let skip = start - (dis.address() - address) as usize;
                                dis.skip(skip);
                                let block_address = dis.address();

                                debug!("thread#{id}: {block_address:#x} offset {start}");

                                let tail = &data[start..];
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
                                    size = tail.iter()
                                        .position(|i| *i != 0)
                                        .unwrap_or(tail.len());
                                    debug!("thread#{id}: {block_address:#x} found block of zeros, {size} bytes");
                                    size += block_size;
                                }
                                let len = block.len();

                                if tx.send(Message::Offset(start + len)).is_err() {
                                    return Ok(());
                                }

                                debug!("thread#{id}: {block_address:#x} disassemble {len} bytes");

                                buffer.clear();
                                let mut out = std::io::Cursor::new(buffer);
                                dis.print(&mut out, block, section_name, &info, start == 0)?;
                                buffer = out.into_inner();
                            }
                            Message::Print => {
                                let address = dis.address();
                                let len = buffer.len();
                                debug!("thread#{id}: {address:#x} print {len} bytes");
                                if let Err(err) = stdout.lock().write_all(&buffer) {
                                    if err.kind() == io::ErrorKind::BrokenPipe {
                                        break;
                                    } else {
                                        return Err(err);
                                    }
                                }
                                if tx.send(Message::Print).is_err() {
                                    return Ok(());
                                }
                            }
                        }
                    }

                    Ok(())
                });
            }
        });

        Ok(())
    }

    fn disassemble_code(
        &self,
        address: u64,
        data: &[u8],
        section_name: &str,
    ) -> Result<(), io::Error> {
        let stdout = std::io::stdout();

        #[allow(unused_mut)]
        let mut out = stdout.lock();

        #[cfg(all(unix, feature = "block-buffering"))]
        let mut out = {
            use std::{
                fs::File,
                io::BufWriter,
                os::fd::{AsRawFd, FromRawFd},
            };
            BufWriter::new(unsafe { File::from_raw_fd(out.as_raw_fd()) })
        };

        let mut disasm = Disasm::new(self.arch, address, self.opts);
        let symbols = self.file.symbol_map();
        let info = Info { symbols: &symbols };
        let res = disasm.print(&mut out, data, section_name, &info, true);

        // do not close stdout if BufWriter is used
        #[cfg(all(unix, feature = "block-buffering"))]
        {
            use std::os::fd::IntoRawFd;
            match out.into_inner() {
                Ok(out) => {
                    out.into_raw_fd();
                }
                Err(err) => {
                    let (err, out) = err.into_parts();
                    let (out, _) = out.into_parts();
                    out.into_raw_fd();
                    return Err(err);
                }
            }
        }

        res
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let cli = cli::parse_cli();
    let data = fs::read(&cli.path)?;
    let file = object::File::parse(&*data)?;
    let app = App::new(&cli, &file);

    if cli.sections.is_empty() {
        for section in file.sections() {
            if object::SectionKind::Text == section.kind() {
                app.disassemble_section(section)?;
            }
        }
    } else {
        for section_name in &cli.sections {
            if let Some(section) = file.section_by_name(section_name) {
                app.disassemble_section(section)?;
            }
        }
    }

    Ok(())
}
