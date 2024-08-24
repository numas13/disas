#[macro_use]
extern crate log;

mod cli;

use std::{error::Error, fs, io, process};

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
            A::X86_64 => {
                let mut opts = x86::Options {
                    ext: x86::Extensions::all(),
                    att: true,
                    .. x86::Options::default()
                };

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
        }
    }

    fn disassemble_section(&self, section: Section) -> Result<(), Box<dyn Error>> {
        let section_name = section.name()?;
        println!();
        println!("Disassembly of section {section_name}:");

        let data = section.data()?;
        let address = section.address();

        #[cfg(feature = "parallel")]
        if self.threads > 1 && data.len() >= 1024 * 64 {
            self.disassemble_code_parallel(address, data, section_name)?;
            return Ok(());
        }
        self.disassemble_code(address, data, section_name)?;

        Ok(())
    }

    #[cfg(feature = "parallel")]
    fn disassemble_code_parallel(
        &self,
        address: u64,
        data: &[u8],
        section_name: &str,
    ) -> Result<(), io::Error> {
        use disasm::{Bundle, Error};
        use std::{
            io::Write,
            sync::{mpsc, Arc, Condvar, Mutex},
            thread,
        };

        // how many instructions decoded per thread
        let block_insns = 1024 * 16 / 4;
        debug!("instructions per block {block_insns}");

        thread::scope(|s| {
            let mut tx = Vec::with_capacity(self.threads);
            let mut rx = Vec::with_capacity(self.threads);

            for _ in 0..self.threads {
                let (t, r) = mpsc::sync_channel::<(usize, u64, usize, usize)>(4);
                tx.push(t);
                rx.push(r);
            }

            let current = Arc::new((Mutex::new(0), Condvar::new()));
            for (thread_id, rx) in rx.into_iter().enumerate() {
                let current = current.clone();
                s.spawn(move || {
                    debug!("thread({thread_id}): start");
                    let stdout = std::io::stdout();
                    let symbols = self.file.symbol_map();
                    let info = Info { symbols: &symbols };

                    let mut disasm = Disasm::new(self.arch, 0, self.opts);
                    let (current, condvar) = &*current;

                    let mut buffer = Vec::with_capacity(8192);
                    while let Ok((block, address, start, end)) = rx.recv() {
                        debug!("thread({thread_id}): disassemble block({block}) at {address:#x}, {} bytes", end - start);
                        let data = &data[start..end];
                        buffer.clear();
                        let mut out = std::io::Cursor::new(&mut buffer);
                        disasm.skip((address - disasm.address()) as usize);
                        disasm.print(&mut out, data, section_name, &info, block == 0).unwrap();

                        let lock = current.lock().unwrap();
                        let mut lock = condvar.wait_while(lock, |cur| *cur != block).unwrap();
                        let res = stdout.lock().write_all(&buffer);
                        *lock += 1;
                        condvar.notify_all();

                        if let Err(err) = res {
                            if err.kind() == io::ErrorKind::BrokenPipe {
                                break;
                            } else {
                                return Err(err);
                            }
                        }
                    }
                    debug!("thread({thread_id}): stop");
                    Ok(())
                });
            }

            let mut disasm = Disasm::new(self.arch, address, self.opts);
            let min_len = disasm.insn_size_min();
            let mut bundle = Bundle::empty();
            let mut block = 0;
            let mut offset = 0;
            debug!("predecode: start");
            while data[offset..].len() >= min_len {
                let mut insns = 0;
                let start = offset;
                let address = disasm.address();
                // TODO: disasm must provide some sort of lenght decoder with respect to
                // tracking of previous instructions in backends.
                while insns < block_insns && data[offset..].len() >= min_len {
                    let len = match disasm.decode(&data[offset..], &mut bundle) {
                        Ok(len) => len,
                        Err(err) => match err {
                            Error::More(_) => data[offset..].len(),
                            Error::Failed(len) => len,
                        },
                    };
                    offset += len;
                    insns += 1;
                }
                let th = block % self.threads;
                debug!("predecode: send block({block}) at {address:#x} to thread {th}");
                if tx[th].send((block, address, start, offset)).is_err() {
                    break;
                }
                block += 1;
            }
            debug!("predecode: stop");

            drop(tx);
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
