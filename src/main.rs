#[macro_use]
extern crate log;

mod cli;

use std::{
    error::Error,
    fs,
    io::{self, Write},
    process,
};

use disasm::{Arch, Decoder, Options, PrinterExt};
use object::{Object, ObjectSection, Section, SymbolMap, SymbolMapName};

#[cfg(feature = "color")]
use std::fmt::{self, Display};

#[cfg(feature = "color")]
use disasm::Style;

use crate::cli::{Cli, Color};

fn unsupported_arch() -> ! {
    eprintln!("error: unsupported architecture");
    process::exit(1);
}

#[derive(Clone)]
struct Info<'a> {
    #[cfg_attr(not(feature = "color"), allow(dead_code))]
    color: Color,
    symbols: SymbolMap<SymbolMapName<'a>>,
}

impl PrinterExt for Info<'_> {
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

    #[cfg(feature = "color")]
    fn print_styled(
        &self,
        fmt: &mut fmt::Formatter,
        style: Style,
        display: impl fmt::Display,
    ) -> fmt::Result {
        use owo_colors::OwoColorize;

        match self.color {
            Color::Off => display.fmt(fmt),
            Color::On | Color::Extended => match style {
                Style::Slot => display.fmt(fmt),
                Style::Mnemonic => display.yellow().fmt(fmt),
                Style::SubMnemonic => display.yellow().fmt(fmt),
                Style::Register => display.blue().fmt(fmt),
                Style::Immediate => display.magenta().fmt(fmt),
                Style::Address => display.magenta().fmt(fmt),
                Style::AddressOffset => display.magenta().fmt(fmt),
                Style::Symbol => display.green().fmt(fmt),
                Style::Comment => display.fmt(fmt),
                Style::AssemblerDirective => display.fmt(fmt),
            },
            // TODO: Color::Extended
        }
    }
}

struct App<'a> {
    file: &'a object::File<'a>,

    opts: Options,
    arch: Arch,

    color: Color,

    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    threads: usize,
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    threads_block_size: usize,
}

impl<'a> App<'a> {
    fn get_disasm_arch(file: &object::File, cli: &Cli) -> Arch {
        use disasm::arch::*;
        use object::Architecture as A;

        match file.architecture() {
            #[cfg(feature = "e2k")]
            A::E2K32 | A::E2K64 => {
                use object::FileFlags;

                let mut opts = e2k::Options::default();
                if let FileFlags::Elf { e_flags, .. } = file.flags() {
                    use object::elf;

                    opts.isa = match elf::ef_e2k_flag_to_mach(e_flags) {
                        elf::E_E2K_MACH_BASE => 2,
                        elf::E_E2K_MACH_EV1 => 1,
                        elf::E_E2K_MACH_EV2 => 2,
                        elf::E_E2K_MACH_EV3 => 3,
                        elf::E_E2K_MACH_EV4 => 4,
                        elf::E_E2K_MACH_EV5 => 5,
                        elf::E_E2K_MACH_EV6 => 6,
                        elf::E_E2K_MACH_EV7 => 7,

                        elf::E_E2K_MACH_8C => 4,
                        elf::E_E2K_MACH_1CPLUS => 4,
                        elf::E_E2K_MACH_12C => 6,
                        elf::E_E2K_MACH_16C => 6,
                        elf::E_E2K_MACH_2C3 => 6,
                        elf::E_E2K_MACH_48C => 7,
                        elf::E_E2K_MACH_8V7 => 7,

                        mach => {
                            debug!("e2k: unexpected e_flags.mach={mach}");
                            opts.isa
                        }
                    };
                }
                Arch::E2K(opts)
            }

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
            A::I386 | A::X86_64 | A::X86_64_X32 => {
                use x86::AddrSize;

                let mut opts = x86::Options {
                    ext: x86::Extensions::all(),
                    att: true,
                    ..x86::Options::default()
                };

                match file.architecture() {
                    A::I386 => {
                        opts.ext.amd64 = false;
                    }
                    A::X86_64_X32 => {
                        opts.addr_size = AddrSize::Addr32;
                    }
                    _ => {}
                }

                for i in cli.disassembler_options.iter().rev() {
                    match i.as_str() {
                        "att" => opts.att = true,
                        "intel" => opts.att = false,
                        "suffix" => opts.suffix_always = true,
                        "addr32" => opts.addr_size = AddrSize::Addr32,
                        "addr64" => opts.addr_size = AddrSize::Addr64,
                        _ => eprintln!("warning: unsupported option `{i}`"),
                    }
                }

                Arch::X86(opts)
            }
            _ => unsupported_arch(),
        }
    }

    fn get_file_format(file: &object::File) -> String {
        use object::{Architecture as A, Endianness as E, File};

        let mut format = String::new();

        match file {
            File::Elf32(..) => format.push_str("elf32"),
            File::Elf64(..) => format.push_str("elf64"),
            _ => format.push_str("unknown"),
        }

        format.push('-');

        match file.architecture() {
            A::E2K32 | A::E2K64 => {
                format.push_str("e2k");

                if let object::FileFlags::Elf { e_flags, .. } = file.flags() {
                    if e_flags & object::elf::EF_E2K_PM != 0 {
                        format.push_str("-pm");
                    }
                }
            }
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
            A::X86_64 | A::X86_64_X32 => {
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
            color: cli.disassembler_color,
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
        use std::{sync::mpsc, thread};

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
                let name = format!("thread#{id}");
                s.spawn(move || {
                    let symbols = self.file.symbol_map();
                    let info = Info { color: self.color, symbols };
                    let mut dis = Decoder::new(self.arch, address, self.opts).printer(info, section_name);
                    let mut buffer = Vec::with_capacity(8 * 1024);
                    let mut block_address = 0;
                    let mut block_len = 0;
                    let mut decoded = 0;
                    let stdout = std::io::stdout();

                    while let Ok(msg) = rx.recv() {
                        match msg {
                            Message::Offset(start) => {
                                if start >= data.len() {
                                    debug!("{name}: end of code");
                                    return Ok(());
                                }

                                let skip = start as u64 - (dis.address() - address);
                                dis.skip(skip);
                                block_address = dis.address();

                                debug!("{name}: {block_address:#x} offset {start:#x}");

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
                });
            }
        });

        Ok(())
    }

    fn disassemble_code(&self, address: u64, data: &[u8], section_name: &str) -> io::Result<()> {
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

        let symbols = self.file.symbol_map();
        let info = Info {
            color: self.color,
            symbols,
        };
        let res = Decoder::new(self.arch, address, self.opts)
            .printer(info, section_name)
            .print(&mut out, data, true);

        // do not close stdout if BufWriter is used
        #[cfg(all(unix, feature = "block-buffering"))]
        {
            use std::os::fd::IntoRawFd;
            match out.into_inner() {
                Ok(out) => {
                    let _ = out.into_raw_fd();
                }
                Err(err) => {
                    let (err, out) = err.into_parts();
                    let (out, _) = out.into_parts();
                    let _ = out.into_raw_fd();
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
