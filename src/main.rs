mod cli;

use std::{error::Error, fs, io::Write};

use disasm::{arch::riscv, Arch, Bundle, Disasm, Options, PrinterInfo};
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
}

struct App<'a> {
    file: &'a object::File<'a>,

    opts: Options,
    arch: Arch,
}

impl<'a> App<'a> {
    fn new(cli: &'a Cli, file: &'a object::File<'a>) -> Self {
        let opts = Options {
            alias: !cli.disassembler_options.iter().any(|i| i == "no-aliases"),
            ..Options::default()
        };

        let opts_riscv = riscv::Options {
            ext: riscv::Extensions::all(),
            ..Default::default()
        };
        let arch = Arch::Riscv(opts_riscv);

        // TODO: remove
        Disasm::new(Arch::Riscv(opts_riscv), 0, opts);

        println!();
        println!("{}:     file format elf64-littleriscv", cli.path); // TODO:
        println!();

        Self { file, opts, arch }
    }

    fn disassemble_section(&self, section: Section) -> Result<(), Box<dyn Error>> {
        let section_name = section.name()?;
        println!();
        println!("Disassembly of section {section_name}:");
        self.disassemble_code(section.address(), section.data()?, section_name)
    }

    fn disassemble_code(
        &self,
        address: u64,
        mut data: &[u8],
        section_name: &str,
    ) -> Result<(), Box<dyn Error>> {
        let symbols = self.file.symbol_map();
        let info = Info { symbols: &symbols };

        let mut disasm = Disasm::new(self.arch, address, self.opts);
        let mut bundle = Bundle::empty();
        let mut symbol = None;

        // TODO: bytes_per_line
        let chunk = 4;
        // TODO: chunk_encoding
        let skip_zero = 2;

        let stdout = std::io::stdout();

        #[cfg(not(all(unix, feature = "block-buffering")))]
        let mut out = stdout.lock();

        #[cfg(all(unix, feature = "block-buffering"))]
        let mut out = {
            use std::{
                fs::File,
                io::BufWriter,
                os::fd::{AsRawFd, FromRawFd},
            };
            BufWriter::new(unsafe { File::from_raw_fd(stdout.lock().as_raw_fd()) })
        };

        while data.len() >= 2 {
            let out = &mut out;
            let address = disasm.address();
            let new_symbol = symbols.get(address);
            if new_symbol != symbol {
                symbol = new_symbol;
                if let Some(symbol) = symbol {
                    writeln!(out)?;
                    writeln!(out, "{address:016x} <{}>:", symbol.name())?;
                } else {
                    writeln!(out, "{:016x} <{section_name}>:", disasm.address())?;
                }
            }

            if data.len() >= skip_zero && data.iter().take(skip_zero).all(|i| *i == 0) {
                let zeroes = data.iter().position(|i| *i != 0).unwrap_or(data.len());
                let sym = symbols.get(address + zeroes as u64);
                if sym != new_symbol || zeroes >= (skip_zero * 2 - 1) {
                    writeln!(out, "\t...")?;
                    let skip = zeroes & !(skip_zero - 1);
                    disasm.skip(skip);
                    data = &data[skip..];
                    continue;
                }
            }

            let addr_width = if address >= 0x8000 { 8 } else { 4 };

            match disasm.decode(data, &mut bundle) {
                Ok(len) => {
                    let mut insns = bundle.iter();
                    let mut n = 0;
                    let mut i = 0;
                    while n < len || i < bundle.len() {
                        write!(out, "{address:addr_width$x}:\t")?;

                        let mut l = 0;
                        if n < len {
                            for i in data[n..len].iter().take(chunk).rev() {
                                write!(out, "{i:02x}")?;
                                n += 1;
                                l += 1;
                            }
                        } else {
                            l = chunk;
                            write!(out, "{1:0$}", chunk, ' ')?;
                        }

                        if let Some(insn) = insns.next() {
                            // INFO: align to match gas output
                            let width = if l == 2 { 20 } else { 18 };
                            write!(out, "{1:0$}\t", width - l * 2, ' ')?;
                            write!(out, "{}", insn.printer(&disasm, info))?;
                        }
                        writeln!(out)?;
                        i += 1;
                    }
                    data = &data[len..];
                }
                Err(len) => {
                    // TODO:
                    write!(out, "{address:addr_width$x}:\t",)?;
                    for i in data.iter().take(len).rev() {
                        write!(out, "{i:02x}")?;
                    }
                    // INFO: align to match gas output
                    let width = if len == 2 { 20 } else { 18 };
                    write!(out, "{1:0$}\t", width - len * 2, ' ')?;
                    writeln!(out, "failed to decode")?;
                    data = &data[len..];
                }
            }
        }

        #[cfg(all(unix, feature = "block-buffering"))]
        {
            use std::os::fd::IntoRawFd;
            // do not close stdout
            out.into_inner()?.into_raw_fd();
        }

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
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
