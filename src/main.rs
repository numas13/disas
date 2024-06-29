use std::{env, error::Error, fs, io::Write};

use disasm::{arch::riscv, Arch, Bundle, Disasm, Options, PrinterInfo};
use object::{Object, ObjectSection, SymbolMap, SymbolMapName};

#[derive(Copy, Clone)]
struct Info<'a> {
    symbols: &'a SymbolMap<SymbolMapName<'a>>,
}

impl PrinterInfo for Info<'_> {
    fn get_symbol(&self, address: u64) -> Option<(u64, &str)> {
        self.symbols.get(address).map(|s| (s.address(), s.name()))
    }
}

#[derive(Default)]
struct Cli {
    alias: bool,
    path: String,
}

fn parse_cli() -> Cli {
    let mut cli = Cli {
        alias: true,
        ..Cli::default()
    };
    for i in env::args().skip(1) {
        match i.as_str() {
            "--no-aliases" => cli.alias = false,
            _ => {
                cli.path = i;
                return cli;
            }
        }
    }
    cli.path = String::from("a.out");
    cli
}

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(not(feature = "block-buffering"))]
    let out = {
        use std::io;
        let stdout = io::stdout();
        &mut stdout.lock()
    };

    #[cfg(feature = "block-buffering")]
    let out = {
        use std::{fs::File, io::BufWriter, os::fd::FromRawFd};
        &mut BufWriter::new(unsafe { File::from_raw_fd(1) })
    };

    let cli = parse_cli();
    let data = fs::read(&cli.path)?;
    let file = object::File::parse(&*data)?;
    let symbols = file.symbol_map();
    let info = Info { symbols: &symbols };
    let rv_opts = riscv::Options {
        ext: riscv::Extensions::all(),
        ..Default::default()
    };
    let opts = Options {
        alias: cli.alias,
        ..Options::default()
    };

    Disasm::new(Arch::Riscv(rv_opts), 0, opts);

    writeln!(out)?;
    writeln!(out, "{}:     file format elf64-littleriscv", cli.path)?; // TODO:
    writeln!(out)?;
    writeln!(out)?;

    for section in file.sections() {
        let section_name = section.name()?;
        if section_name == ".text" {
            let mut disasm = Disasm::new(Arch::Riscv(rv_opts), section.address(), opts);
            writeln!(out, "Disassembly of section {section_name}:")?;

            let mut data = section.data()?;
            let mut bundle = Bundle::empty();
            let mut symbol = None;

            // TODO: bytes_per_line
            let chunk = 4;
            // TODO: chunk_encoding
            let skip_zero = 2;

            while data.len() >= 2 {
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
            break;
        }
    }
    Ok(())
}
