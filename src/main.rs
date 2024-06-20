use std::{
    env,
    error::Error,
    fs,
    io::{self, Write},
};

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

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).unwrap_or_else(|| String::from("a.out"));
    let data = fs::read(&path)?;
    let file = object::File::parse(&*data)?;
    let symbols = file.symbol_map();
    let info = Info { symbols: &symbols };
    let rv_opts = riscv::Options {
        ext: riscv::Extensions::all(),
        ..Default::default()
    };
    let opts = Options {
        alias: false,
        ..Options::default()
    };

    Disasm::new(Arch::Riscv(rv_opts), 0, opts);

    println!();
    println!("{path}:     file format elf64-littleriscv"); // TODO:
    println!();
    println!();

    for section in file.sections() {
        let section_name = section.name()?;
        if section_name == ".text" {
            let mut disasm = Disasm::new(Arch::Riscv(rv_opts), section.address(), opts);
            let stdout = io::stdout();
            let out = &mut stdout.lock();
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
