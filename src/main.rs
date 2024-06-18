use std::{
    env,
    error::Error,
    fs,
    io::{self, Write},
};

use disasm::{Arch, Bundle, Disasm, Options, PrinterInfo};
use object::{Object, ObjectSection, SymbolMap, SymbolMapName};

#[derive(Copy, Clone)]
struct Info<'a>(&'a SymbolMap<SymbolMapName<'a>>);

impl PrinterInfo for Info<'_> {
    fn get_symbol(&self, address: u64) -> Option<(u64, &str)> {
        self.0.get(address).map(|s| (s.address(), s.name()))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).unwrap_or_else(|| String::from("a.out"));
    let data = fs::read(&path)?;
    let file = object::File::parse(&*data)?;
    let symbols = file.symbol_map();
    let info = Info(&symbols);
    let opts = Options {
        alias: false,
        abi_regs: true,
    };

    Disasm::new(Arch::Riscv, 0, opts)?;

    println!();
    println!("{path}:     file format elf64-littleriscv"); // TODO:
    println!();
    println!();

    for section in file.sections() {
        let section_name = section.name()?;
        if section_name == ".text" {
            let mut disasm = Disasm::new(Arch::Riscv, section.address(), opts)?;
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
                    writeln!(out, "\t...")?;
                    let skip = zeroes & !(skip_zero - 1);
                    disasm.skip(skip);
                    data = &data[skip..];
                    continue;
                }

                match disasm.decode(data, &mut bundle) {
                    Ok(len) => {
                        let mut n = 0;
                        for insn in &bundle {
                            write!(out, "{address:8x}:\t",)?;

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

                            // INFO: align to match gas output
                            let width = if l == 2 { 20 } else { 18 };
                            write!(out, "{1:0$}\t", width - l * 2, ' ')?;
                            writeln!(out, "{}", insn.printer(&disasm, info))?;
                        }
                        while n < len {
                            write!(out, "{address:8x}:\t",)?;
                            for i in data[n..len].iter().take(chunk).rev() {
                                write!(out, "{i:02x}")?;
                                n += 1;
                            }
                            writeln!(out)?;
                        }
                        data = &data[len..];
                    }
                    Err(len) => {
                        // TODO:
                        write!(out, "{address:8x}:\t",)?;
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
