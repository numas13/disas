use std::{
    env,
    error::Error,
    fs,
    io::{self, Write},
};

use disasm::{Arch, Disasm, Insn, Options, PrinterInfo};
use object::{Object, ObjectSection, SymbolMap, SymbolMapName};

#[derive(Copy, Clone)]
struct Info<'a>(&'a SymbolMap<SymbolMapName<'a>>);

impl PrinterInfo for Info<'_> {
    fn get_symbol(&self, address: u64) -> Option<(u64, &str)> {
        self.0.get(address).map(|s| (s.address(), s.name()))
    }
}

/// Reads a file and displays the name of each section.
fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).unwrap_or_else(|| String::from("a.out"));
    let data = fs::read(&path)?;
    let file = object::File::parse(&*data)?;
    let symbols = file.symbol_map();
    let info = Info(&symbols);
    let opts = Options { alias: true };

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
            let mut insn = Insn::default();
            let mut symbol = None;

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

                let (len, is_ok) = match disasm.decode(data, &mut insn) {
                    Ok(len) => (len, true),
                    Err(len) => (len, false),
                };

                // print address
                write!(out, "{address:8x}:\t",)?;

                // print bytes
                for i in data.iter().take(len).rev() {
                    write!(out, "{i:02x}")?;
                }
                // INFO: to match gas output
                let width = if len == 2 { 20 } else { 18 };
                write!(out, "{1:0$}\t", width - len * 2, ' ')?;

                if is_ok {
                    // print instuctions and operands
                    writeln!(out, "{}", insn.printer(&disasm, info))?;
                } else {
                    writeln!(out, "failed to decode")?;
                }

                data = &data[len..];
            }

            break;
        }
    }
    Ok(())
}
