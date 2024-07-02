mod cli;

use std::{error::Error, fs, io::Write, process};

use disasm::{Arch, Bundle, Disasm, Options, PrinterInfo};
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
    fn get_disasm_arch(file: &object::File) -> Arch {
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
            _ => todo!(),
        }

        format
    }

    fn new(cli: &'a Cli, file: &'a object::File<'a>) -> Self {
        let opts = Options {
            alias: !cli.disassembler_options.iter().any(|i| i == "no-aliases"),
            ..Options::default()
        };

        let arch = Self::get_disasm_arch(file);
        let format = Self::get_file_format(file);

        println!();
        println!("{}:     file format {format}", cli.path);
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

        let bytes_per_line = self.arch.bytes_per_line();
        let min_len = disasm.insn_size_min();
        let skip_zeroes = self.arch.skip_zeroes();

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

        while data.len() >= min_len {
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

            if data.len() >= skip_zeroes && data.iter().take(skip_zeroes).all(|i| *i == 0) {
                let zeroes = data.iter().position(|i| *i != 0).unwrap_or(data.len());
                let sym = symbols.get(address + zeroes as u64);
                if sym != new_symbol || zeroes >= (skip_zeroes * 2 - 1) {
                    writeln!(out, "\t...")?;
                    let skip = zeroes & !(skip_zeroes - 1);
                    disasm.skip(skip);
                    data = &data[skip..];
                    continue;
                }
            }

            let (len, is_ok, mut err_msg) = match disasm.decode(data, &mut bundle) {
                Ok(len) => (len, true, None),
                Err(err) => {
                    let len = match err {
                        disasm::Error::More(_) => data.len(),
                        disasm::Error::Failed(len) => len,
                    };
                    (len, false, Some("failed to decode"))
                }
            };

            let addr_width = if address >= 0x1000 { 8 } else { 4 };
            let bytes_per_chunk = self.arch.bytes_per_chunk(len);
            let mut insns = bundle.iter();
            let mut chunks = data[..len].chunks(bytes_per_chunk);
            let mut l = 0;
            loop {
                let insn = if is_ok { insns.next() } else { None };
                if l >= len && insn.is_none() {
                    break;
                }
                write!(out, "{:addr_width$x}:\t", address + l as u64)?;

                let mut p = 0;
                let mut c = 0;
                if l < len {
                    for _ in (0..bytes_per_line).step_by(bytes_per_chunk) {
                        c += 1;
                        if let Some(chunk) = chunks.next() {
                            for i in chunk.iter().rev() {
                                write!(out, "{i:02x}")?;
                            }
                            out.write_all(b" ")?;
                            p += chunk.len();
                            l += chunk.len();
                            c -= 1;
                        }
                    }
                }

                let width = (bytes_per_line - p) * 2 + c;

                if let Some(insn) = insn {
                    write!(out, "{:width$}\t{}", "", insn.printer(&disasm, info))?;
                }

                if let Some(err) = err_msg.take() {
                    write!(out, "{:width$}\t{err}", "")?;
                }

                writeln!(out)?;
            }
            data = &data[len..];
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
