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
        self.disassemble_code(section.address(), section.data()?, section_name)?;
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
        let res = disasm.print(&mut out, data, section_name, &info);

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
                    out.into_inner().unwrap().into_raw_fd();
                    return Err(err);
                }
            }
        }

        res
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
