use std::cmp;

use bpaf::*;

#[derive(Copy, Clone, Debug)]
pub enum Color {
    Off,
    On,
    Extended,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Cli {
    pub disassemble: bool,
    pub disassemble_all: bool,
    pub disassemble_zeroes: bool,
    pub disassemble_symbols: Vec<String>,
    pub sections: Vec<String>,
    pub disassembler_options: Vec<String>,
    pub disassembler_color: Color,
    pub threads: usize,
    pub threads_block_size: usize,
    pub path: String,
}

pub fn parse_cli() -> Cli {
    let disassemble = short('d')
        .long("disassemble")
        .help("Display assembler contents of executable sections")
        .switch();

    let disassemble_all = short('D')
        .long("disassemble-all")
        .help("Display assembler contents of all sections")
        .switch();

    let disassemble_zeroes = short('z')
        .long("disassemble-zeroes")
        .help("Do not skip blocks of zeroes when disassembling")
        .switch();

    let disassemble_symbols = long("disassemble-symbols")
        .help("Display assembler contents from <sym>")
        .argument::<String>("sym")
        .map(|s| {
            s.split(|c: char| c.is_whitespace())
                .map(|i| i.trim())
                .filter(|i| !i.is_empty())
                .map(|i| i.into())
                .collect()
        })
        .fallback(Vec::new());

    let disassembler_options = short('M')
        .long("disassembler-options")
        .help("Pass text OPT on to the disassembler")
        .argument::<String>("OPT")
        .map(|s| {
            s.split(',')
                .map(|i| i.trim())
                .filter(|i| !i.is_empty())
                .map(|i| i.into())
                .collect()
        })
        .fallback(Vec::new());

    #[cfg(feature = "color")]
    let auto_color =
        supports_color::on(supports_color::Stream::Stdout).map_or(Color::Off, |_| Color::On);

    #[cfg(not(feature = "color"))]
    let auto_color = Color::Off;

    let disassembler_color = long("disassembler-color")
        .help("Enable or disable disassembler color output [default: auto, valid modes: off, on, auto, terminal, extended]")
        .argument::<String>("MODE")
        .parse(move |s| {
            match s.as_str() {
                "off" => Ok(Color::Off),
                "on" => Ok(Color::On),
                "auto" | "terminal" => Ok(auto_color),
                "extended" => Ok(Color::Extended),
                _ => Err(format!("invalid color {s}")),
            }
        })
        .fallback(auto_color);

    let sections = short('j')
        .long("section")
        .help("Only display information for section NAME")
        .argument("NAME")
        .many();

    let num_cpus = std::thread::available_parallelism()
        .map(|i| i.get())
        .unwrap_or(1);

    #[cfg(feature = "parallel")]
    let threads_help = &*format!("Set the number of threads to use [default: {num_cpus}]");

    #[cfg(not(feature = "parallel"))]
    let threads_help = "Set the number of threads to use [disabled at compile]";

    let threads = long("threads")
        .help(threads_help)
        .argument("NUM")
        .map(move |i| match i {
            0 => num_cpus,
            _ => i,
        })
        .fallback(cmp::min(4, num_cpus));

    let threads_block_size = long("threads-block-size")
        .help("Set the number of bytes decoded per thread [default: 4096]")
        .argument("BYTES")
        .map(|i: usize| i.clamp(256, 1024 * 1024))
        .fallback(4096);

    let path = positional("FILE")
        .help("File to process")
        .fallback("a.out".into());

    construct!(Cli {
        disassemble,
        disassemble_all,
        disassemble_zeroes,
        disassemble_symbols,
        sections,
        disassembler_options,
        disassembler_color,
        threads,
        threads_block_size,
        path,
    })
    .to_options()
    .descr("This is a description")
    .fallback_to_usage()
    .run()
}
