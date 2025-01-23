use std::{cmp, fmt, num::ParseIntError, str::FromStr};

use bpaf::{doc::Style, *};

#[derive(Copy, Clone, Debug)]
pub enum Color {
    Off,
    On,
    Extended,
}

#[derive(Copy, Clone, Debug)]
pub enum Demangle {
    None,
    Auto,
    Gnuv3,
    Java,
    Gnat,
    Dlang,
    Rust,
}

impl fmt::Display for Demangle {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Demangle::None => "none",
            Demangle::Auto => "auto",
            Demangle::Gnuv3 => "gnu-v3",
            Demangle::Java => "java",
            Demangle::Gnat => "gnat",
            Demangle::Dlang => "dlang",
            Demangle::Rust => "rust",
        };
        fmt.write_str(s)
    }
}

impl FromStr for Demangle {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Demangle::None),
            "auto" => Ok(Demangle::Auto),
            "gnu-v3" => Ok(Demangle::Gnuv3),
            "java" => Ok(Demangle::Java),
            "gnat" => Ok(Demangle::Gnat),
            "dlang" => Ok(Demangle::Dlang),
            "rust" => Ok(Demangle::Rust),
            _ => Err("invalid demangle style"),
        }
    }
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
    pub show_raw_insn: bool,
    pub source: bool,
    pub demangle: Demangle,
    pub start_address: u64,
    pub stop_address: u64,
    pub threads: usize,
    pub threads_block_size: usize,
    pub path: String,
}

fn parse_address(s: &str) -> Result<u64, ParseIntError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
    } else {
        s.parse()
    }
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
        .many()
        .map(|v| {
            v.join(",")
                .split(',')
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

    let show_raw_insn = long("show-raw-insn")
        .help("Display hex alongside symbolic disassembly")
        .switch()
        .map(|_| true);
    let no_show_raw_insn = long("no-show-raw-insn")
        .switch()
        .hide_usage()
        .map(|_| false);
    let show_raw_insn = construct!([show_raw_insn, no_show_raw_insn])
        .custom_usage(&[("--[no-]show-raw-insn", Style::Literal)])
        .fallback(true)
        .last();

    let source = short('S')
        .long("source")
        .help("Intermix source code with disassembly")
        .switch()
        .hide();

    let demangle_flag = short('C')
        .long("demangle")
        .switch()
        .hide()
        .map(|_| Demangle::Auto);
    let demangle_arg = short('C')
        .long("demangle")
        .help("Decode mangled/processed symbol names [default: auto]")
        .argument::<Demangle>("STYLE");
    let demangle = construct!([demangle_arg, demangle_flag])
        .last()
        .fallback(Demangle::Auto);

    let sections = short('j')
        .long("section")
        .help("Only display information for section NAME")
        .argument("NAME")
        .many();

    let start_address = long("start-address")
        .help("Only process data whose address is >= ADDR")
        .argument::<String>("ADDR")
        .parse(move |s| parse_address(&s))
        .fallback(0);

    let stop_address = long("stop-address")
        .help("Only process data whose address is < ADDR")
        .argument::<String>("ADDR")
        .parse(move |s| parse_address(&s))
        .fallback(u64::MAX);

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
        start_address,
        stop_address,
        disassembler_options,
        disassembler_color,
        show_raw_insn,
        source,
        demangle,
        threads,
        threads_block_size,
        path,
    })
    .to_options()
    .version(env!("CARGO_PKG_VERSION"))
    .descr("This is a description")
    .fallback_to_usage()
    .run()
}
