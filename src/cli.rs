use bpaf::*;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Cli {
    pub disassemble: bool,
    pub disassemble_all: bool,
    pub disassemble_symbols: Vec<String>,
    pub sections: Vec<String>,
    pub disassembler_options: Vec<String>,
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

    let sections = short('j')
        .long("section")
        .help("Only display information for section NAME")
        .argument("NAME")
        .many();

    let path = positional("FILE")
        .help("File to process")
        .fallback("a.out".into());

    construct!(Cli {
        disassemble,
        disassemble_all,
        disassemble_symbols,
        sections,
        disassembler_options,
        path,
    })
    .to_options()
    .descr("This is a description")
    .fallback_to_usage()
    .run()
}
