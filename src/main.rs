extern crate clap;
#[macro_use] extern crate bitflags;

use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::vec::Vec;

use clap::{Arg, App};

use crate::coff::FileContainer;

mod errors;
mod coff;
mod decoder;

enum FileAction {
    Header,
    Extract,
    Disassemble,
}

fn handle_file_buffer(buf: &[u8], action: FileAction, section: Option<&str>) {
    match FileContainer::read(buf) {
        Ok(container) => {
            match action {
                FileAction::Header => {
                    println!("{:?}", container.header);

                    if let Some(opt_header) = &container.opt_header {
                        println!("{:?}", opt_header);
                    }
                },
                FileAction::Extract => {
                    for (sec_num, section) in container.sections.iter().enumerate() {
                        println!("{:?}", section.header);

                        if let Err(e) = container.dump_relocation_table(sec_num) {
                            println!("Error: Couldn't dump relocation table: {:?}", e);
                        }

                        if let Err(e) = container.dump_section_data(sec_num) {
                            println!("Error: Couldn't dump section data: {:?}", e);
                        }
                    }
                    container.dump_symbol_table();
                    container.dump_strings_table();
                },
                FileAction::Disassemble => {
                    print!("Using section: {}\n\n", section.unwrap_or(".text"));
                    container.disassemble_named_section(section.unwrap_or(".text"));
                }
            }
        },
        Err(e) => {
            println!("Could not parse file: {}", e);
        }
    }
}

fn main() {
    let matches = App::new("WE32100 Disassembler")
        .version("0.2")
        .author("Seth J. Morabito <web@loomcom.com>")
        .about("WE32100 Disassembler")
        .arg(Arg::with_name("SECTION")
             .value_name("SECTION")
             .short("n")
             .long("named section")
             .help("Named section to disassemble or dump")
             .takes_value(true))
        .arg(Arg::with_name("header")
            .short("H")
            .long("file-header")
            .help("Extract file header information")
            .group("action"))
        .arg(Arg::with_name("info")
            .short("i")
            .long("info")
            .help("Extract section information")
            .group("action"))
        .arg(Arg::with_name("disassemble")
            .short("d")
            .long("disassemble")
            .help("Disassemble section")
            .group("action"))
        .arg(Arg::with_name("INPUT")
            .value_name("FILE")
            .help("Input file to decompile")
            .requires("action")
            .required(true)
            .index(1))
        .get_matches();

    let infile = matches.value_of("INPUT").unwrap_or("a.out");
    let section = matches.value_of("SECTION");
    let (header, extract, disassemble) = (matches.is_present("header"),
                                          matches.is_present("extract"),
                                          matches.is_present("disassemble"));

    let action = match (header, extract, disassemble) {
        (true, _, _) => FileAction::Header,
        (_, true, _) => FileAction::Extract,
        (_, _, true) => FileAction::Disassemble,
        _ => unreachable!(),
    };

    let path = Path::new(infile);
    let display = path.display();

    let mut file = match File::open(&path) {
        Err(why) => panic!("Couldn't open {}: {}", display, why.description()),
        Ok(file) => file,
    };

    let mut buf = Vec::new();

    if let Err(why) = file.read_to_end(&mut buf) {
        panic!("Couldn't open {}: {}", display, why.description())
    }

    handle_file_buffer(&buf, action, section);
}
