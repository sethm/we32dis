//
// This file is part of the we32dis WE32100 Disassembler.
//
// Copyright 2018 Seth J. Morabito <web@loomcom.com>
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::io::Cursor;
use std::str;
///
/// WE32000 COFF File Parsing and Utilities
///

use byteorder::{BigEndian, ReadBytesExt};
use chrono::prelude::*;
use chrono::TimeZone;

use crate::decoder::Decoder;
use crate::errors::{CoffError, OffsetError, ReadResult};

// WE32000 without transfer vector
const MAGIC_WE32K: u16 = 0x170;

// WE32000 with transfer vector
const MAGIC_WE32K_TV: u16 = 0x171;

// Size of the file header
const FILE_HEADER_SIZE: u16 = 20;

// Length of old COFF version symbol names
const SYM_NAME_LEN: usize = 8;

// Maximum size, in bytes, of auxiliary symbol file names.
// const SYM_FILNMLEN: usize = 14;

// File Header flags
bitflags! {
    pub struct FileHeaderFlags: u16 {
        // Relocation info stripped from file
        const F_RELFLG = 0x0001;
        // File is executable (i.e. no unresolved external references)
        const F_EXEC = 0x0002;
        // Line numbers stripped from file
        const F_LNNO = 0x0004;
        // Local symbols stripped from file
        const F_LSYMS = 0x0008;
        // This file has the byte ordering of an AR32W machine (e.g. 3b, maxi)
        const F_AR32W = 0x0200;
        // WE32100 required
        const F_BM32B = 0x2000;
        // MAU required
        const F_BM32MAU = 0x4000;
    }
}

pub struct FileHeader {
    pub magic: u16,
    pub section_count: u16,
    pub timestamp: u32,
    pub datetime: DateTime<Utc>,
    pub symbol_table_offset: u32,
    pub symbol_count: u32,
    pub opt_header: u16,
    pub flags: FileHeaderFlags,
}

fn buf_to_str(buf: &[u8]) -> Result<&str, std::str::Utf8Error> {
    let nul = buf.iter().position( |&c| c == b'\0').unwrap_or(buf.len());
    str::from_utf8(&buf[0..nul])
}

impl FileHeader {
    ///
    /// Read a FileHeader from the current cursor position.
    ///

    pub fn read(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let magic = cursor.read_u16::<BigEndian>()?;
        let section_count = cursor.read_u16::<BigEndian>()?;
        let timestamp = cursor.read_u32::<BigEndian>()?;
        let symbol_table_offset = cursor.read_u32::<BigEndian>()?;
        let symbol_count = cursor.read_u32::<BigEndian>()?;
        let opt_header = cursor.read_u16::<BigEndian>()?;
        let flags = FileHeaderFlags::from_bits_truncate(cursor.read_u16::<BigEndian>()?);
        let datetime = Utc.timestamp(i64::from(timestamp), 0);

        let header = FileHeader {
            magic,
            section_count,
            timestamp,
            datetime,
            symbol_table_offset,
            symbol_count,
            opt_header,
            flags,
        };

        Ok(header)
    }

    pub fn executable(&self) -> bool {
        self.flags.contains(FileHeaderFlags::F_EXEC)
    }

    pub fn local_symbols_stripped(&self) -> bool {
        self.flags.contains(FileHeaderFlags::F_LSYMS)
    }

    pub fn is_32100_required(&self) -> bool {
        self.flags.contains(FileHeaderFlags::F_BM32B)
    }

    pub fn mau_required(&self) -> bool {
        self.flags.contains(FileHeaderFlags::F_BM32MAU)
    }
}

impl fmt::Debug for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let magic = match self.magic {
            MAGIC_WE32K | MAGIC_WE32K_TV => "WE32000",
            _ => "Unknown"
        };

        write!(f, "{}", magic)?;

        if self.executable() {
            write!(f, " executable")?;
        }

        if !self.local_symbols_stripped() {
            write!(f, " not stripped")?;
        }

        if self.is_32100_required() {
            write!(f, ", 32100 required")?;
        }

        if self.mau_required() {
            write!(f, ", MAU hardware required")?;
        }

        writeln!(f, ".")?;

        writeln!(f, "    Magic Number:    0x{:04x}", self.magic)?;
        writeln!(f, "    Num Sections:    {}", self.section_count)?;
        writeln!(f, "    Date:            {}", self.datetime.to_rfc2822())?;
        writeln!(f, "    Symbols Ptr:     0x{:x}", self.symbol_table_offset)?;
        writeln!(f, "    Symbol Count:    {}", self.symbol_count)?;
        writeln!(f, "    Opt Hdr:         {:?}", self.opt_header > 0)?;
        write!(f, "    Flags:           0x{:04x}", self.flags)
    }
}

// Only present in the file if the file header's opt_header == 0x1c (28 bytes)
pub struct OptionalHeader {
    pub magic: u16,
    pub version_stamp: u16,
    pub text_size: u32,
    pub dsize: u32,
    pub bsize: u32,
    pub entry_point: u32,
    pub text_start: u32,
    pub data_start: u32,
}

impl OptionalHeader {
    pub fn read(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let header = OptionalHeader {
            magic: cursor.read_u16::<BigEndian>()?,
            version_stamp: cursor.read_u16::<BigEndian>()?,
            text_size: cursor.read_u32::<BigEndian>()?,
            dsize: cursor.read_u32::<BigEndian>()?,
            bsize: cursor.read_u32::<BigEndian>()?,
            entry_point: cursor.read_u32::<BigEndian>()?,
            text_start: cursor.read_u32::<BigEndian>()?,
            data_start: cursor.read_u32::<BigEndian>()?
        };

        Ok(header)
    }
}

impl fmt::Debug for OptionalHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Optional Header:")?;
        writeln!(f, "    Magic Number:    0x{:04x}", self.magic)?;
        writeln!(f, "    Version Stamp:   0x{:04x}", self.version_stamp)?;
        writeln!(f, "    Text Size:       0x{:x}", self.text_size)?;
        writeln!(f, "    dsize:           0x{:x}", self.dsize)?;
        writeln!(f, "    bsize:           0x{:x}", self.bsize)?;
        writeln!(f, "    Entry Point:     0x{:x}", self.entry_point)?;
        writeln!(f, "    Text Start:      0x{:x}", self.text_start)?;
        write!(f, "    Data Start:      0x{:x}", self.data_start)
    }
}

pub struct SectionHeader {
    pub name: [u8; 8],
    pub paddr: u32,
    pub vaddr: u32,
    pub size: u32,
    pub scnptr: u32,
    pub relptr: u32,
    pub lnnoptr: u32,
    pub nreloc: u16,
    pub nlnno: u16,
    pub flags: u32,
}

impl SectionHeader {
    pub fn read(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let mut name: [u8; 8] = [0; 8];
        cursor.read_exact(&mut name)?;

        let header = SectionHeader {
            name,
            paddr: cursor.read_u32::<BigEndian>()?,
            vaddr: cursor.read_u32::<BigEndian>()?,
            size: cursor.read_u32::<BigEndian>()?,
            scnptr: cursor.read_u32::<BigEndian>()?,
            relptr: cursor.read_u32::<BigEndian>()?,
            lnnoptr: cursor.read_u32::<BigEndian>()?,
            nreloc: cursor.read_u16::<BigEndian>()?,
            nlnno: cursor.read_u16::<BigEndian>()?,
            flags: cursor.read_u32::<BigEndian>()?,
        };

        Ok(header)
    }
}

impl fmt::Debug for SectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = buf_to_str(&self.name).unwrap_or("???");

        writeln!(f, "Section Header:")?;
        writeln!(f, "    Name:              {}", name)?;
        writeln!(f, "    Phys. Addr:        0x{:x}", self.paddr)?;
        writeln!(f, "    Virtual Addr:      0x{:x}", self.vaddr)?;
        writeln!(f, "    Sec. Size:         0x{:x}", self.size)?;
        writeln!(f, "    Data Offset:       0x{:x}", self.scnptr)?;
        writeln!(f, "    Rel. Tab. Offset:  0x{:x}", self.relptr)?;
        writeln!(f, "    Line Num. Offset:  0x{:x}", self.lnnoptr)?;
        writeln!(f, "    Rel. Tab. Entries: {}", self.nreloc)?;
        writeln!(f, "    Line Num. Entries: {}", self.nlnno)?;
        write!(f, "    Flags:             0x{:08x}", self.flags)
    }
}

/// Representation of a Relocation Table Entry
#[derive(Eq, PartialEq)]
pub struct RelocationEntry {
    pub vaddr: u32,
    pub symndx: u32,
    pub rtype: u16,
}

impl fmt::Debug for RelocationEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[vaddr=0x{:08x} symndx={}, rtype={}]", self.vaddr, self.symndx, self.rtype)
    }
}

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum StorageClass {
    EndOfFunction,
    Null,
    Auto,
    ExternalSym,
    Static,
    Register,
    ExternalDef,
    Label,
    UndefinedLabel,
    MemberOfStruct,
    FunctionArg,
    StructureTag,
    MemberOfUnion,
    UnionTag,
    TypeDefinition,
    UninitializedStatic,
    EnumerationTag,
    MemberOfEnumeration,
    RegisterParameter,
    BitField,
    BeginEndBlock,
    BeginEndFunc,
    EndOfStruct,
    Filename,
    Line,
    Alias,
    Hidden,
}

impl fmt::Debug for StorageClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StorageClass::EndOfFunction => write!(f, "end of function"),
            StorageClass::Null => write!(f, "null"),
            StorageClass::Auto => write!(f, "automatic variable"),
            StorageClass::ExternalSym => write!(f, "external symbol"),
            StorageClass::Static => write!(f, "static"),
            StorageClass::Register => write!(f, "register variable"),
            StorageClass::ExternalDef => write!(f, "external definition"),
            StorageClass::Label => write!(f, "label"),
            StorageClass::UndefinedLabel => write!(f, "undefined label"),
            StorageClass::MemberOfStruct => write!(f, "member of structure"),
            StorageClass::FunctionArg => write!(f, "function argument"),
            StorageClass::StructureTag => write!(f, "structure tag"),
            StorageClass::MemberOfUnion => write!(f, "member of union"),
            StorageClass::UnionTag => write!(f, "union tag"),
            StorageClass::TypeDefinition => write!(f, "type definition"),
            StorageClass::UninitializedStatic => write!(f, "uninitialized static"),
            StorageClass::EnumerationTag => write!(f, "enumeration tag"),
            StorageClass::MemberOfEnumeration => write!(f, "member of enumeration"),
            StorageClass::RegisterParameter => write!(f, "register parameter"),
            StorageClass::BitField => write!(f, "bit field"),
            StorageClass::BeginEndBlock => write!(f, "beginning and end of block"),
            StorageClass::BeginEndFunc => write!(f, "beginning and end of function"),
            StorageClass::EndOfStruct => write!(f, "end of structure"),
            StorageClass::Filename => write!(f, "filename"),
            StorageClass::Line => write!(f, "line"),
            StorageClass::Alias => write!(f, "duplicated tag"),
            StorageClass::Hidden => write!(f, "hidden"),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimarySymbol {
    pub n_name: [u8; SYM_NAME_LEN],
    pub n_zeroes: u32, // may also be n_nptr[0] for overlaying
    pub n_offset: u32, // may also be n_nptr[1] for overlaying
    pub n_value: u32,
    pub n_scnum: i16,
    pub n_type: u16,
    pub n_numaux: u8,
    pub storage_class: StorageClass,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AuxiliarySymbol {
    pub x_fname: Option<String>,
    pub x_tagndx: u32,
    pub x_lnno: u16,        // Decl. line number
    pub x_size: u16,        // Str, union, array size
    pub x_fsize: u32,       // Size of function
    pub x_lnnoptr: u32,     // Ptr to fcn line #
    pub x_endndx: u32,      // Entry ndx past block end
    pub x_dimen: [u16; 4],  // Up to 4 array dimen.
    pub x_tvndx: u16,       // TV index
}

#[derive(Debug, Eq, PartialEq)]
pub struct SymbolTableEntry {
    pub primary: PrimarySymbol,
    pub aux: Vec<AuxiliarySymbol>,
}

///
/// A symbol table entry is a collection of entries, all related to a primary entry.
///
impl SymbolTableEntry {
    pub fn len(&self) -> usize {
        1 + self.aux.len()
    }

    pub fn read_entry(cursor: &mut Cursor<&[u8]>) -> io::Result<SymbolTableEntry> {
        let mut raw_data: [u8; 18] = [0; 18];

        cursor.read_exact(&mut raw_data)?;

        let mut n_name: [u8; SYM_NAME_LEN] = Default::default();
        n_name.copy_from_slice(&raw_data[0..8]);
        let n_zeroes = (&raw_data[0..4]).read_u32::<BigEndian>()?;
        let n_offset = (&raw_data[4..8]).read_u32::<BigEndian>()?;
        let n_value = (&raw_data[8..12]).read_u32::<BigEndian>()?;
        let n_scnum = (&raw_data[12..14]).read_i16::<BigEndian>()?;
        let n_type = (&raw_data[14..16]).read_u16::<BigEndian>()?;
        let n_sclass = raw_data[16] as i8;
        let n_numaux = raw_data[17];

        let storage_class = match n_sclass {
            -1 => StorageClass::EndOfFunction,
            1 => StorageClass::Auto,
            2 => StorageClass::ExternalSym,
            3 => StorageClass::Static,
            4 => StorageClass::Register,
            5 => StorageClass::ExternalDef,
            6 => StorageClass::Label,
            7 => StorageClass::UndefinedLabel,
            8 => StorageClass::MemberOfStruct,
            9 => StorageClass::FunctionArg,
            10 => StorageClass::StructureTag,
            11 => StorageClass::MemberOfUnion,
            12 => StorageClass::UnionTag,
            13 => StorageClass::TypeDefinition,
            14 => StorageClass::UninitializedStatic,
            15 => StorageClass::EnumerationTag,
            16 => StorageClass::MemberOfEnumeration,
            17 => StorageClass::RegisterParameter,
            18 => StorageClass::BitField,
            100 => StorageClass::BeginEndBlock,
            101 => StorageClass::BeginEndFunc,
            102 => StorageClass::EndOfStruct,
            103 => StorageClass::Filename,
            104 => StorageClass::Line,
            105 => StorageClass::Alias,
            106 => StorageClass::Hidden,
            _ => StorageClass::Null,
        };

        let primary = PrimarySymbol {
            n_name,
            n_zeroes,
            n_offset,
            n_value,
            n_scnum,
            n_type,
            n_numaux,
            storage_class,
        };

        let mut aux = Vec::new();

        for _ in 0..n_numaux {
            cursor.read_exact(&mut raw_data)?;

            let mut x_dimen: [u16; 4] = Default::default();

            let x_fname = match storage_class {
                StorageClass::Filename => {
                    Some(buf_to_str(&raw_data[0..14]).unwrap_or("???").to_owned())
                },
                _ => None
            };

            let x_tagndx = (&raw_data[0..4]).read_u32::<BigEndian>()?;
            let x_lnno = (&raw_data[4..6]).read_u16::<BigEndian>()?;
            let x_size = (&raw_data[6..8]).read_u16::<BigEndian>()?;
            let x_fsize = (&raw_data[4..8]).read_u32::<BigEndian>()?;
            let x_lnnoptr = (&raw_data[8..12]).read_u32::<BigEndian>()?;
            let x_endndx = (&raw_data[12..16]).read_u32::<BigEndian>()?;
            x_dimen[0] = (&raw_data[8..10]).read_u16::<BigEndian>()?;
            x_dimen[1] = (&raw_data[10..12]).read_u16::<BigEndian>()?;
            x_dimen[2] = (&raw_data[12..14]).read_u16::<BigEndian>()?;
            x_dimen[3] = (&raw_data[14..16]).read_u16::<BigEndian>()?;
            let x_tvndx = (&raw_data[16..18]).read_u16::<BigEndian>()?;

            aux.push(AuxiliarySymbol {
                x_fname,
                x_tagndx,
                x_lnno,
                x_size,
                x_fsize,
                x_lnnoptr,
                x_endndx,
                x_dimen,
                x_tvndx,
            });
        }

        Ok(SymbolTableEntry {
            primary,
            aux,
        })
    }
}

pub struct StringTable {
    pub data: Vec<u8>,
    pub data_size: u32,
    pub strings: HashMap<u32, String>,
}

impl StringTable {
    pub fn read(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let mut data: Vec<u8> = vec!();

        // The first four bytes of data are ALWAYS zeroed.
        let mut pad: Vec<u8> = vec!(0, 0, 0, 0);
        data.append(&mut pad);

        // ... and therefore, the string start index is always
        // initialized to 4.
        let mut i: usize = 4;

        // Denormalize the strings as we parse them.
        let mut strings = HashMap::new();

        // Get the size of data we're expected to read
        let data_size = cursor.read_u32::<BigEndian>()?;

        for j in 4..data_size as usize {
            let c = cursor.read_u8()?;
            data.push(c);
            if c == 0 {
                // Push from the last start to here.
                let s = buf_to_str(&data[i..j]).unwrap_or("???");
                strings.insert(i as u32, s.to_owned());
                i = j + 1usize;
            }
        }

        let table = StringTable {
            data,
            data_size,
            strings,
        };

        Ok(table)
    }

    pub fn string_at(&self, index: u32) -> Option<String> {
        self.strings.get(&index).cloned()
    }
}

pub struct Section {
    pub name: String,
    pub header: SectionHeader,
    pub relocation_table: Vec<RelocationEntry>,
    pub data: Vec<u8>,
}

pub struct FileContainer {
    pub header: FileHeader,
    pub opt_header: Option<OptionalHeader>,
    pub sections: Vec<Section>,
    pub symbols: Vec<SymbolTableEntry>,
    pub strings: StringTable,
}

impl FileContainer {
    ///
    /// Read in and destructure a WE32100 COFF file.
    ///

    fn bad_metadata(header: &FileHeader) -> bool {
        !(header.magic == MAGIC_WE32K || header.magic == MAGIC_WE32K_TV)
    }

    fn read_sections(file_header: &FileHeader, cursor: &mut Cursor<&[u8]>) -> io::Result<Vec<Section>> {
        let mut section_headers: Vec<SectionHeader> = vec!();

        // Read the section headers
        for _ in 0..file_header.section_count {
            section_headers.push(SectionHeader::read(cursor)?);
        }

        // Build up the section structures
        let mut sections: Vec<Section> = vec!();

        for header in section_headers {
            let mut relocation_table: Vec<RelocationEntry> = vec!();
            let mut data: Vec<u8> = vec!();

            // Get relocation information
            if header.nreloc > 0 {
                cursor.seek(SeekFrom::Start(u64::from(header.relptr)))?;

                for _ in 0..header.nreloc {
                    let entry = RelocationEntry {
                        vaddr: cursor.read_u32::<BigEndian>()?,
                        symndx: cursor.read_u32::<BigEndian>()?,
                        rtype: cursor.read_u16::<BigEndian>()?,
                    };
                    relocation_table.push(entry);
                }
            }

            // Get data
            if header.size > 0 {
                cursor.seek(SeekFrom::Start(u64::from(header.scnptr)))?;

                for _ in 0..header.size {
                    data.push(cursor.read_u8()?);
                }
            }

            // Done with this section.
            let section = Section {
                name: buf_to_str(&header.name).unwrap_or("???").to_owned(),
                header,
                relocation_table,
                data,
            };

            sections.push(section);
        }

        Ok(sections)
    }

    fn read_symbol_table(header: &FileHeader, cursor: &mut Cursor<&[u8]>) -> io::Result<Vec<SymbolTableEntry>> {
        let mut symbols: Vec<SymbolTableEntry> = vec!();

        if header.symbol_count > 0 {
            cursor.seek(SeekFrom::Start(u64::from(header.symbol_table_offset)))?;

            let mut index: usize = 0;

            while index < header.symbol_count as usize {
                let entry: SymbolTableEntry = SymbolTableEntry::read_entry(cursor)?;
                index += entry.len();
                symbols.push(entry);
            }
        }

        Ok(symbols)
    }

    ///
    /// Consume the buffer
    ///
    pub fn read(buf: &[u8]) -> ReadResult<Self> {
        let mut cursor = Cursor::new(buf);

        // Read the file header.
        let header = match FileHeader::read(&mut cursor) {
            Ok(h) => {
                if FileContainer::bad_metadata(&h) {
                    return Err(CoffError::BadFileHeader)
                } else {
                    h
                }
            },
            Err(_) => return Err(CoffError::BadFileHeader)
        };

        // If an optional header is indicated in the file header, read
        // it.
        let opt_header = if header.opt_header > 0 {
            match OptionalHeader::read(&mut cursor) {
                Ok(h) => Some(h),
                Err(_) => return Err(CoffError::BadOptionalHeader)
            }
        } else {
            None
        };

        // Now we have to seek to the sections area.
        if let Err(_) = cursor.seek(SeekFrom::Start(u64::from(FILE_HEADER_SIZE + header.opt_header))) {
            return Err(CoffError::BadSections)
        }

        // Read sections
        let sections = match FileContainer::read_sections(&header, &mut cursor) {
            Ok(s) => s,
            Err(_) => return Err(CoffError::BadSections)
        };

        // Load symbols
        let symbols = match FileContainer::read_symbol_table(&header, &mut cursor) {
            Ok(s) => s,
            Err(_) => return Err(CoffError::BadSymbols)
        };

        // The cursor is now at the correct position to read string entries.
        let strings = match StringTable::read(&mut cursor) {
            Ok(s) => s,
            Err(_) => return Err(CoffError::BadStrings)
        };

        let container = FileContainer {
            header,
            opt_header,
            sections,
            symbols,
            strings,
        };

        Ok(container)
    }

    ///
    /// Dump relocation table from the specified section to stdout.
    ///

    pub fn dump_relocation_table(&self, sec_num: usize) -> Result<(), OffsetError> {
        if self.sections.len() == 0 || sec_num > (self.sections.len() - 1) {
            return Err(OffsetError)
        }

        let section = &self.sections[sec_num];

        println!("    Relocation Table:");

        // If there is relocation data, let's dump that too.
        if section.relocation_table.len() > 0 {
            println!("        Num    Vaddr       Symndx  Type");
            println!("        -----  ----------  ------  ----");
            for (i, entry) in section.relocation_table.iter().enumerate() {
                println!("        [{:03}]  0x{:08x}  {:6}  {:3}",
                         i,  entry.vaddr, entry.symndx, entry.rtype);
            }
        } else {
            println!("       No Entries.")
        }

        return Ok(())
    }

    ///
    /// Dump section data from the specified section to stdout.
    ///
    pub fn dump_section_data(&self, sec_num: usize) -> Result<(), OffsetError> {
        if self.sections.len() == 0 || sec_num > (self.sections.len() - 1) {
            return Err(OffsetError)
        }

        let section = &self.sections[sec_num];
        let header = &section.header;
        let sec_name = buf_to_str(&header.name).unwrap_or("???");

        println!("    Section Data (number {}, name {}):", sec_num, sec_name);

        if section.data.len() == 0 {
            println!("        No Data.");
            return Ok(())
        }

        // Make a cute little array for our read data.
        let mut row_bytes: [u8; 16] = [0; 16];
        let end = section.data.len() - 1;

        for (i, b) in section.data.iter().enumerate() {
            row_bytes[i % 16] = *b;

            if i % 16 == 0 {
                let vaddr = header.vaddr + i as u32;
                print!("        {:08x}:   ", vaddr);
            }

            print!("{:02x} ", b);

            if (i + 1) % 8 == 0 && (i + 1) % 16 != 0 {
                print!("  ");
            }

            // If we need to end a line, it's time to print the
            // human-readable summary.

            if (i + 1) % 16 == 0 || i == end {

                // How many empty characters do we need to pad out
                // before the summary?
                let spaces = if i == end {
                    15 - (end % 16)
                } else {
                    0
                };

                for _ in 0..spaces {
                    print!("   ");
                }

                if spaces > 8 {
                    print!("  ");
                }

                print!("  | ");

                for (x, c) in row_bytes.iter().enumerate() {
                    if x < (16 - spaces) as usize {
                        let printable = if *c >= 0x20 && *c < 0x7f {
                            *c as char
                        } else {
                            b'.' as char
                        };
                        print!("{}", printable);
                    } else {
                        print!(" ");
                    }
                }

                println!(" |");
            }
        }

        Ok(())
    }

    ///
    /// Dump section data from the specified section to stdout.
    ///
    pub fn dump_symbol_table(&self) {
        println!("Symbol Table:");

        let symbols = &self.symbols;

        if symbols.is_empty() {
            println!("    No Entries");
            return;
        }

        let mut index = 0;

        println!("[");

        for entry in symbols {

            let primary = &entry.primary;
            let aux = &entry.aux;

            let name = if primary.n_zeroes == 0 {
                self.strings.string_at(primary.n_offset).unwrap_or("???".to_owned())
            } else {
                buf_to_str(&primary.n_name).unwrap_or("???").to_owned()
            };

            println!("    {{");
            println!("        index: {},", index);
            println!("        name: '{}',", name);
            println!("        value: '0x{:x}',", primary.n_value);
            println!("        section: {},", primary.n_scnum);
            println!("        type: '0x{:02x}',", primary.n_type);
            println!("        class: '{:?}',", primary.storage_class);
            println!("        numaux: {}", primary.n_numaux);
            println!("    }},");

            index += 1;

            if !aux.is_empty() {
                for aux_sym in aux {
                    println!("    {{");
                    println!("        index: {},", index);
                    if aux_sym.x_fname.is_some() {
                        println!("        filename: '{}',", aux_sym.x_fname.as_ref().unwrap());
                    } else {
                        println!("        tagindex: {},", aux_sym.x_tagndx);
                        println!("        lnno: '0x{:x}',", aux_sym.x_lnno);
                        println!("        size: '0x{:x}',", aux_sym.x_size);
                        println!("        fsize: '0x{:x}',", aux_sym.x_fsize);
                    }
                    println!("        lnnoptr: '0x{:x}',", aux_sym.x_lnnoptr);
                    println!("        endndx: {},", aux_sym.x_endndx);
                    println!("        dim0: {},", aux_sym.x_dimen[0]);
                    println!("        dim1: {},", aux_sym.x_dimen[1]);
                    println!("        tvndx: {}", aux_sym.x_tvndx);
                    println!("    }},");

                    index += 1;
                }
            }
        }

        println!("]");
    }

    pub fn dump_strings_table(&self) {
        println!("Strings Table:");

        let strings = &self.strings;

        if strings.strings.len() > 0 {
            // Strings are kept in an unsorted hash map, so they should
            // be sorted before printing out.
            let mut keys: Vec<&u32> = strings.strings.keys().collect();
            keys.sort();
            for key in keys.iter() {
                if let Some(val) = &strings.strings.get(key) {
                    println!("    [{:4}]    {}", key, val);
                }
            }
        } else {
            println!("    No Strings");
        }
    }


    fn symbol_name(&self, primary: &PrimarySymbol) -> String {
        if primary.n_zeroes == 0 {
            self.strings.string_at(primary.n_offset).unwrap_or("???".to_owned())
        } else {
            buf_to_str(&primary.n_name).unwrap_or("???").to_owned()
        }
    }

    fn func_symbol(&self, pc: u32) -> Option<&SymbolTableEntry> {
        for entry in &self.symbols {
            match entry.primary.storage_class {
                StorageClass::ExternalSym => {
                    if entry.primary.n_value == pc {
                        return Some(&entry)
                    }
                },
                _ => {}
            }
        }

        None
    }

    pub fn disassemble_named_section(&self, name: &str) {
        for section in &self.sections {
            if section.name == name {
                println!("section {}", name);
                let pc = section.header.vaddr;
                let decoder = Decoder::new(&section.data, pc, &self.symbols, &section.relocation_table);

                for instruction in decoder {
                    if let Some(e) = self.func_symbol(instruction.pc) {
                        println!("{}()", self.symbol_name(&e.primary))
                    }
                    print!("        {}", instruction);
                    for (i, op) in instruction.operands.iter().enumerate() {
                        if let Some(reloc) = &op.relocation {
                            let primary = &reloc.symbol_table_entry.primary;
                            let symbol_name = self.symbol_name(primary);
                            print!(" [{}={}", i, symbol_name);
                            match primary.storage_class {
                                StorageClass::ExternalSym => {
                                    if primary.n_type == 0x24 {
                                        print!("()")
                                    }
                                },
                                StorageClass::Static => {
                                    if let Some(aux) = &reloc.symbol_table_entry.aux.get(0) {
                                        if let Some(s) = self.strings.strings.get(&aux.x_tagndx) {
                                            print!(" <{}>", s);
                                        } else {
                                            if let Some(static_data) = self.symbols
                                                .iter()
                                                .find(|s| s.primary.n_value == op.embedded) {
                                                let name = self.symbol_name(&static_data.primary);
                                                print!(" <{}>", name);
                                            } else {
                                                // Is this a string in the data table?
                                                if symbol_name == ".data" {
                                                    if let Some(data_section) = self.sections.iter().find(|s| s.name == ".data") {
                                                        let offset = op.embedded as usize - data_section.header.vaddr as usize;
                                                        if let Ok(s) = buf_to_str(&data_section.data[offset..]) {
                                                            print!(" <'{}'>", s);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                            print!("]");
                        }
                    }
                    println!();
                }
            }
        }
    }
}
