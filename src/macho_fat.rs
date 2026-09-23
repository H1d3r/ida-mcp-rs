//! Universal (fat) Mach-O inputs: detect them, name their slices, and copy one
//! slice out as a standalone Mach-O for IDA to load.
//!
//! IDA 9.4's idalib cannot choose a fat slice (it rejects the `-T` switch), its
//! Mach-O loader silently prefers x86_64 over ARM slices, and it does not
//! recognize 64-bit fat headers at all. Extracting the requested slice makes
//! the choice explicit and independent of IDA's loader selection.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use tracing::warn;

use crate::error::ToolError;

const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// Java class files share `FAT_MAGIC`. The field a fat header uses for its
/// slice count holds a class file's major version there, which is at least 45.
const JAVA_CLASS_MIN_MAJOR: u32 = 45;
const FAT_ARCH_SIZE: usize = 20;
const FAT_ARCH_64_SIZE: usize = 32;
/// Covers the largest slice table a non-Java fat header can declare.
const FAT_HEADER_READ_LIMIT: u64 = 8 + JAVA_CLASS_MIN_MAJOR as u64 * FAT_ARCH_64_SIZE as u64;
/// Copy buffer for slice extraction; std's 8 KiB default means thousands of
/// syscalls per slice on platforms without kernel copy offload.
const COPY_BUFFER_BYTES: usize = 1 << 20;

const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;

const CPU_ARCH_ABI64: i32 = 0x0100_0000;
const CPU_ARCH_ABI64_32: i32 = 0x0200_0000;
const CPU_TYPE_X86: i32 = 7;
const CPU_TYPE_X86_64: i32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
const CPU_TYPE_ARM: i32 = 12;
const CPU_TYPE_ARM64: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
const CPU_TYPE_ARM64_32: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32;
const CPU_TYPE_POWERPC: i32 = 18;
const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;
/// Feature-flag bits (for example arm64e's pointer-authentication ABI) that do
/// not change which architecture a subtype names.
const CPU_SUBTYPE_FEATURE_MASK: u32 = 0xff00_0000;

/// One architecture slice inside a universal Mach-O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatSlice {
    /// `lipo`-style architecture name, e.g. `arm64e` or `x86_64`.
    pub arch: String,
    pub offset: u64,
    pub size: u64,
}

/// Name a Mach-O CPU type/subtype pair the way `lipo` does.
///
/// Pairs outside the table get a `cputype0x…-subtype0x…` name, which is still
/// unique within a file and accepted by [`select_slice`].
fn arch_name(cputype: i32, cpusubtype: i32) -> String {
    let subtype = cpusubtype.cast_unsigned() & !CPU_SUBTYPE_FEATURE_MASK;
    let known = match (cputype, subtype) {
        (CPU_TYPE_X86, 3) => Some("i386"),
        (CPU_TYPE_X86_64, 3) => Some("x86_64"),
        (CPU_TYPE_X86_64, 8) => Some("x86_64h"),
        (CPU_TYPE_ARM, 6) => Some("armv6"),
        (CPU_TYPE_ARM, 9) => Some("armv7"),
        (CPU_TYPE_ARM, 11) => Some("armv7s"),
        (CPU_TYPE_ARM, 12) => Some("armv7k"),
        (CPU_TYPE_ARM64, 0) => Some("arm64"),
        (CPU_TYPE_ARM64, 2) => Some("arm64e"),
        (CPU_TYPE_ARM64, 12) => Some("arm64e.x1"),
        (CPU_TYPE_ARM64_32, 0 | 1) => Some("arm64_32"),
        (CPU_TYPE_POWERPC, 0) => Some("ppc"),
        (CPU_TYPE_POWERPC64, 0) => Some("ppc64"),
        _ => None,
    };
    known.map_or_else(
        || format!("cputype{cputype:#x}-subtype{cpusubtype:#x}"),
        str::to_string,
    )
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let field = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes(field.try_into().ok()?))
}

fn be_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let field = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_be_bytes(field.try_into().ok()?))
}

/// Parse the fat header at the start of a file.
///
/// `header` holds the file's first bytes and `file_len` its full length.
/// Returns `Ok(None)` for anything that is not a fat Mach-O, Java class files
/// included, and an error when a fat header's slice table is truncated, points
/// outside the file, or lists an architecture twice (which `lipo` refuses).
fn parse_fat_header(header: &[u8], file_len: u64) -> Result<Option<Vec<FatSlice>>, String> {
    let Some(magic) = be_u32(header, 0) else {
        return Ok(None);
    };
    let entry_size = match magic {
        FAT_MAGIC => FAT_ARCH_SIZE,
        FAT_MAGIC_64 => FAT_ARCH_64_SIZE,
        _ => return Ok(None),
    };
    let Some(count) = be_u32(header, 4) else {
        return Ok(None);
    };
    if count == 0 || count >= JAVA_CLASS_MIN_MAJOR {
        return Ok(None);
    }
    let count = usize::try_from(count).map_err(|_| "fat slice count overflows".to_string())?;
    let table_end = 8 + count * entry_size;
    if header.len() < table_end {
        return Err(format!(
            "fat header declares {count} slices but the file ends inside the slice table"
        ));
    }

    let mut slices: Vec<FatSlice> = Vec::with_capacity(count);
    for index in 0..count {
        let (cputype, cpusubtype, offset, size) =
            parse_fat_arch(header, 8 + index * entry_size, magic == FAT_MAGIC_64)
                .ok_or_else(|| format!("fat slice {} entry is truncated", index + 1))?;
        let arch = arch_name(cputype, cpusubtype);
        let end = offset.checked_add(size);
        if size == 0 || offset < table_end as u64 || end.is_none_or(|end| end > file_len) {
            return Err(format!(
                "fat slice {} ({arch}) spans {offset:#x}+{size:#x}, outside the {file_len}-byte file",
                index + 1,
            ));
        }
        if slices.iter().any(|slice| slice.arch == arch) {
            return Err(format!("fat header lists {arch} twice"));
        }
        slices.push(FatSlice { arch, offset, size });
    }
    Ok(Some(slices))
}

fn parse_fat_arch(header: &[u8], at: usize, wide: bool) -> Option<(i32, i32, u64, u64)> {
    let cputype = be_u32(header, at)?.cast_signed();
    let cpusubtype = be_u32(header, at + 4)?.cast_signed();
    let (offset, size) = if wide {
        (be_u64(header, at + 8)?, be_u64(header, at + 16)?)
    } else {
        (
            u64::from(be_u32(header, at + 8)?),
            u64::from(be_u32(header, at + 12)?),
        )
    };
    Some((cputype, cpusubtype, offset, size))
}

/// Architecture of a single-architecture Mach-O, or `None` if `header` does
/// not start with a Mach-O header.
fn thin_arch(header: &[u8]) -> Option<String> {
    let magic = be_u32(header, 0)?;
    let swap = match (magic, magic.swap_bytes()) {
        (MH_MAGIC | MH_MAGIC_64, _) => false,
        (_, MH_MAGIC | MH_MAGIC_64) => true,
        _ => return None,
    };
    let field = |at| {
        be_u32(header, at)
            .map(|value| if swap { value.swap_bytes() } else { value })
            .map(u32::cast_signed)
    };
    Some(arch_name(field(4)?, field(8)?))
}

/// Read a file's first bytes, up to `limit`.
fn read_prefix(file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
    let mut prefix = Vec::new();
    file.take(limit).read_to_end(&mut prefix)?;
    Ok(prefix)
}

/// What an input file is, as far as slice selection is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachOKind {
    /// A universal Mach-O with at least one slice.
    Universal(Vec<FatSlice>),
    /// A single-architecture Mach-O of the named architecture.
    Thin(String),
    /// Anything else, including files that could not be read; the open path
    /// reports those the same way it always has.
    Other,
}

/// Classify `path` and validate a universal file's slice table.
///
/// Every slice must itself start with a Mach-O header, which also rules out
/// Java class files that happen to pass the header checks.
pub fn inspect(path: &Path) -> Result<MachOKind, ToolError> {
    let Ok(mut file) = File::open(path) else {
        return Ok(MachOKind::Other);
    };
    let Ok(file_len) = file.metadata().map(|meta| meta.len()) else {
        return Ok(MachOKind::Other);
    };
    let header = read_prefix(&mut file, FAT_HEADER_READ_LIMIT).map_err(|error| {
        ToolError::OpenFailed(format!("{}: reading header: {error}", path.display()))
    })?;
    let slices = match parse_fat_header(&header, file_len) {
        Ok(Some(slices)) => slices,
        Ok(None) => return Ok(thin_arch(&header).map_or(MachOKind::Other, MachOKind::Thin)),
        Err(reason) => {
            return Err(ToolError::InvalidParams(format!(
                "{} is a malformed universal Mach-O: {reason}",
                path.display()
            )));
        }
    };
    for (index, slice) in slices.iter().enumerate() {
        file.seek(SeekFrom::Start(slice.offset))
            .and_then(|_| read_prefix(&mut file, 12))
            .ok()
            .and_then(|prefix| thin_arch(&prefix))
            .ok_or_else(|| {
                ToolError::InvalidParams(format!(
                    "{} is a malformed universal Mach-O: slice {} ({}) at {:#x} is not a \
                     Mach-O image",
                    path.display(),
                    index + 1,
                    slice.arch,
                    slice.offset
                ))
            })?;
    }
    Ok(MachOKind::Universal(slices))
}

/// Comma-separated slice names, for prompts and errors.
pub fn slice_names(slices: &[FatSlice]) -> String {
    slices
        .iter()
        .map(|slice| slice.arch.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The slice named `arch` (case-insensitive). Names are unique per file.
pub fn select_slice<'a>(slices: &'a [FatSlice], arch: &str) -> Option<&'a FatSlice> {
    let wanted = arch.trim();
    slices
        .iter()
        .find(|slice| slice.arch.eq_ignore_ascii_case(wanted))
}

/// Where the extracted slice for `input` is written: next to the output
/// database when `idb_out` is set, otherwise next to the input, named
/// `<input file name>.<arch>`.
pub fn slice_path(input: &Path, idb_out: Option<&Path>, arch: &str) -> Option<PathBuf> {
    let mut name = input.file_name()?.to_os_string();
    name.push(".");
    name.push(arch);
    let dir = match idb_out {
        Some(out) => out.parent()?,
        None => input.parent()?,
    };
    Some(dir.join(name))
}

/// Outcome of [`extract_slice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceFile {
    Created,
    /// An identical copy was already present.
    Reused,
}

/// Copy `slice` out of `input` into `dest`.
///
/// An existing `dest` with identical bytes is reused. One with different
/// bytes is never overwritten: nothing proves it is an earlier extraction
/// rather than someone's own file, so the caller must remove or relocate it.
///
/// The slice is written to an exclusively created temporary file and then
/// published with a hard link, which fails instead of replacing a `dest` that
/// appeared meanwhile (another publisher, or anyone else). A filesystem that
/// cannot hard-link is an error; there is no fallback that could overwrite.
pub fn extract_slice(input: &Path, slice: &FatSlice, dest: &Path) -> Result<SliceFile, ToolError> {
    extract_slice_with(input, slice, dest, |original, link| {
        fs::hard_link(original, link)
    })
}

/// [`extract_slice`] with the publishing link supplied by the caller, so
/// tests can reproduce a lost race or a filesystem without hard links.
fn extract_slice_with(
    input: &Path,
    slice: &FatSlice,
    dest: &Path,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<SliceFile, ToolError> {
    match fs::metadata(dest) {
        Ok(_) => return existing_slice(input, slice, dest),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(slice_io_error("inspecting", input, slice, dest, &error)),
    }

    let mut partial = dest.as_os_str().to_os_string();
    partial.push(format!(".partial-{}", uuid::Uuid::new_v4().simple()));
    let partial = PathBuf::from(partial);
    // Only a file this call created may be removed below; if the name were
    // somehow taken, fail without touching it.
    let file = File::options()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| slice_io_error("creating", input, slice, &partial, &error))?;

    let published = match write_slice(file, input, slice) {
        Err(error) => Err(slice_io_error("writing", input, slice, &partial, &error)),
        Ok(()) => match link(&partial, dest) {
            Ok(()) => Ok(SliceFile::Created),
            // Another publisher got there first; judge its file like one
            // that already existed.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                existing_slice(input, slice, dest)
            }
            Err(error) => Err(ToolError::OpenFailed(format!(
                "cannot publish the {} slice of {} at {}: the filesystem refused a hard link \
                 ({error}); choose an idb_out directory on a filesystem that supports hard links",
                slice.arch,
                input.display(),
                dest.display()
            ))),
        },
    };
    if let Err(error) = fs::remove_file(&partial)
        && error.kind() != io::ErrorKind::NotFound
    {
        warn!(path = %partial.display(), %error, "failed to remove partial slice file");
    }
    published
}

/// Reuse an identical `dest`, or refuse to touch a different one.
fn existing_slice(input: &Path, slice: &FatSlice, dest: &Path) -> Result<SliceFile, ToolError> {
    let comparing = |error: io::Error| slice_io_error("comparing", input, slice, dest, &error);
    let identical = fs::metadata(dest).map_err(comparing)?.len() == slice.size
        && slice_matches(input, slice, dest).map_err(comparing)?;
    if identical {
        return Ok(SliceFile::Reused);
    }
    Err(ToolError::InvalidParams(format!(
        "{} already exists and differs from the {} slice of {}; delete it or choose an \
         idb_out in another directory",
        dest.display(),
        slice.arch,
        input.display()
    )))
}

fn slice_io_error(
    action: &str,
    input: &Path,
    slice: &FatSlice,
    path: &Path,
    error: &io::Error,
) -> ToolError {
    ToolError::OpenFailed(format!(
        "{action} {} slice of {} at {}: {error}",
        slice.arch,
        input.display(),
        path.display()
    ))
}

/// Copy the slice bytes into `out` and flush them to disk.
fn write_slice(mut out: File, input: &Path, slice: &FatSlice) -> io::Result<()> {
    let mut source = File::open(input)?;
    source.seek(SeekFrom::Start(slice.offset))?;
    let mut source = BufReader::with_capacity(COPY_BUFFER_BYTES, source.take(slice.size));
    let copied = io::copy(&mut source, &mut out)?;
    if copied != slice.size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("input ended after {copied} of {} slice bytes", slice.size),
        ));
    }
    out.sync_all()
}

/// Compare `dest`, already known to be `slice.size` bytes, with the slice.
fn slice_matches(input: &Path, slice: &FatSlice, dest: &Path) -> io::Result<bool> {
    let mut source = File::open(input)?;
    source.seek(SeekFrom::Start(slice.offset))?;
    let mut source = source.take(slice.size);
    let mut existing = File::open(dest)?;
    let mut left = vec![0_u8; 64 * 1024];
    let mut right = vec![0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut left)?;
        if read == 0 {
            return Ok(true);
        }
        existing.read_exact(&mut right[..read])?;
        if left[..read] != right[..read] {
            return Ok(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use std::io;
    use std::sync::{Arc, Barrier};

    use crate::macho_fat::{
        arch_name, extract_slice, extract_slice_with, inspect, parse_fat_header, select_slice,
        slice_path, thin_arch, FatSlice, MachOKind, SliceFile,
    };

    const ARM64: (i32, i32) = (0x0100_000c, 0);
    const ARM64E: (i32, i32) = (0x0100_000c, 0x8000_0002_u32.cast_signed());
    const X86_64: (i32, i32) = (0x0100_0007, 3);

    fn thin_image((cputype, cpusubtype): (i32, i32), body: u8, len: usize) -> Vec<u8> {
        let mut image = vec![body; len.max(12)];
        image[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
        image[4..8].copy_from_slice(&cputype.to_le_bytes());
        image[8..12].copy_from_slice(&cpusubtype.to_le_bytes());
        image
    }

    /// Lay out slices at 0x1000-aligned offsets behind a fat header.
    fn fat_image(wide: bool, slices: &[((i32, i32), Vec<u8>)]) -> Vec<u8> {
        let magic: u32 = if wide { 0xcafe_babf } else { 0xcafe_babe };
        let count = u32::try_from(slices.len()).expect("slice count");
        let mut out = Vec::new();
        out.extend_from_slice(&magic.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        let mut offset = 0x1000_usize;
        let mut layout = Vec::new();
        for ((cputype, cpusubtype), data) in slices {
            layout.push((offset, data));
            let size = data.len();
            out.extend_from_slice(&cputype.to_be_bytes());
            out.extend_from_slice(&cpusubtype.to_be_bytes());
            if wide {
                out.extend_from_slice(&(offset as u64).to_be_bytes());
                out.extend_from_slice(&(size as u64).to_be_bytes());
                out.extend_from_slice(&12_u32.to_be_bytes());
                out.extend_from_slice(&0_u32.to_be_bytes());
            } else {
                out.extend_from_slice(&u32::try_from(offset).expect("offset").to_be_bytes());
                out.extend_from_slice(&u32::try_from(size).expect("size").to_be_bytes());
                out.extend_from_slice(&12_u32.to_be_bytes());
            }
            offset = (offset + size).next_multiple_of(0x1000);
        }
        for (at, data) in layout {
            out.resize(at, 0);
            out.extend_from_slice(data);
        }
        out
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ida-mcp-macho-fat-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn names_follow_lipo() {
        assert_eq!(arch_name(X86_64.0, X86_64.1), "x86_64");
        assert_eq!(arch_name(0x0100_0007, 8), "x86_64h");
        assert_eq!(arch_name(ARM64.0, ARM64.1), "arm64");
        assert_eq!(arch_name(ARM64E.0, ARM64E.1), "arm64e");
        assert_eq!(
            arch_name(0x0100_000c, 0x8000_000c_u32.cast_signed()),
            "arm64e.x1"
        );
        assert_eq!(arch_name(0x0200_000c, 1), "arm64_32");
        assert_eq!(arch_name(12, 12), "armv7k");
        assert_eq!(arch_name(0x77, 5), "cputype0x77-subtype0x5");
    }

    #[test]
    fn parses_both_header_widths_in_file_order() {
        for wide in [false, true] {
            let image = fat_image(
                wide,
                &[
                    (ARM64E, thin_image(ARM64E, 1, 64)),
                    (X86_64, thin_image(X86_64, 2, 32)),
                ],
            );
            let slices = parse_fat_header(&image, image.len() as u64)
                .expect("valid header")
                .expect("fat");
            let names: Vec<_> = slices.iter().map(|slice| slice.arch.as_str()).collect();
            assert_eq!(names, ["arm64e", "x86_64"], "wide={wide}");
            assert_eq!((slices[0].offset, slices[0].size), (0x1000, 64));
        }
    }

    #[test]
    fn non_fat_inputs_are_not_universal() {
        assert_eq!(parse_fat_header(&[], 0), Ok(None));
        assert_eq!(parse_fat_header(&[0xca, 0xfe], 2), Ok(None));
        let thin = thin_image(ARM64, 0, 64);
        assert_eq!(parse_fat_header(&thin, 64), Ok(None));
        // Java class file: CAFEBABE, minor 0, major 65.
        let java = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65, 0, 0];
        assert_eq!(parse_fat_header(&java, 10), Ok(None));
        let empty = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0];
        assert_eq!(parse_fat_header(&empty, 8), Ok(None));
    }

    #[test]
    fn rejects_slice_tables_that_do_not_fit_or_repeat() {
        let image = fat_image(false, &[(ARM64, thin_image(ARM64, 0, 64))]);
        let truncated_table = &image[..20];
        assert!(parse_fat_header(truncated_table, 20).is_err());
        let err = parse_fat_header(&image, image.len() as u64 - 1).expect_err("slice past EOF");
        assert!(err.contains("outside"), "{err}");

        let mut overlapping = image.clone();
        overlapping[16..20].copy_from_slice(&4_u32.to_be_bytes());
        assert!(parse_fat_header(&overlapping, image.len() as u64).is_err());

        let mut huge = fat_image(true, &[(ARM64, thin_image(ARM64, 0, 64))]);
        huge[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(parse_fat_header(&huge, huge.len() as u64).is_err());

        let twins = fat_image(
            false,
            &[
                (ARM64, thin_image(ARM64, 0, 64)),
                (ARM64, thin_image(ARM64, 1, 64)),
            ],
        );
        let err = parse_fat_header(&twins, twins.len() as u64).expect_err("duplicate arch");
        assert!(err.contains("arm64 twice"), "{err}");
    }

    #[test]
    fn arbitrary_headers_never_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = usize::try_from(state % 96).expect("small");
            let mut bytes: Vec<u8> = (0..len)
                .map(|i| state.rotate_left(u32::try_from(i % 64).expect("small")) as u8)
                .collect();
            if bytes.len() >= 4 && state.is_multiple_of(2) {
                bytes[..4].copy_from_slice(&0xcafe_babe_u32.to_be_bytes());
            }
            let _ = parse_fat_header(&bytes, state % 4096);
            let _ = thin_arch(&bytes);
        }
    }

    #[test]
    fn thin_arch_reads_either_byte_order() {
        assert_eq!(
            thin_arch(&thin_image(ARM64E, 0, 16)).as_deref(),
            Some("arm64e")
        );
        let mut big_endian = vec![0_u8; 12];
        big_endian[..4].copy_from_slice(&0xfeed_face_u32.to_be_bytes());
        big_endian[4..8].copy_from_slice(&18_i32.to_be_bytes());
        assert_eq!(thin_arch(&big_endian).as_deref(), Some("ppc"));
        assert_eq!(thin_arch(b"\x7fELF\x02\x01\x01\0\0\0\0\0"), None);
    }

    #[test]
    fn selects_by_case_insensitive_name() {
        let slices = [
            FatSlice {
                arch: "x86_64".into(),
                offset: 0x1000,
                size: 1,
            },
            FatSlice {
                arch: "arm64e".into(),
                offset: 0x2000,
                size: 1,
            },
        ];
        assert_eq!(
            select_slice(&slices, " ARM64E ").map(|s| s.offset),
            Some(0x2000)
        );
        assert_eq!(select_slice(&slices, "arm64"), None);
    }

    #[test]
    fn slice_path_sits_beside_the_output_database() {
        let input = Path::new("/bin/ls");
        assert_eq!(
            slice_path(input, Some(Path::new("/tmp/out/ls.i64")), "arm64e"),
            Some(PathBuf::from("/tmp/out/ls.arm64e"))
        );
        assert_eq!(
            slice_path(input, None, "x86_64"),
            Some(PathBuf::from("/bin/ls.x86_64"))
        );
    }

    #[test]
    fn inspect_classifies_and_validates_files() {
        let dir = temp_dir("inspect");
        let fat = dir.join("fat");
        let image = fat_image(
            false,
            &[
                (X86_64, thin_image(X86_64, 1, 48)),
                (ARM64, thin_image(ARM64, 2, 64)),
            ],
        );
        std::fs::write(&fat, &image).expect("write fat");
        let MachOKind::Universal(slices) = inspect(&fat).expect("inspect") else {
            panic!("expected a universal file");
        };
        assert_eq!(slices.len(), 2);

        let thin = dir.join("thin");
        std::fs::write(&thin, thin_image(ARM64E, 0, 32)).expect("write thin");
        assert_eq!(
            inspect(&thin).expect("inspect"),
            MachOKind::Thin("arm64e".into())
        );
        assert_eq!(
            inspect(&dir.join("missing")).expect("inspect"),
            MachOKind::Other
        );

        let mut not_macho = image.clone();
        not_macho[0x1000..0x1004].copy_from_slice(b"\x7fELF");
        let bad = dir.join("bad");
        std::fs::write(&bad, not_macho).expect("write bad");
        let err = inspect(&bad).expect_err("slice is not Mach-O");
        assert!(err.to_string().contains("slice 1 (x86_64)"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A universal file in `dir` whose arm64 slice is `arm64_len` bytes of
    /// `fill`, plus the parsed arm64 slice.
    fn fat_with_arm64(dir: &Path, name: &str, fill: u8, arm64_len: usize) -> (PathBuf, FatSlice) {
        let fat = dir.join(name);
        let image = fat_image(
            false,
            &[
                (X86_64, thin_image(X86_64, 1, 48)),
                (ARM64, thin_image(ARM64, fill, arm64_len)),
            ],
        );
        std::fs::write(&fat, &image).expect("write fat");
        let MachOKind::Universal(slices) = inspect(&fat).expect("inspect") else {
            panic!("expected a universal file");
        };
        let slice = select_slice(&slices, "arm64").expect("arm64").clone();
        (fat, slice)
    }

    fn slice_bytes(fat: &Path, slice: &FatSlice) -> Vec<u8> {
        let image = std::fs::read(fat).expect("read fat");
        let start = usize::try_from(slice.offset).expect("offset");
        let len = usize::try_from(slice.size).expect("size");
        image[start..start + len].to_vec()
    }

    /// Temporary files this module created and left behind in `dir`.
    fn leftover_partials(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("list dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".partial-") && !name.ends_with(".partial-foreign"))
            .collect()
    }

    #[test]
    fn extraction_reuses_identical_output_and_never_overwrites_others() {
        let dir = temp_dir("extract");
        let (fat, slice) = fat_with_arm64(&dir, "fat", 7, 5000);
        let arm = slice_bytes(&fat, &slice);
        let dest = dir.join("fat.arm64");

        assert_eq!(
            extract_slice(&fat, &slice, &dest).ok(),
            Some(SliceFile::Created)
        );
        assert_eq!(std::fs::read(&dest).expect("read slice"), arm);
        assert_eq!(
            extract_slice(&fat, &slice, &dest).ok(),
            Some(SliceFile::Reused)
        );

        for other in [b"someone else's file".to_vec(), vec![0xa5; arm.len()]] {
            std::fs::write(&dest, &other).expect("overwrite");
            let err = extract_slice(&fat, &slice, &dest).expect_err("differs");
            assert!(err.to_string().contains("delete it"), "{err}");
            assert_eq!(std::fs::read(&dest).expect("untouched"), other);
        }
        assert_eq!(leftover_partials(&dir), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_racing_publisher_that_wins_keeps_its_file() {
        let dir = temp_dir("race-lost");
        let (fat, slice) = fat_with_arm64(&dir, "fat", 7, 5000);
        let arm = slice_bytes(&fat, &slice);
        let dest = dir.join("fat.arm64");

        // The destination appears between the existence check and the link.
        let winner = b"published by someone else".to_vec();
        let err = extract_slice_with(&fat, &slice, &dest, |original, link| {
            std::fs::write(link, &winner).expect("racing publisher");
            std::fs::hard_link(original, link)
        })
        .expect_err("a different winner must not be replaced");
        assert!(
            err.to_string().contains("already exists and differs"),
            "{err}"
        );
        assert_eq!(std::fs::read(&dest).expect("winner intact"), winner);
        assert_eq!(leftover_partials(&dir), Vec::<String>::new());

        // A winner with the same bytes is simply reused.
        std::fs::remove_file(&dest).expect("reset");
        let outcome = extract_slice_with(&fat, &slice, &dest, |original, link| {
            std::fs::write(link, &arm).expect("racing publisher");
            std::fs::hard_link(original, link)
        });
        assert_eq!(outcome.ok(), Some(SliceFile::Reused));
        assert_eq!(std::fs::read(&dest).expect("winner intact"), arm);
        assert_eq!(leftover_partials(&dir), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refused_hard_link_is_an_error_without_fallback_or_leftovers() {
        let dir = temp_dir("no-hard-links");
        let (fat, slice) = fat_with_arm64(&dir, "fat", 7, 5000);
        let dest = dir.join("fat.arm64");
        let foreign = dir.join("fat.arm64.partial-foreign");
        std::fs::write(&foreign, b"not ours").expect("foreign partial");

        let err = extract_slice_with(&fat, &slice, &dest, |_, _| {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        })
        .expect_err("no hard links");
        let message = err.to_string();
        assert!(message.contains("refused a hard link"), "{message}");
        assert!(message.contains("supports hard links"), "{message}");
        assert!(!dest.exists(), "nothing may be published without the link");
        assert_eq!(leftover_partials(&dir), Vec::<String>::new());
        assert_eq!(
            std::fs::read(&foreign).expect("foreign intact"),
            b"not ours"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_write_removes_only_this_operations_temporary_file() {
        let dir = temp_dir("short-input");
        let (fat, slice) = fat_with_arm64(&dir, "fat", 7, 5000);
        let dest = dir.join("fat.arm64");
        let foreign = dir.join("fat.arm64.partial-foreign");
        std::fs::write(&foreign, b"not ours").expect("foreign partial");
        let past_end = FatSlice {
            size: slice.size + 4096,
            ..slice
        };

        let err = extract_slice(&fat, &past_end, &dest).expect_err("input too short");
        assert!(err.to_string().contains("writing"), "{err}");
        assert!(!dest.exists());
        assert_eq!(leftover_partials(&dir), Vec::<String>::new());
        assert_eq!(
            std::fs::read(&foreign).expect("foreign intact"),
            b"not ours"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_publishers_with_different_content_leave_one_intact_winner() {
        let dir = temp_dir("concurrent");
        let (fat_a, slice_a) = fat_with_arm64(&dir, "a", 0xa1, 256 * 1024);
        let (fat_b, slice_b) = fat_with_arm64(&dir, "b", 0xb2, 256 * 1024);
        let (bytes_a, bytes_b) = (slice_bytes(&fat_a, &slice_a), slice_bytes(&fat_b, &slice_b));
        assert_ne!(bytes_a, bytes_b);
        let dest = dir.join("shared.arm64");

        let publishers = 8;
        let barrier = Arc::new(Barrier::new(publishers));
        let handles: Vec<_> = (0..publishers)
            .map(|index| {
                let (fat, slice) = if index % 2 == 0 {
                    (fat_a.clone(), slice_a.clone())
                } else {
                    (fat_b.clone(), slice_b.clone())
                };
                let (dest, barrier) = (dest.clone(), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    (index, extract_slice(&fat, &slice, &dest))
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("publisher thread"))
            .collect();

        let published = std::fs::read(&dest).expect("one slice published");
        let winner_is_a = published == bytes_a;
        assert!(
            winner_is_a || published == bytes_b,
            "published file is torn"
        );
        let created = results
            .iter()
            .filter(|(_, result)| matches!(result, Ok(SliceFile::Created)))
            .count();
        assert_eq!(created, 1, "{results:?}");
        for (index, result) in &results {
            let same_content = (index % 2 == 0) == winner_is_a;
            match result {
                Ok(SliceFile::Created | SliceFile::Reused) => assert!(same_content, "{index}"),
                Err(error) => {
                    assert!(!same_content, "{index}: {error}");
                    assert!(
                        error.to_string().contains("already exists and differs"),
                        "{error}"
                    );
                }
            }
        }
        assert_eq!(leftover_partials(&dir), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
