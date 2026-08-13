use std::ffi::CString;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

struct Options {
    recursive: bool,   // -r, -R
    preserve: bool,    // -p (mode, ownership, timestamps)
    no_deref: bool,    // -d, -P (don't follow symlinks)
    force: bool,       // -f (remove existing destination if open fails)
    interactive: bool, // -i (prompt before overwrite)
    verbose: bool,     // -v
}

pub fn main(args: &str) {
    let args = args.trim();

    let mut opts = Options {
        recursive: false,
        preserve: false,
        no_deref: false,
        force: false,
        interactive: false,
        verbose: false,
    };

    let mut paths: Vec<&str> = Vec::new();
    let mut no_more_opts = false;

    for part in args.split_whitespace() {
        if !no_more_opts && part == "--" {
            no_more_opts = true;
        } else if !no_more_opts && part.starts_with('-') && part.len() > 1 {
            for ch in part[1..].chars() {
                match ch {
                    'r' | 'R' => opts.recursive = true,
                    'a' => {
                        // archive: same as -dpR
                        opts.recursive = true;
                        opts.preserve = true;
                        opts.no_deref = true;
                    }
                    'p' => opts.preserve = true,
                    'd' | 'P' => opts.no_deref = true,
                    'L' => opts.no_deref = false,
                    'H' => {} // accepted for compatibility; sources are followed by default
                    'f' => {
                        opts.force = true;
                        opts.interactive = false;
                    }
                    'i' => {
                        opts.interactive = true;
                        opts.force = false;
                    }
                    'v' => opts.verbose = true,
                    _ => {
                        eprintln!("cp: invalid option -- '{}'", ch);
                        return;
                    }
                }
            }
        } else {
            paths.push(part);
        }
    }

    if paths.len() < 2 {
        eprintln!("Usage: cp [-arPLHpfilv] SOURCE... DEST");
        return;
    }

    let dest = paths.pop().unwrap();
    let sources = paths;

    let dest_is_dir = fs::metadata(dest).map(|m| m.is_dir()).unwrap_or(false);

    if sources.len() > 1 && !dest_is_dir {
        eprintln!("cp: '{}' is not a directory", dest);
        return;
    }

    for src in sources {
        let target: PathBuf = if dest_is_dir {
            let name = Path::new(src)
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new(src));
            Path::new(dest).join(name)
        } else {
            PathBuf::from(dest)
        };

        copy_path(Path::new(src), &target, &opts);
    }
}

fn copy_path(src: &Path, dst: &Path, opts: &Options) {
    let src_meta = if opts.no_deref {
        fs::symlink_metadata(src)
    } else {
        fs::metadata(src)
    };

    let src_meta = match src_meta {
        Ok(m) => m,
        Err(e) => {
            eprintln!("cp: can't stat '{}': {}", src.display(), e);
            return;
        }
    };

    if src_meta.file_type().is_symlink() {
        copy_symlink(src, dst, opts);
    } else if src_meta.is_dir() {
        if !opts.recursive {
            eprintln!("cp: -r not specified; omitting directory '{}'", src.display());
            return;
        }
        copy_dir(src, dst, &src_meta, opts);
    } else {
        copy_file(src, dst, &src_meta, opts);
    }
}

fn copy_dir(src: &Path, dst: &Path, src_meta: &fs::Metadata, opts: &Options) {
    // Guard against copying a directory into itself
    if dst.starts_with(src) {
        eprintln!(
            "cp: can't copy '{}' into itself, '{}'",
            src.display(),
            dst.display()
        );
        return;
    }

    match fs::metadata(dst) {
        Ok(m) if m.is_dir() => {} // exists, descend into it
        Ok(_) => {
            eprintln!(
                "cp: can't overwrite non-directory '{}' with directory '{}'",
                dst.display(),
                src.display()
            );
            return;
        }
        Err(_) => {
            if let Err(e) = fs::create_dir(dst) {
                eprintln!("cp: can't create directory '{}': {}", dst.display(), e);
                return;
            }
            if opts.verbose {
                println!("'{}' -> '{}'", src.display(), dst.display());
            }
        }
    }

    let entries = match fs::read_dir(src) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("cp: can't open '{}': {}", src.display(), e);
            return;
        }
    };

    for entry in entries.flatten() {
        let child_src = entry.path();
        let child_dst = dst.join(entry.file_name());
        copy_path(&child_src, &child_dst, opts);
    }

    if opts.preserve {
        preserve_attributes(dst, src_meta);
    }
}

fn copy_symlink(src: &Path, dst: &Path, opts: &Options) {
    let target = match fs::read_link(src) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cp: can't read link '{}': {}", src.display(), e);
            return;
        }
    };

    if fs::symlink_metadata(dst).is_ok() {
        if !confirm_overwrite(dst, opts) {
            return;
        }
        if let Err(e) = fs::remove_file(dst) {
            eprintln!("cp: can't remove '{}': {}", dst.display(), e);
            return;
        }
    }

    #[cfg(unix)]
    let result = std::os::unix::fs::symlink(&target, dst);
    #[cfg(not(unix))]
    let result: io::Result<()> = Err(io::Error::new(io::ErrorKind::Other, "unsupported"));

    match result {
        Ok(_) => {
            if opts.verbose {
                println!("'{}' -> '{}'", src.display(), dst.display());
            }
        }
        Err(e) => {
            eprintln!("cp: can't create symlink '{}': {}", dst.display(), e);
        }
    }
}

fn copy_file(src: &Path, dst: &Path, src_meta: &fs::Metadata, opts: &Options) {
    if let Ok(dst_meta) = fs::metadata(dst) {
        if same_file(src_meta, &dst_meta) {
            eprintln!(
                "cp: '{}' and '{}' are the same file",
                src.display(),
                dst.display()
            );
            return;
        }
        if !confirm_overwrite(dst, opts) {
            return;
        }
    }

    let mut result = fs::copy(src, dst);

    if result.is_err() && opts.force {
        // -f: unlink the destination and try again
        let _ = fs::remove_file(dst);
        result = fs::copy(src, dst);
    }

    match result {
        Ok(_) => {
            if opts.preserve {
                preserve_attributes(dst, src_meta);
            }
            if opts.verbose {
                println!("'{}' -> '{}'", src.display(), dst.display());
            }
        }
        Err(e) => {
            eprintln!("cp: can't create '{}': {}", dst.display(), e);
        }
    }
}

fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return a.dev() == b.dev() && a.ino() == b.ino();
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}

fn confirm_overwrite(dst: &Path, opts: &Options) -> bool {
    if !opts.interactive {
        return true;
    }
    print!("cp: overwrite '{}'? ", dst.display());
    let _ = io::stdout().flush();
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().chars().next(), Some('y') | Some('Y'))
}

fn preserve_attributes(dst: &Path, src_meta: &fs::Metadata) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let path_cstr = match CString::new(dst.to_string_lossy().as_bytes()) {
            Ok(s) => s,
            Err(_) => return,
        };

        unsafe {
            libc::chmod(path_cstr.as_ptr(), src_meta.mode() as libc::mode_t);
            libc::chown(path_cstr.as_ptr(), src_meta.uid(), src_meta.gid());

            #[allow(deprecated)]
            let times = [
                libc::timeval {
                    tv_sec: src_meta.atime() as libc::time_t,
                    tv_usec: (src_meta.atime_nsec() / 1000) as libc::suseconds_t,
                },
                libc::timeval {
                    tv_sec: src_meta.mtime() as libc::time_t,
                    tv_usec: (src_meta.mtime_nsec() / 1000) as libc::suseconds_t,
                },
            ];
            libc::utimes(path_cstr.as_ptr(), times.as_ptr());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dst, src_meta);
    }
}

pub fn help_text() -> &'static str {
    "cp [-arPLpfiv] SOURCE... DEST     - Copy files/directories (-r recursive, -a archive, -p preserve)"
}
