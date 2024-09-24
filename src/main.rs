mod dir_scanner;
mod copy;
mod file_copier;
mod stats;

use std::env::args_os;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn parse_num_option(opt: Option<OsString>, flag: &'static str) -> usize {
    let opt = match opt {
        Some(o) => o,
        None => {
            eprintln!("Missing value for {}", flag);
            exit(2);
        }
    };
    if let Some(opt) = opt.to_str() {
        if let Ok(opt) = opt.parse() {
            return opt;
        }
    }
    eprintln!("Invalid value for --entries");
    exit(2);
}

fn main() {
    // Parse command line
    let mut entries = None;
    let mut size = None;
    let mut source = None;
    let mut target = None;
    let mut threads = None;

    let mut args = args_os();
    args.next();
    let usage = "Usage: fast-local-sync [--entries TOTAL_ENTRIES] [--size TOTAL_SIZE] [--threads NUM_THREADS] SOURCE DESTINATION";
    while let Some(arg) = args.next() {
        if &arg == "--help" {
            println!("{}", usage);
            exit(0);
        } else if &arg == "--entries" {
            entries = Some(parse_num_option(args.next(), "--entries"));
        } else if &arg == "--size" {
            size = Some(parse_num_option(args.next(), "--size"));
        } else if &arg == "--threads" {
            threads = Some(parse_num_option(args.next(), "--threads"));
        } else {
            if source.is_none() {
                source = Some(arg);
            } else if target.is_none() {
                target = Some(arg);
            } else {
                eprintln!("Too many arguments");
                eprintln!("{}", usage);
                exit(2);
            }
        }
    }

    let threads = threads.unwrap_or(8);
    let source: PathBuf = match source {
        Some(s) => s.into(),
        None => {
            eprintln!("Missing source");
            eprintln!("{}", usage);
            exit(2);
        }
    };
    let target: PathBuf = match target {
        Some(s) => s.into(),
        None => {
            eprintln!("Missing target");
            eprintln!("{}", usage);
            exit(2);
        }
    };

    // Initialize statistics
    let stats = Arc::new(stats::Stats::new(entries, size));

    // Create worker pools
    let file_copy_pool = file_copier::FileCopyPool::new(
        source.as_path(),
        target.as_path(),
        threads,
        stats.clone(),
    );
    let dir_scan_pool = dir_scanner::DirScanPool::new(
        source.as_path(),
        target.as_path(),
        threads,
        file_copy_pool.clone(),
        stats.clone(),
    );

    // Enqueue work
    dir_scan_pool.add("/".into());

    // Print stats regularly
    {
        let stats = stats.clone();
        thread::spawn(move || {
            let stats = &*stats;

            let mut i = 0;

            loop {
                thread::sleep(Duration::from_secs(10));

                i += 1;
                if i >= 30 {
                    i = 1;
                    eprintln!(
                        "SCANNED   \
                         SKIPPED   \
                         QUEUED    \
                         COPIED"
                    );
                }
                eprintln!(
                    "{:>9} {:>9} {:>9} {:>9}",
                    stats.scanned_entries(),
                    stats.skipped_entries(),
                    stats.queued_copy_entries(),
                    stats.copied_entries(),
                )
            }
        });
    }

    // Wait until done
    dir_scan_pool.join();
    file_copy_pool.join();
}
