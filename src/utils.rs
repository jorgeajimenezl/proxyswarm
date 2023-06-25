static BYTES_SUFFIX: ([&str; 8], [&str; 8]) = (
    ["kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"],
    ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"],
);

pub fn natural_size(bytes: u64, binary: bool) -> String {
    let base = if binary { 1024 } else { 1000 };
    let suffix = if binary {
        BYTES_SUFFIX.1
    } else {
        BYTES_SUFFIX.0
    };
    if bytes < base {
        return format!("{} Bytes", bytes);
    }

    let mut unit = base * base;
    for &s in suffix[..7].iter() {
        if bytes < unit {
            return format!("{:.2} {}", (base * bytes) as f64 / unit as f64, s);
        }
        unit *= base;
    }

    format!("{:.2} {}", (base * bytes) as f64 / unit as f64, suffix[7])
}
