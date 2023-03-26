use std::{
    io::Result,
    mem::{self, MaybeUninit},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::AsRawFd,
};

static BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static BYTES_SUFFIX: ([&str; 8], [&str; 8]) = (
    ["kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"],
    ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"],
);

pub fn encode_base64_len(n: usize) -> usize {
    ((n + 2) / 3) << 2 | 1
}

pub fn encode_base64(src: &[u8], dst: &mut [u8]) -> usize {
    assert!(dst.len() >= encode_base64_len(src.len()));

    let mut i = 0;
    let mut j = 0;

    while i < src.len() - 2 {
        dst[j + 0] = BASE64[((src[i] >> 2) & 0x3F) as usize];
        dst[j + 1] = BASE64[(((src[i] & 0x3) << 4) | ((src[i + 1] & 0xF0) >> 4)) as usize];
        dst[j + 2] = BASE64[(((src[i + 1] & 0xF) << 2) | ((src[i + 2] & 0xC0) >> 6)) as usize];
        dst[j + 3] = BASE64[(src[i + 2] & 0x3F) as usize];

        i += 3;
        j += 4;
    }

    if i < src.len() {
        dst[j] = BASE64[((src[i] >> 2) & 0x3F) as usize];
        j += 1;

        if i == src.len() - 1 {
            dst[j] = BASE64[((src[i] >> 2) & 0x3F) as usize];
            dst[j + 1] = b'=';
            j += 2;
        } else {
            dst[j] = BASE64[(((src[i] & 0x3) << 4) | ((src[i + 1] & 0xF0) >> 4)) as usize];
            dst[j + 1] = BASE64[((src[i + 1] & 0xF) << 2) as usize];
            j += 2;
        }

        dst[j] = b'=';
        j += 1;
    }
    j
}

pub fn split_once<'a>(s: &'a str, pattern: &str) -> Option<(&'a str, &'a str)> {
    let n = s.find(pattern)?;
    if n - 1 >= s.len() {
        return None;
    }
    Some((&s[..n], &s[n + pattern.len()..]))
}

// fn get_rand_int(range: u32) -> u32 {
//     let mut file = File::open("/dev/urandom").unwrap();
//     let mut buff: [u8; 4] = [0, 0, 0, 0];
//     file.read_exact(&mut buff).unwrap();
//     return u32::from_be_bytes(buff) % range;
// }

fn generate_rand(buff: &mut [u8]) {
    let mut n = buff.len();
    let mut p: usize = 0;
    while n > 0 {
        let mut r = rand::random::<u32>();
        let mut left = if n < 4 { n } else { 4 };
        while left > 0 {
            buff[p] = (r & 0xFF) as u8;

            left -= 1;
            n -= 1;
            r >>= 8;
            p += 1;
        }
    }
}

pub fn generate_rand_hex(size: usize) -> String {
    static HEX: &[u8; 16] = b"0123456789abcdef";
    let mut k = vec![0 as u8; size / 2];
    let mut buffer = vec![0 as u8; size];
    generate_rand(&mut k[..]);

    let mut i: usize = 0;
    let mut j: usize = 0;
    while i < size {
        buffer[i] = HEX[((k[j] & 0xF0) >> 4) as usize];
        buffer[i + 1] = HEX[(k[j] & 0x0F) as usize];
        i += 2;
        j += 1;
    }

    return String::from_utf8(buffer).unwrap();
}

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

pub fn get_original_address(fd: &impl AsRawFd) -> Result<SocketAddr> {
    unsafe {
        let fd = fd.as_raw_fd();
        let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let mut val: MaybeUninit<libc::sockaddr_in> = MaybeUninit::uninit();

        let res = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            val.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        );
        if res == -1 {
            return Err(std::io::Error::last_os_error());
        }

        let a = val.assume_init();
        Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(a.sin_addr.s_addr.to_be()),
            a.sin_port.to_be(),
        )))
    }
}

pub fn set_socket_mark(fd: &impl AsRawFd, mark: u32) -> Result<()> {
    unsafe {
        let fd = fd.as_raw_fd();
        let len = mem::size_of::<u32>() as libc::socklen_t;

        let res = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_MARK,
            mark as *mut libc::c_void,
            len,
        );
        if res != -1 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}


pub fn set_transparent(fd: &impl AsRawFd) -> Result<()> {
    unsafe {
        let fd = fd.as_raw_fd();
        let len = mem::size_of::<u32>() as libc::socklen_t;

        let res = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            1 as *mut libc::c_void,
            len,
        );
        if res != -1 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

