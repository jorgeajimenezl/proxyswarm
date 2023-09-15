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
        return format!("{bytes} Bytes");
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

use http::{header, request::Builder, Request, Response, Version};
use hyper::body::Body;

pub trait RequestExt {
    fn builder_from(&self) -> Builder;
}

pub trait ResponseExt {
    fn is_closed(&self) -> bool;
}

impl<T> RequestExt for Request<T> {
    fn builder_from(&self) -> Builder {
        let mut builder = Request::builder()
            .uri(self.uri())
            .method(self.method())
            .version(self.version());

        let headers = builder.headers_mut().unwrap();
        headers.extend(self.headers().clone());

        builder
    }
}

impl<T: Body> ResponseExt for Response<T> {
    fn is_closed(&self) -> bool {
        let closed = match self.headers().get(header::CONNECTION) {
            Some(header) => header
                .to_str()
                .map(|x| x.eq_ignore_ascii_case("close"))
                .unwrap_or(false),
            None => false,
        };
        closed
            || matches!(self.version(), Version::HTTP_10 | Version::HTTP_09)
            || self.is_end_stream()
    }
}
