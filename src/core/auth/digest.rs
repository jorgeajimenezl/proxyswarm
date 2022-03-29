use md5::{Context, Digest};

fn digest_compute_a1(
    username: &str,
    password: &str,
    realm: &str,
    algorithm: Option<&str>,
    nonce: &str,
    cnonce: &str,
) -> Digest {
    let mut ctx = Context::new();
    ctx.consume(username);
    ctx.consume(b":");
    ctx.consume(realm);
    ctx.consume(b":");
    ctx.consume(password);

    if let Some("md5-sess") = algorithm {
        {
            let digest = ctx.compute();
            ctx = Context::new();
            ctx.consume(&*digest);
        }
        ctx.consume(b":");
        ctx.consume(nonce);
        ctx.consume(b":");
        ctx.consume(cnonce);
    }

    ctx.compute()
}

fn digest_compute_a2(
    qop: Option<&str>,
    method: &str,
    digest_uri: &str,
    entity_body: &str,
) -> Digest {
    let mut ctx = Context::new();
    ctx.consume(method);
    ctx.consume(b":");
    ctx.consume(digest_uri);
    if let Some("auth-int") = qop {
        ctx.consume(b":");
        ctx.consume(entity_body);
    }

    ctx.compute()
}

pub fn digest_compute_response(
    username: &str,
    password: &str,
    realm: &str,
    algorithm: Option<&str>,
    nonce: &str,
    cnonce: &str,
    nonce_count: u32,
    qop: Option<&str>,
    method: &str,
    digest_uri: &str,
) -> String {
    let mut ctx = Context::new();

    // TODO: Add entity body support
    let ha1 = digest_compute_a1(username, password, realm, algorithm, nonce, cnonce);
    let ha2 = digest_compute_a2(qop, method, digest_uri, &String::from(""));
    let ha1 = format!("{:x}", ha1);
    let ha2 = format!("{:x}", ha2);

    ctx.consume(ha1);
    ctx.consume(b":");
    ctx.consume(nonce);
    ctx.consume(b":");

    if let Some(t) = qop {
        ctx.consume(format!("{:08x}", nonce_count));
        ctx.consume(b":");
        ctx.consume(cnonce);
        ctx.consume(b":");
        ctx.consume(t);
        ctx.consume(b":");
    }

    ctx.consume(ha2);
    format!("{:x}", ctx.compute())
}
