use hyper::{
    header::{PROXY_AUTHENTICATE},
    Response, Uri,
};
use crate::error::Error;

#[derive(Clone, PartialEq, Debug)]
pub enum AuthenticationScheme {
    Basic,
    Digest,
    None,
}

#[derive(Clone, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct Proxy {
    pub uri: Uri,
    pub credentials: Option<Credentials>,
}

impl Proxy {
    // pub fn add_authentication_headers<B>(
    //     &self,
    //     authentication: &mut AuthenticationScheme,
    //     req: &mut Request<B>,
    // ) -> io::Result<()> {
    //     let credentials = (&self.credentials).as_ref().ok_or(Error::new(
    //         ErrorKind::Other,
    //         "The proxy require credentials and it not was given",
    //     ))?;
    //     let headers = req.headers_mut();

    //     match authentication {
    //         AuthenticationScheme::Basic => {
    //             let cred = format!("{}:{}", credentials.username, credentials.password);

    //             headers.insert(
    //                 PROXY_AUTHORIZATION,
    //                 format!("Basic {}", STANDARD.encode(cred)).parse().unwrap(),
    //             );
    //         }
    //         AuthenticationScheme::Digest(ref mut prompt) => {
    //             let uri = req.uri().to_string();
    //             let method = req.method().to_string();

    //             let context = AuthContext::new_with_method(
    //                 &credentials.username,
    //                 &credentials.password,
    //                 &uri,
    //                 Option::<&'_ [u8]>::None,
    //                 digest_auth::HttpMethod::from(method),
    //             );
    //             let response = prompt.respond(&context);

    //             headers.insert(
    //                 PROXY_AUTHORIZATION,
    //                 response.unwrap().to_header_string().parse().unwrap(),
    //             );
    //         }
    //         _ => (),
    //     }

    //     Ok(())
    // }

    pub fn get_auth_info<B>(
        response: &'_ Response<B>,
    ) -> Result<(AuthenticationScheme, Option<&'_ str>), Error> {
        let data = match response.headers().get(PROXY_AUTHENTICATE) {
            Some(d) => d.to_str()?,
            None => return Ok((AuthenticationScheme::None, None)),
        };

        // This must be right since hyper keep a valid structure 
        let (auth, _) = data.split_once(' ').ok_or("Invalid digest structure")?;

        if auth.eq_ignore_ascii_case("digest") { 
            return Ok((AuthenticationScheme::Digest, Some(data)));
        }
        if auth.eq_ignore_ascii_case("basic") {
            return Ok((AuthenticationScheme::Basic, Some(data)));
        }
        Err("Unknow auth scheme method".into())
    }
}
