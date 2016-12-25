use std;
use serde_json::Error as json_error;
use openssl::error::ErrorStack as openssl_error;
use std::io::Error as io_error;

macro_rules! impl_from {
    ($type_: ident, $enum_ty: ident) => {
        impl From<$type_> for JwtErr {
            fn from(e: $type_) -> JwtErr {
                JwtErr::$enum_ty(e)
            }
        }
    }
}

#[derive(Debug)]
pub enum JwtErr {
  Json(json_error),
  OpenSSL(openssl_error),
  Io(io_error),
  Unknown
}

impl_from!(json_error, Json);
impl_from!(openssl_error, OpenSSL);
impl_from!(io_error, Io);

impl std::fmt::Display for JwtErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            JwtErr::Json(ref e) => e.fmt(f),
            JwtErr::OpenSSL(ref e) => e.fmt(f),
            JwtErr::Io(ref e) => e.fmt(f),
            JwtErr::Unknown => write!(f, "An unknown error has occured"),
        }
    }
}

impl std::error::Error for JwtErr {
    fn description(&self) -> &str {
        match *self {
            JwtErr::Json(ref e) => e.description(),
            JwtErr::OpenSSL(ref e) => e.description(),
            JwtErr::Io(ref e) => e.description(),
            JwtErr::Unknown => "unknown error",
        }
    }
}