#![feature(proc_macro)]
#![allow(dead_code)]

extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate openssl;
extern crate time;
#[macro_use]
extern crate log;

pub mod error;

use std::*;
use rustc_serialize::base64::{ToBase64, URL_SAFE};
use openssl::sign::Signer;
use openssl::pkey::{PKey};
use openssl::hash::MessageDigest;

use serde::Serialize;

use std::io::prelude::*;
use std::fs::File;

use error::JwtErr;

#[derive(Debug)]
pub enum Algorithm {
  HS256,
  RS256
}

impl Algorithm {
  fn signer(&self) -> openssl::hash::MessageDigest {
    match *self {
      Algorithm::HS256 => unimplemented!(),
      Algorithm::RS256 => MessageDigest::sha256(),
    }
  }
}

impl fmt::Display for Algorithm {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      Algorithm::HS256 => write!(f, "HS256"),
      Algorithm::RS256 => write!(f, "RS256")
    }

  }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JwtHeader {
  alg: String,
  typ: String
}

impl fmt::Display for JwtHeader {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "JwtHeader: {}", serde_json::to_string_pretty(&self).unwrap())
  }
}

pub struct RSAKey {
  key: PKey
}

impl RSAKey {
  pub fn from_pem(filename: &str) -> Result<Self, JwtErr> {
    Ok(RSAKey { key: Self::read_keyfile(filename)? })
  }

  pub fn from_pkey(pkey: PKey) -> Result<Self, JwtErr> {
    Ok(RSAKey { key: pkey })
  }

  pub fn from_str(pkey: &str) -> Result<Self, JwtErr> {
    Ok(RSAKey { key: PKey::private_key_from_pem(pkey.as_bytes())? })
  }

  fn read_keyfile(keyfile: &str) -> Result<PKey, JwtErr> {
    let mut f = File::open(keyfile)?;
    let mut buffer = Vec::new();
    let _ = f.read_to_end(&mut buffer);
    Ok(PKey::private_key_from_pem(&buffer)?)
  }

  fn produce_key(&self) -> &PKey {
    &self.key
  }
}

pub struct Jwt<T> {
  body: T,
  pkey: RSAKey,
  algo: Algorithm
}

impl<T: Serialize> fmt::Display for Jwt<T> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Jwt: \n header: {} \n body: {}, \n algorithm: {}",
           serde_json::to_string_pretty(&self.header().unwrap()).unwrap(),
           serde_json::to_string_pretty(&self.body).unwrap(),
           &self.algo)
  }
}

/// Jwt can be finalized to produce an encoded and signed string representation
///
/// ### Example
///
/// ```
/// #![feature(proc_macro)]
///
/// #[macro_use]
/// extern crate serde_derive;
/// extern crate serde;
/// extern crate smpl_jwt;
///
/// use serde::Serialize;
/// use smpl_jwt::{Jwt, RSAKey};
///
/// fn main() {
///   #[derive(Serialize)]
///   struct ExampleStruct {
///     field: String
///   }
///
///   let rsa_key = match RSAKey::from_pem("random_rsa_for_testing") {
///     Ok(x) => x,
///     Err(e) => panic!("{}", e)
///   };
///
///   let jwt = Jwt::new(ExampleStruct{field: String::from("test")},
///                     rsa_key,
///                     None);
///
///   println!("{}", jwt);
/// }
/// ```

impl<T> Jwt<T> where
  T: Serialize {
  fn input(&self) -> Result<String, JwtErr> {
    let header = &self.encode_header()?;
    let body = Self::encode(&self.body)?;
    Ok(format!("{}.{}", header, body))
  }

  fn encode(param: &T) -> Result<String, JwtErr> {
    Ok(serde_json::to_string(&param)?.as_bytes().to_base64(URL_SAFE).to_owned())
  }

  fn encode_header(&self) -> Result<String, JwtErr> {
    Ok(serde_json::to_string(&self.header()?)?.as_bytes().to_base64(URL_SAFE).to_owned())
  }

  fn header(&self) -> Result<JwtHeader, JwtErr> {
    Ok(JwtHeader {
      alg: self.algo.to_string(),
      typ: "JWT".to_string(),
    })
  }

  fn sign(&self) -> Result<String, JwtErr> {
    let pkey = self.pkey.produce_key();
    let mut signer = Signer::new(self.algo.signer(), pkey)?;
    signer.update(self.input()?.as_bytes())?;
    let signed: Vec<u8> = signer.finish()?;
    Ok(signed.to_base64(URL_SAFE))
  }

  pub fn finalize(&self) -> Result<String, JwtErr> {
    Ok(format!("{}.{}", &self.input()?, &self.sign()?))
  }

  pub fn new(body: T, jwt_key: RSAKey, algo: Option<Algorithm>) -> Jwt<T>  {
    Jwt {
      body: body,
      pkey: jwt_key,
      algo: algo.unwrap_or(Algorithm::RS256)
    }
  }
}

#[test]
fn test_sign() {
//  Verified with https://jwt.io/

  #[derive(Serialize)]
  struct TestBody {
    serialize: String
  }

  let rsa_key = match RSAKey::from_pem("random_rsa_for_testing") {
    Ok(x) => x,
    Err(e) => panic!("{}", e)
  };

  let jwt = Jwt::new(TestBody{serialize: "me".to_string()},
                     rsa_key,
                     None);
  assert_eq!(jwt.finalize().unwrap(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXJpYWxpemUiOiJtZSJ9.nJIFpAKQWE5Mt1TQS2eDqoLVANJf809pCegB7herGYZ0Lqb1eV9MAv_Cz6lyaq87v1StC48e-U3Lp6oVezsQ-mUg5h92hFEEkzKIoJOYE6N-BEaVuy73Qf2s7c6W3ZdD0U3oR6PiEO9-FnB5bsiQlIfgzykmDUSjo2CmYpAypF9sT43by4tvSMwUwNZ_NuTI3ASPqdk5wKAkrCOJjayhyKZR7KrqeUmZdqS0Un8NSpr53Zd6SdCYTpDSGsKF_mwYV309q7zAbzRhWN-YTYsdB6Em5QoXo0ZUuNIigfprOQP1MVFvznbeonQvu6OHzJMIFhhUip8UCFNp6wzsqm4syQ");
}