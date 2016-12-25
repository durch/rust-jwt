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
/// extern crate jwt;
///
/// use serde::Serialize;
/// use jwt::{Jwt, RSAKey};
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

  let rsa_key = match RSAKey::from_str("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEApbqWApvg28npX4N0WlP+6gRAvOsBqDZjqEilUfwyjYxaXecU87dOVN31jBBcEXffrPWX9njntWRKF+WwDvm6xi5rSlhbKU/SlTFiMPJx/r9789UpWPKmkDncRQVzBm5NFeYTRAu870SgF9Z2DQC46utGWEBkRYsKs+C5jo7vBse50xshCS6XiWK+7UQlJyV+egOIPwFMMXAmhqfVhSRnzEz1QwoJJrakzenNgiAcWhSQ4MBKtuOlkQse1mWEQFQ0yYx0kwMogNQMK70wdRf+STdGZyIJHGYfvZBrEZlpPufB6FPOA+LmG1YCf3276DNb6hmauTa5q+8j24FseUkdywIDAQABAoIBAFpeW94gUYSHnRHQBGoc0yuYFhTtsIGg5saklkEWXBqDJeN+VhZvJe9w+KvfX9TGoNkXMj3bv71RanWNcWs5EXdvaGGpvEvSkul3fCtkiHR4xYY3/cvaxKhwZIPebNJc4vvF8UtxexydNw7IiqacdjjjAgCtW//vyW48Y/IwTnZLHQ0cdY/OqiKHB1O5IdtdVP4zQJ5TozA+7TcgZjcBHTBnBWOG/viFdD3MVAGPiodeMcHILvHUpoxqAw43J9OZVArCU1OuT+GJN/yCkbtsJQkzRi8FXPNh/5D31lJr+Pgb7MPjOWca3u9MQjVO9VWE4nqGQ+/h8MdJyHJm1m7odwECgYEA+5IZtdstqd8cszACdPQgVntcc8P9mkmf5B1Ig/FtpqfzjXjSw/oyn5WT0SunPUSIHXT5LVWsUrJU+XxrQnZ1qlYSSMxfY+aQKvhxU/5z53PxEMq0rJEEt/YG6Gzf1W9b5wPa5cJFY1qIsBM3q7o+ThemSUjdXGd8fYb3IDXjKhsCgYEAqKWSgZ1Eig2jrPzPJQU8ZlJhK9nx+b5OeO0zUwOWDuZPgbuSFlsTi7OL5pNPHv3f8Tb7bs031jcFWdhUEw/V48RLek3DUd7p5LZmwHQic91o8XQ6Yp0nYyxn0VAQFwT7DqTb9PZWdiEsVGrj0P4lQEIkA2WlwLChEnFQhjgPFhECgYA0d0/tYXywhNuTc1vP0Go+HxQ1AJcPanNyO7k3604XB8f/pUcvoCqWpbdiVFxYpsZMfmzJS6jYxmB6d7xW7CW2FKVTkWwDhb5jd9UK03KQvtlzyxLLOqNlSmY+axZziPn9wAwTBuU5x1PihN+DbSA5YS1I821XLC4Gb/NyQErUKQKBgHA6HpCac23bPbx0T/S200bUM03XLyue9OGMF8d6b3Vi1i3jAIhX+13QEZ1TEifxkgEXMaK+dhXbb3gmeWxl8VQs4H13Gi91Q/irWR1hKzwnbxqe2eud4QQiHMQxn0NyUQ+hra4J7+eUk8dpikkdlvR4DzcjgXYFFGsNdSScUY3BAoGBAOPQOwUekXEObbBVD2ZwnJAPe0A5YDwMgvv8QZehEx7Y9OF/fcEbqR8khzR93btLMbEZ+LkBw0oPcXDhNhxsGXUyRRnAAr6gX8cX8rhgpUmvLFoTBNHNsI5PlkWNQxRnuESumOsbasF/4BHrH33bZnNtBaYH9YfWshR+KdtBr8IM\n-----END RSA PRIVATE KEY-----") {
    Ok(x) => x,
    Err(e) => panic!("{}", e)
  };

  let jwt = Jwt::new(TestBody{serialize: "me".to_string()},
                     rsa_key,
                     None);
  assert_eq!(jwt.finalize().unwrap(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXJpYWxpemUiOiJtZSJ9.nJIFpAKQWE5Mt1TQS2eDqoLVANJf809pCegB7herGYZ0Lqb1eV9MAv_Cz6lyaq87v1StC48e-U3Lp6oVezsQ-mUg5h92hFEEkzKIoJOYE6N-BEaVuy73Qf2s7c6W3ZdD0U3oR6PiEO9-FnB5bsiQlIfgzykmDUSjo2CmYpAypF9sT43by4tvSMwUwNZ_NuTI3ASPqdk5wKAkrCOJjayhyKZR7KrqeUmZdqS0Un8NSpr53Zd6SdCYTpDSGsKF_mwYV309q7zAbzRhWN-YTYsdB6Em5QoXo0ZUuNIigfprOQP1MVFvznbeonQvu6OHzJMIFhhUip8UCFNp6wzsqm4syQ");
}