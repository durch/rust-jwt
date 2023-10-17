[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/durch/rust-jwt/blob/master/LICENSE)

## rust-jwt [[docs](https://durch.github.io/rust-jwt)]

Very simple [JWT](https://jwt.io/) generation lib, provides a Jwt struct which can be *finalised* to produce an encoded and signed [String](https://doc.rust-lang.org/std/string/struct.String.html) representation. 

Generic over [serde::ser::Serialize](https://docs.serde.rs/serde/ser/trait.Serialize.html) trait.

### Usage

```rust
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate smpl_jwt;

use serde::Serialize;
use smpl_jwt::{Jwt, RSAKey};

fn main() {
  #[derive(Serialize)]
  struct ExampleStruct {
    field: String
  }

  let rsa_key = match RSAKey::from_pem("random_rsa_for_testing") {
    Ok(x) => x,
    Err(e) => panic!("{}", e)
  };

  let jwt = Jwt::new(ExampleStruct{field: String::from("test")},
                    rsa_key,
                    None);
  println!("{}", jwt);
}
```
