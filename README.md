# JWKnife - Swiss Army Knife of JWK sets

Manipulate & Convert JWK sets.
- Read any number of keys in PEM, JWK or JWKS format into a single JWK set.
- Output some or all of the JWKs as a JWK set or PEM.

## Security

**This is Alpha software, use at your own risk**

Operations are implemented entirely using functions of the Go standard library and github.com/go-jose/go-jose module.

## Example

Shell command:

```sh
jwknife read -pem -path=my.pem gen -rsa=2048 -setstr=alg=RS256 -setstr=use=sig write -jwks -path=my-jwk.json
```

In a compose file:

```yml
version: "3"
services:
  keygen:
    image: docker pull devnev/jwknife:latest
    command: >
      gen -rsa=2048 -setstr=use=sig -setstr=alg=RS256
      write -pubkey -pem /keys/pub.pem
      write -pubkey -jwks /keys/pub.json
      write -fullkey -pem /keys/priv.pem
      write -fullkey -jwks /keys/priv.json
    volumes:
      - keys:/keys
  api:
    build:
      context: .
    depends_on:
      keygen:
        condition: service_completed_successfully
    volumes:
      - keys:/keys:ro
volumes:
  keys:
```

## Usage

Arguments form a series of commands applied to a single JWK set.

Available subcommands:

```sh
read [-jwks] [-pem] [-insecure] [-path=path] [-url=url] [-schemes=scheme[,...]]
gen [-rsa=bits] [-ec] [-setstr=key=str] [-setjson=key=json]
write [-pubkey] [-fullkey] [-jwks] [-pem] [-path=path] [-mode=octal-mode] [-url=url] [-post] [-put] [-insecure]
```
