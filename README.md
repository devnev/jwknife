# JWKnife - Swiss Army Knife of JWK sets

![GitHub License](https://img.shields.io/github/license/devnev/jwknife)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/devnev/jwknife/ci.yml?branch=main)

Manipulate & Convert JWK sets.
- Read any number of keys in PEM, JWK or JWKS format into a single JWK set.
- Output some or all of the JWKs as a JWK set or PEM.

## Security

**This is Alpha software, use at your own risk**

Operations are implemented entirely using functions of the Go standard library and github.com/go-jose/go-jose module.

The command format is designed to be unambiguous; possible interpretations of a flag's value must be non-overlapping (e.g. separate `-path` and `-url` flags instead of trying to detect if the value is a valid URL). Risky behaviour like outputting private keys or use plaintext protocols require an individual boolean flag to explicitly allow them (e.g. `-allow-plaintext` or `-fullkey`).

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
read [-jwks] [-pem] [-allow-plaintext] [-path=path] [-url=url] [-schemes=scheme[,...]]
gen [-rsa=bits] [-ec] [-okp] [-setstr=key=str] [-setjson=key=json]
write [-pubkey] [-fullkey] [-jwks] [-pem] [-path=path] [-mode=octal] [-mkdir=octal] [-url=url] [-post] [-put] [-allow-plaintext]
```
