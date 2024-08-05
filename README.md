# JWKnife - Swiss Army Knife of JWK sets

Manipulate & Convert JWK sets.
- Read any number of keys in PEM, JWK or JWKS format into a single JWK set.
- Output some or all of the JWKs as a JWK set or PEM.

## Security

**This is Alpha software, use at your own risk**

Operations are implemented entirely using functions of the Go standard library and github.com/go-jose/go-jose module.

## Example

```sh
jwknife read -pem -path=my.pem gen -rsa=2048 -set=alg=RS256 -set=use=sig write -jwks -path=my-jwk.json
```

## Usage

Arguments form a series of commands applied to a single JWK set.

Available subcommands:

```sh
read [-jwks] [-pem] [-insecure] [-path=path] [-url=url] [-schemes=scheme[,...]]
gen [-rsa=bits] [-ec=curve] [-setstr=key=str] [-setjson=key=json]
write [-pubkey] [-fullkey] [-jwks] [-pem] [-path=path] [-mode=octal-mode] [-url=url] [-post] [-put] [-insecure]
```
