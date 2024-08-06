# JWKnife - Swiss Army Knife of JWK sets

![GitHub License](https://img.shields.io/github/license/devnev/jwknife)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/devnev/jwknife/ci.yml?branch=main)

 - Read any number of keys in PEM, JWK or JWKS format into a single JWK set.
 - Generate new keys and add them to the set.
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

```
read [-jwks] [-pem] [-path=path] [-url=url] [-url.allow-plaintext]
     [-url.schemes=scheme[,...]] [-url.timeout=duration] [-url.retry.interval=duration]
     [-url.retry.backoff=float] [-url.retry.end=duration] [-url.retry.jitter=float]
gen [-rsa=bits] [-ec] [-okp] [-setstr=key=str] [-setjson=key=json]
write [-pubkey] [-fullkey] [-jwks] [-pem] [-path=path] [-path.mode=mode] [-path.mkdir=mode]
      [-url=url] [-url.post] [-url.put] [-url.allow-plaintext] [-url.timeout=duration]
      [-url.retry.interval=duration] [-url.retry.backoff=float] [-url.retry.end=duration]
      [-url.retry.jitter=float]
```

# Read

```
read [-jwks] [-pem] [-path=path] [-url=url] [-url.allow-plaintext] [-url.schemes=scheme[,...]]
     [-url.timeout=duration] [-url.retry.interval=duration] [-url.retry.backoff=float]
     [-url.retry.end=duration] [-url.retry.jitter=float]
```

Append keys to the JWK set.

The source may be given using a path or a URL. The supported URL schemes are file, http and https,
but http is only enabled when the -allow-plaintext flag is set. To further restrict the allowed
schemes, use the --scheme flag.

If -pem is given, the ssource must be a series of one or more PEM blocks. Otherwise (with -jwks
given, or neither -jwks nor -pem), the source must be either a JWK or a JWK set.

Flags:

```
-jwks                        The source must be a JWK or JWK set.
-pem                         The source must be a series of PEM blocks.
-path=path                   The path of the source file.
-url=url                     The url of the source. Supported schemes are file, http and https.
-url.allow-plaintext         Allow plaintext traffic during retrieval of the URL.
-url.schemes=scheme[,...]    The schemes to allow. Defaults to all supported if not specified.
-url.timeout=duration        Timeout for a remote read. Default is 10s.
-url.retry.interval=duration Interval after a failed remote read before retrying. Default is 1s.
-url.retry.backoff=float     Multiplier applied to the interval after each attempt. Default is 1.5.
-url.retry.end=duration      No further attempts are started if the elapsed time since the first
                             attempt exceeds this duration. Default is 1m.
-url.retry.jitter=float      Randomised addition to each interval before waiting, as a proportion
                             of the interval. Defaults to 0.1.
```

# Generate

```
gen [-rsa=bits] [-ec] [-okp] [-setstr=key=str] [-setjson=key=json]
```

Generate and append a key to the JWK set.

Key generation takes its parameters from the key's properties where possible. Specifically, EC and
OKP keys use the "alg" and/or "crv" fields to determine which elliptic curve to use.

The private key is added to the JWK set during generation. To get just the public key, use the
corresponding flags on the write command when writing keys.

Properties of the key are set using -setstr or -setjson. The "kty" property cannot be modified.
Minimal validation is applied to properties; standard JWK properties must have the correct primitive
type.

Flags:
```
-rsa=bits         Generate an RSA key with the given bit length.
-ec               Generate an EC key.
-okp              Generate an OKP key.
-setstr=key=str   Set the given property to the (unparsed) string value.
-setjson=key=json Parse the value as JSON and set the given property to the value.
```

# Write

```
write [-pubkey] [-fullkey] [-jwks] [-pem] [-path=path] [-path.mode=mode] [-path.mkdir=mode]
      [-url=url] [-url.post] [-url.put] [-url.allow-plaintext] [-url.timeout=duration]
      [-url.retry.interval=duration] [-url.retry.backoff=float] [-url.retry.end=duration]
      [-url.retry.jitter=float]
```

Write the JWK set.

The set can be written to either a path or a URL. The supported URL schemes are http and https, but
http is only enabled when the -allow-plaintext flag is set. By default, or if -pubkey is given, only
the public keys are written. Specify -fullkey to write each key in its entirety. By default, or if
-jwks is given, the keys are written as a JWK set. Specify -pem to write the keys as a series of PEM
blocks. If a path is specified, the file mode defaults to octal 0400. If a url is specified, the
request method defaults to PUT. Specify -post to use a POST request.

Flags:
```
-pubkey                      Write public key forms of each key.
-fullkey                     Write the full key for each key.
-jwks                        Write the keys as a JWK set.
-pem                         Write the keys as a series of PEM blocks.
-path=path                   Write the keys to a file at the given path.
-path.mode=mode              The permission mode of the file when a path is given.
-path.mkdir=mode             Create missing parent directories with the given permission mode.
-url=url                     Write the file to the given URL.
-url.post                    When a HTTP(S) URL is given, make a POST request.
-url.put                     When a HTTP(S) URL is given, make a PUT request.
-url.allow-plaintext         Allow plaintext traffic when writing the file using a request.
-url.timeout=duration        Timeout for a remote read. Default is 10s.
-url.retry.interval=duration Interval after a failed remote read before retrying. Default is 1s.
-url.retry.backoff=float     Multiplier applied to the interval after each attempt. Default is 1.5.
-url.retry.end=duration      No further attempts are started if the elapsed time since the first
                             attempt exceeds this duration. Default is 1m.
-url.retry.jitter=float      Randomised addition to each interval before waiting, as a proportion
                             of the interval. Defaults to 0.1.
```
