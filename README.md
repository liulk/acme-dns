# acme-dns "minimalist"

This is a minimalist rewrite of [acme-dns] with a number of notable
simplifications.

[acme-dns]: https://github.com/acme-dns/acme-dns

  * Uses [golang.org/x/dns/dnsmessage] for the DNS wire protocol,
    which is the same code used by golang's builtin DNS resolver.
  * Eschews self-service registration and record persistence, which
    lets us avoid sqlite3 or external databases.  See [Usage](#usage)
    below.

[golang.org/x/dns/dnsmessage]: https://pkg.go.dev/golang.org/x/net/dns/dnsmessage

This eliminates supply chain attacks targeting third-party package
maintainers.  It currently has about 560 lines.

## Usage

Install the latest version:

```sh
go install github.com/liulk/acme-dns@latest
```

The `acme-dns` server accepts the following command line flags:

  * `-domain NAME` serves authoritative DNS for domain `NAME`
    (required).

  * `-registry_dir DIR` reads the registrations from `DIR` (required).
    This is read-only to the server.  The server can generate new
    registrations, but they won't take effect until the registration
    is manually placed here.

  * `-dns_addr ADDR` listens for DNS at `ADDR` (default: `:5300` on
    any interface).  This is the port reached by ACME CA (i.e. Let's
    Encrypt) to validate the challenge token.

  * `-api_addr ADDR` listens for the HTTP API at `ADDR` (default:
    `localhost:8000`).  This is the port reached by the ACME DNS
    client to publish challenge tokens.

  * `-api_tls_cert CERTFILE` and `-api_tls_key KEYFILE` specifies that
    `-api_addr ADDR` will listen for TLS using the specified CERTFILE
    and KEYFILE.  Note we deliberately do not self-renew this
    certificate.

  * `-allow_from NET,...` specifies one or more comma separated
    netblock permitting the API source.

  * `-keep NUM` keeps the most recent `NUM` (default: `2`) TXT values
    updated through the API.

There is no config file.  Everything is read-only to the server.  The
server keeps the TXT records in memory and has no persistent state on
disk.

In a typical deployment scenario, the server should run behind a
firewall that redirects external UDP port 53 to the host's DNS port.
The ACME client would also run on the same host or on the internal
LAN.  The REST API does not need to be exposed to the WAN.

Endpoint registration must be done before attempting an ACME
challenge.  This can be done using a `POST /register` JSON request.

```console
$ curl --json '{}' -o reg.json http://localhost:8000/register
```

Example `reg.json` content:

```json
{
    "allowfrom": [
        "192.0.2.0/24",
    ],
    "fulldomain": "8e5700ea-a4bf-41c7-8a77-e990661dcc6a.acme.example.com",
    "password": "htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KW3F7Z",
    "subdomain": "8e5700ea-a4bf-41c7-8a77-e990661dcc6a",
    "username": "c36f50e8-4632-44f0-83fe-e070fef28a10"
}
```

The values for `fulldomain` (same as `subdomain` plus the origin
domain), `password`, `subdomain`, and `username` are all randomly
generated.  The `allowfrom` comes from the command line and is FYI
only.

Some notable differences from [acme-dns]:

  * The `allowfrom` in the input JSON is silently ignored.  Only the
    `-allow_from` flag in the command line is honored.

  * The registration does not take effect until someone puts
    `reg.json` into the registry specified by `-registry_dir DIR`.
    The filename must begin with the value of the `subdomain` property
    and end with the `.json` suffix,
    e.g. `8e5700ea-a4bf-41c7-8a77-e990661dcc6a.json`

An ACME client will update the endpoint's TXT record using a `POST
/update` JSON request.

```console
$ ENDPOINT_USERNAME=c36f50e8-4632-44f0-83fe-e070fef28a10
$ ENDPOINT_PASSWORD=htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KW3F7Z

$ cat <<END > update.json
{
    "subdomain": "8e5700ea-a4bf-41c7-8a77-e990661dcc6a",
    "txt": "___validation_token_received_from_the_ca___"
}
END

$ curl --json @update.json \
    -H "X-Api-User: ${ENDPOINT_USERNAME}" \
    -H "X-Api-Key: ${ENDPOINT_PASSWORD}" \
    http://localhost:8000/update
```

The TXT record is ephemeral and not preserved across server restarts.

For requesting a certificate with multiple Subject Alternative Names
(SAN), each subject name must have its own endpoint registration.

## Extension: request credentials in JSON body

As an extension to [acme-dns], the username and password can go into
the request JSON as well.  You can make a copy of `reg.json`, add the
desired `"txt"` field, and use it to update the record.

```console
$ cat <<END > update.json
{
    "subdomain": "8e5700ea-a4bf-41c7-8a77-e990661dcc6a",
    "username": "c36f50e8-4632-44f0-83fe-e070fef28a10",
    "password": "htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KW3F7Z",
    "txt": "___validation_token_received_from_the_ca___"
}
END

$ curl --json @update.json http://localhost:8000/update
```

## Extention: DNS-PERSIST-01

This implementation further supports multiple TXT string fragments per
record, which is required by DNS-PERSIST-01.  The fragments go in to
the `"txts"` field and overrides `"txt"`.

```console
$ cat <<END > update.json
{
    "subdomain": "8e5700ea-a4bf-41c7-8a77-e990661dcc6a",
    "username": "c36f50e8-4632-44f0-83fe-e070fef28a10",
    "password": "htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KW3F7Z",
    "txts": ["letsencrypt", " accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890"]
}
END

$ curl --json @update.json http://localhost:8000/update
```

The [acme-poly] client supports DNS-PERSIST-01.

[acme-poly]: https://github.com/liulk/acme-poly

## Extension: Non-API Registry Update

ACME client running on the same host as the server could write the TXT
record to the registry directly.  These records can still be updated
but the provided TXT will always be returned.

Example JSON:

```json
{
    "subdomain": "8e5700ea-a4bf-41c7-8a77-e990661dcc6a",
    "txt": "___validation_token_received_from_the_ca___"
}
```

To write more than one TXT record, write to a new file with random
character suffixes `.XXXXXXXX.json` and so on.

The server always reads from the registry directory and does not need
to be reloaded or restarted.

## Motivation

An ACME DNS server is specifically designed to automate ACME DNS
challenges and nothing more, for the purposing of obtaining [Let's
Encrypt][letsencrypt] TLS certificates through the [DNS-01] and
[DNS-PERSIST-01] challenge methods.  The DNS methods are the only ways
for issuing wildcard certificates.

[letsencrypt]: https://letsencrypt.org/
[DNS-01]: https://letsencrypt.org/docs/challenge-types/#dns-01-challenge
[DNS-PERSIST-01]: https://letsencrypt.org/2026/02/18/dns-persist-01

For the wildcard certificate `*.example.com`, instead of serving
`_acme-challenge` TXT records from the origin domain `example.com`,
the domain owner would delegate a subdomain nameserver to the ACME DNS
server (serving UDP port 53 at e.g. 203.0.113.1) with an NS record:

```dns-zone
acme.example.com.    IN NS ns.acme.example.com.
ns.acme.example.com. IN A  203.0.113.1
```

And redirect the ACME challenge record to a name record registered
with the ACME DNS server in advance (see [Usage](#usage) above),
e.g. `8e5700ea-a4bf-41c7-8a77-e990661dcc6a.acme.example.com`.

```dns-zone
_acme-challenge IN CNAME 8e5700ea-a4bf-41c7-8a77-e990661dcc6a.acme.example.com.
```

This redirection is a one-time setup.  When an ACME script like
certbot renews the certificate, it would instead publish the challenge
to the target of the CNAME.

```dns-zone
8e5700ea-a4bf-41c7-8a77-e990661dcc6a.acme.example.com. IN TXT ___validation_token_received_from_the_ca___
```

Similar redirection can be done for non-wildcard subdomains.

The main reason for doing this is that many hosted DNS server
providers do not allow scoping the access token to the DNS name being
updated.  If the ACME client possessing the access token is
compromised, it would allow the attacker to change all records within
the origin domain.

Original motivation see: <https://www.eff.org/deeplinks/2018/02/technical-deep-dive-securing-automation-acme-dns-challenge-validation>
