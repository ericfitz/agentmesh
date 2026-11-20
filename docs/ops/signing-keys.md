# Signing keys and certificates

The server signs the bearers it issues (`/v1/auth/token`, the human sign-in) with a key that no one stores in the database. The keys form a three-level certificate hierarchy (ADR 0019): a root that stays outside the server, one intermediate key per installation, and a short-lived leaf key that each server process makes in memory. The database holds only public material: certificates and revocation lists. Local mode (`agentmesh` over the user's own SQLite file) has none of this: no certificates, no bearers.

| Level | Key | Where the private key lives | Who signs it | Lifetime |
|---|---|---|---|---|
| Root | ECDSA P-256 from the root tool; any key Go's `crypto/x509` verifies from an outside CA | The CA's own storage, offline. The server and the database never hold it. | Itself | The root tool's default is 3650 days; an outside CA chooses |
| Intermediate | ECDSA P-256 | One key per installation: a PEM file (`intermediate_key_file`) or a key service (`intermediate_key_uri`), shared by every replica | The root | The CA chooses; the root tool's default is 365 days |
| Leaf | Ed25519 | In the memory of one server process, never written anywhere | The intermediate | `leaf_validity_hours`, W, default 168 (7 days), 2 to 720 |

No certificate carries a DNS name, an IP address or a TLS key usage: the hierarchy is not used for TLS. The intermediate and the leaf carry one extended key usage, `1.3.6.1.4.1.67669.1.1` ("agentmesh signing"), under the Private Enterprise Number IANA assigned to the publisher (ADR 0019 Decision 50); the root does not carry it. A bearer's header names its leaf by the certificate's thumbprint (`kid` and `x5t#S256`: the SHA-256 of the DER, base64url without padding). Any replica verifies a bearer by loading that leaf's row and checking the chain leaf, intermediate, pinned root: a row is never trusted for what it claims, so inserting a key into the database does not make it trusted. `GET /v1/auth/jwks` publishes one JWK per unexpired, unrevoked leaf the process has verified, each with `kid`, `x5t#S256` and `x5c` (the leaf, then the intermediate).

## What an operator must know

1. **Each installation under one root needs a name of its own** (Decision 23). The intermediate certificate's subject common name is the installation's name (the setting `installation_name`: 1 to 64 characters of `a` to `z`, `0` to `9`, `.` and `-`, starting with a letter or a digit). A server and a client accept only an intermediate that carries that name, so one installation does not accept another's bearers. Two installations that share a root and a name accept each other's bearers.
2. **An outside CA issues three things.** The installation name as the subject common name, the agentmesh extended key usage, and one subject key identifier for every certificate it issues for the same key (a hash of the public key does it). Section "A root from an outside CA" gives the profile and an `openssl` example. Nothing in agentmesh checks that two installations under an outside CA's root have different names; there it is the operator's duty.
3. **Revoking an intermediate means revoking every certificate of its key** (Decision 26). After a renewal one key has two certificates and a leaf chains through either. A root CRL lists serial numbers, so a verifier treats a key as revoked when the CRL lists a certificate of that key that the verifier holds, and a listed serial number it holds no certificate for tells it nothing about a key. List every certificate of the key. `agentmesh ca revoke` does so for the root tool's own certificates. Nobody drops an intermediate certificate, the revoked and the expired included: a CRL names a serial number and only the certificate says which key that is.
4. **`signing-key revoke` is for one leaf that a forced renewal cannot reach** (Decision 25). A forced renewal revokes the leaves that have rows in the database. A leaf that has no row (its row was removed, or the intermediate key was made to sign it outside the server) is missed. Without this command the only remedy would be to revoke the whole intermediate and every message under it. `signing-key revoke -cert FILE | -serial S` puts that one leaf on the leaf CRL (section "Revoking one leaf").
5. **Any root renewal is a new root to every client** (Decision 34), a renewal that keeps the key included. Every client needs `-accept-new-root` (section "Renewing or replacing the root"). When the root expires, bearers stop until a new root is in place and every client has accepted it.
6. **The root tool refuses a name it issued to another key** (Decision 37). `agentmesh ca sign` exits 2 and writes nothing when `state.json` records the CSR's name with a different public key, and names the flag `-same-installation`. The flag is for one installation that changes its key; a second installation passes a name of its own, not the flag. An outside CA has no such check.
7. **A single server whose renewals fail for W/2 stops serving authenticated requests until one succeeds** (spec 1 Ruling 12). Every bearer a process signs expires no later than its leaf, so once the leaf has expired and nothing renewed it, no bearer of that server is valid and nobody can read with one. With several replicas the others keep serving the bearers they signed. Health is `degraded` from the first failed renewal (`health.md`).

## A first start

A server in server mode needs a root certificate it trusts, an intermediate key and a certificate for that key, and a name. The root's directory belongs on an offline machine; this example puts everything in one directory. The four commands, run once (`-sqlite` and the three `-set` flags are the same for all of them: they are the settings of `configuration.md`, and may come from a file or `AGENTMESH_SERVER_*` variables instead):

```
$ agentmesh ca init -dir root
root root/root.pem
thumbprint 8OuA_wmPO1rdxjPlrhVUY2bZuqpC4Ajc1kPGcNfA7Xk
$ agentmesh server admin -sqlite am.db -set root_certificate_file=root/root.pem -set intermediate_key_file=intermediate.key -set installation_name=example-prod ca csr -out intermediate.csr
$ agentmesh ca sign -dir root intermediate.csr > intermediate.pem
installation example-prod
$ agentmesh server admin -sqlite am.db -set root_certificate_file=root/root.pem -set intermediate_key_file=intermediate.key -set installation_name=example-prod ca install intermediate.pem
installed mnT2J9hcnQLZuuZlAXBzf7hLxuYQdMTgKxyAsM5IYAY installation example-prod until 2027-11-16T05:20:13Z
```

- `ca init` makes `root/root.key` (PKCS#8 PEM, mode 0600; on Windows an owner-only access list instead, set on the file before any key byte is written), `root/root.pem` and `root/state.json`, and prints the thumbprint that clients can pin (`install.md`). It refuses to run when the directory already holds a root: `agentmesh ca: rootca: refused: root already holds root.pem; it never overwrites a root` (exit 2). Options: `-name NAME` (the root's common name) and `-days N` (default 3650).
- `ca sign` and `ca revoke` read `root.key` only when no other account can read or write it: mode 0600 or narrower on Unix, and on Windows an access list that names only the current user, SYSTEM and Administrators. An exposed key is refused (exit 1) with the fix named (`chmod 600 PATH`, or the `icacls` command for PowerShell and cmd.exe on Windows). On Windows the mode means nothing, so the directory's volume decides the rest: keep the root directory on a volume only the operator can read (not a shared or network drive, and not a folder a synchronization service uploads), because the file's access list does not protect a copy made elsewhere.
- `ca csr` creates `intermediate.key` (PKCS#8 PEM, mode 0600, written whole and never over an existing file) when it does not exist, then writes the request with `installation_name` as its subject common name. When the key file exists it prints a request for that key: that is how a certificate is renewed. It writes nothing to the database. With a key service the key must already exist there (see the backends below).
- `ca sign` checks the request's own signature, issues the intermediate certificate (default 365 days; `-days N`), records it in `state.json`, prints the certificate as PEM on standard output and the name on standard error.
- `ca install` checks the certificate and stores it. It must chain to the pinned root and be inside its validity period; be a CA with path length 0 and the certificate signing and CRL signing usages; carry a subject key identifier, the agentmesh extended key usage and `installation_name` as its subject common name; be for the configured key; carry the subject key identifier the stored certificates of that key carry; and not be revoked by the stored root CRL. A failing check names itself and exits 2, for example `agentmesh server admin ca: signingkeys: check failed: extended key usage: the intermediate certificate lacks the agentmesh extended key usage`. Run again with the same certificate it prints `unchanged <thumbprint>` and exits 0.

Then start the server with the same settings:

```
$ agentmesh server -listen 127.0.0.1:8451 -sqlite am.db -set root_certificate_file=root/root.pem -set intermediate_key_file=intermediate.key -set installation_name=example-prod
agentmesh server listening on 127.0.0.1:8451 (sqlite, registration open, issuer http://127.0.0.1:8451, leaf gV3TYWeKtDndfq2snaj89AKT9YPZOmgW_sSNbMzA3Ns until 2026-11-23T05:20:13Z)
```

Every start makes a fresh leaf; the line names its thumbprint and expiry. The previous process's leaf stays valid until it expires or is revoked.

### Start-up failures

| State at start | Result |
|---|---|
| `root_certificate_file` unset, unreadable or not one CA certificate | exit 2: `root_certificate_file is required` |
| The pinned root has expired | exit 2 |
| `installation_name` unset or not a valid name | exit 2: `installation_name is required` |
| Neither or both of `intermediate_key_file` and `intermediate_key_uri` | exit 2: `one of intermediate_key_file and intermediate_key_uri is required`, `at most one of intermediate_key_file and intermediate_key_uri may be set` |
| Key file missing, not owner-only or not an ECDSA P-256 key | exit 2: `intermediate.key has mode 0644, which other accounts can read or write, and holds a private key; chmod 600 intermediate.key` |
| No stored intermediate certificate that matches the configured key, is signed by the pinned root and carries this installation's name and the usage | exit 2, naming `ca csr` and `ca install` |
| The matching intermediate has expired, or the stored root CRL revokes its key | exit 2 |
| A backend scheme that is not in this build | exit 2: `intermediate_key_uri: the awskms backend is not in this build (build with -tags awskms)` |
| The key service does not answer while the first leaf is signed | exit 1 |
| `token_lifetime_seconds` or an issuer's human token lifetime above W/2 | exit 2: `token_lifetime_seconds 7200 is more than half of leaf_validity_hours 2 (3600 seconds)` |

A stored certificate or CRL that fails verification is ignored and logged with its thumbprint (`trust material ignored`); it never trusts anything and never causes a server error. `ca status` shows it (below).

### `ca status`

`agentmesh server admin ... ca status` prints, one item per line: the pinned root's thumbprint and expiry (`root`), the installation name, each stored intermediate (`intermediate <thumbprint> <not before> <not after> key=configured|other revoked=yes|no`), then `ignored intermediate <thumbprint>: <reason>` for each stored intermediate row that does not verify, in the same stream among the status lines (standard output, exit 0), then `root-crl <number>` or `root-crl none`, one `leaf-crl <key id> <number>` per leaf CRL, `trust-number <n>`, and one `leaf <thumbprint> serial <hex> until <time>` per unexpired leaf (a revoked leaf included: `signing-key list` shows the state). It makes no call to a key service. For example, after changing `installation_name` to another name, the certificate above no longer verifies:

```
$ agentmesh server admin -sqlite am.db -set root_certificate_file=outside-root.pem -set intermediate_key_file=intermediate.key -set installation_name=example-other ca status
root tJ0rOgluRTK5IdmIFB25WtptAf5eOjaIXvnxKYBNOVA until 2036-11-13T05:23:47Z
installation example-other
ignored intermediate PYJtuiFOYG2UkjYfKhDlUhg7r3e-RtOPRWgkSXw7LO0: installation name: the intermediate certificate names installation "example-prod", expected "example-other"
root-crl none
trust-number 1794806627408
```

## A root from an outside CA

Use your own CA instead of the root tool when you have one. It must issue the intermediate certificate for the public key in the request that `ca csr` prints, with this profile:

- the subject common name is the installation name (`installation_name`); any other subject attribute is ignored;
- CA true with path length 0 (critical); key usage certificate signing and CRL signing (critical);
- the subject key identifier, and the authority key identifier;
- the extended key usage `1.3.6.1.4.1.67669.1.1` (a certificate that carries only the "any" usage does not have it);
- no name constraints;
- signed with any algorithm Go's `crypto/x509` verifies; the root itself may use any such algorithm;
- the same subject key identifier on every certificate the CA ever issues for this key (a hash of the public key gives it), so the verifiers can tell which certificates share a key.

The root certificate file is one PEM certificate. An example with `openssl` (OpenSSL 4.1.0), as run by hand. The first command pair makes a stand-in outside CA; a real one already exists:

```
$ openssl ecparam -name prime256v1 -genkey -noout -out outside-root.key
$ openssl req -x509 -new -key outside-root.key -days 3650 -subj "/CN=Example Outside Root" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out outside-root.pem
$ agentmesh server admin -sqlite am.db -set root_certificate_file=outside-root.pem -set intermediate_key_file=intermediate.key -set installation_name=example-prod ca csr -out intermediate.csr
$ cat > intermediate.ext <<'EXT'
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
extendedKeyUsage = 1.3.6.1.4.1.67669.1.1
EXT
$ openssl x509 -req -in intermediate.csr -CA outside-root.pem -CAkey outside-root.key -CAcreateserial -days 365 -sha256 -extfile intermediate.ext -out intermediate.pem
Certificate request self-signature ok
subject=CN=example-prod
$ openssl x509 -in intermediate.pem -noout -subject -ext basicConstraints,keyUsage,extendedKeyUsage,subjectKeyIdentifier,authorityKeyIdentifier
subject=CN=example-prod
X509v3 Basic Constraints: critical
    CA:TRUE, pathlen:0
X509v3 Key Usage: critical
    Certificate Sign, CRL Sign
X509v3 Subject Key Identifier: 
    EE:27:2A:7D:02:E7:A5:3E:96:3C:BC:90:62:7B:C0:8D:B6:72:81:70
X509v3 Authority Key Identifier: 
    1D:05:69:D6:F3:ED:8D:9A:62:A6:DC:70:AB:D8:1A:4E:76:A1:25:CB
X509v3 Extended Key Usage: 
    1.3.6.1.4.1.67669.1.1
$ agentmesh server admin -sqlite am.db -set root_certificate_file=outside-root.pem -set intermediate_key_file=intermediate.key -set installation_name=example-prod ca install intermediate.pem
installed PYJtuiFOYG2UkjYfKhDlUhg7r3e-RtOPRWgkSXw7LO0 installation example-prod until 2027-11-16T05:23:47Z
```

`ca install` is the check: it passed. The same request signed without the `extendedKeyUsage` line is refused:

```
$ agentmesh server admin -sqlite am.db -set root_certificate_file=outside-root.pem -set intermediate_key_file=intermediate.key -set installation_name=example-prod ca install bad.pem
agentmesh server admin ca: signingkeys: check failed: extended key usage: the intermediate certificate lacks the agentmesh extended key usage
```

Keep the names apart: agentmesh cannot see the other installations under an outside root. A second installation takes a name of its own, and a key change in one installation keeps its name. To revoke an intermediate, the CA revokes every certificate it issued for the key and publishes a root CRL; then `ca install-crl` (below).

## The intermediate key: a file or a key service

Exactly one of two settings names the key (Decision 10):

| Setting | The key |
|---|---|
| `intermediate_key_file` | A PKCS#8 PEM file, mode 0600 or owner-only (checked like the credential files). The operator delivers the same file to every replica, for example as a mounted secret. The server process reads it, so whoever can read that process's memory or act as its OS user has the intermediate key and not only a leaf key. |
| `intermediate_key_uri` | `awskms://...`, `gcpkms://...`, `azurekms://...` or `hashivault://...`. The service signs in place and the private key never reaches the server. ECDSA P-256 (ES256) only: any other key type is refused when the URI is resolved. |

A scheme whose backend is not compiled into the binary stops the start with `intermediate_key_uri: the <scheme> backend is not in this build (build with -tags <scheme>)` (exit 2). The host commands exit 2 for the same configuration errors (a bad URI, a backend not in the build, an unset `AZURE_TOKEN_CREDENTIALS` for azurekms) and 1 when the key service is unavailable. Each backend is behind a build tag of the same name, so the default binary links no cloud SDK. Error messages name a key service key by its name, never by its URI.

With a key service the operator creates the key there first: the server never creates, disables, deletes or schedules the deletion of an external key. `ca csr` resolves the URI and has the service sign the request. `ca install` resolves it again and records the resolved reference (the exact key version) with the certificate, and every process signs with that reference from then on. A changed alias or a new key version therefore changes nothing for a running server. Every leaf the server issues is checked against the intermediate certificate before it is used, so a wrong reference only stops the issuing and never makes a wrong key trusted. With a key service the server calls the service for each leaf (at start and at each renewal), for each leaf CRL (a forced renewal, `signing-key revoke`, a host rotation) and once for the request.

## awskms

Build: `go build -tags awskms .` (the default binary and the release archives link no AWS SDK; the Docker image of this repository is built with this tag, `ARG BUILD_TAGS` in its `Dockerfile`).

- Key URI: `awskms://[endpoint]/{key-id|key-ARN|alias/NAME|alias-ARN}`, for example `awskms:///alias/agentmesh` or `awskms:///arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`. The optional `endpoint` is `host[:port]` and is always reached over https (for a VPC endpoint or a compatible service); leave it empty for the regional AWS endpoint. A URI that does not match is refused at start (exit 2).
- The key: an AWS KMS asymmetric key with key spec `ECC_NIST_P256`, usage `SIGN_VERIFY`, state `Enabled`. Another key spec, a disabled key or another usage is refused when the URI is resolved.
- Credentials and region come from the AWS SDK default chain (environment, shared config, container or instance role); set `AWS_REGION` or a profile region. The server stores none.
- What the server calls: `kms:DescribeKey` and `kms:GetPublicKey` when `ca csr` and `ca install` resolve the URI and again, at most every five minutes, before it signs (sigstore's signer re-reads them), and `kms:Sign` for each leaf (at start and at each renewal), each leaf CRL, and the request `ca csr` makes. Grant exactly those three actions on the key. Nothing else: the server never creates a key or an alias and never schedules a key's deletion.
- `AWS_TLS_INSECURE_SKIP_VERIFY` is not supported: sigstore honors it when signing but the key lookup does not, so the two would disagree; use a trusted certificate on the endpoint.
- Pinning: `ca install` resolves the key id or alias to the key's ARN and stores `awskms://[endpoint]/<key ARN>` as the certificate's key reference, so every leaf is signed by the key whose public half the certificate holds, even after the alias moves.
- Changing the key: create a new key and point `intermediate_key_uri` at it (an alias or the key id), then follow "Renewing the intermediate certificate, and changing its key": `ca csr`, `ca sign -same-installation`, `ca install`, restart. Repointing the alias alone changes nothing for a server that has the old ARN pinned. The server never disables or deletes the old key: retire it in KMS yourself once the leaves it signed have expired or been revoked.
- Failures: an unreachable endpoint, a timeout, throttling or an AWS 5xx is the service's own failure: `ca csr`, `ca install`, `signing-key rotate` and `signing-key revoke` answer `unavailable` (retryable, exit 1), a start that cannot sign its first leaf exits 1, and a renewal that fails is retried and shown in `GET /v1/health`. Bad credentials, a missing, disabled or wrong-type key and access-denied answers are not retryable; the host commands report the AWS message with the key name, never the URI. A malformed URI exits 2. The SDK makes up to three attempts per request before giving up, and a sign call is bounded to 30 seconds.
- Trust boundary: whoever may call `kms:Sign` on the key as the server's role can issue leaves and so mint a bearer for any identity. Keep that permission on the server's role alone and audit it with CloudTrail.

## hashivault

Build: `go build -tags hashivault .` (the default binary and the release archives link no Vault client; the Docker image of this repository is built with this tag, `ARG BUILD_TAGS` in its `Dockerfile`). The backend works with HashiCorp Vault and with OpenBao (same API); the URI scheme is `hashivault` for both, and `openbao://` is refused.

- Key URI: `hashivault://NAME`, the name of a key in Vault's transit secrets engine, for example `hashivault://agentmesh`. `NAME` is letters, digits, `_`, `-` and `.`, starting and ending with a letter, digit or `_`. Anything else (a path, a query, user info, a trailing slash) is refused at start (exit 2), and the refusal does not print the URI.
- The key: a transit key of type `ecdsa-p256` that supports signing. Another type (`ed25519`, `ecdsa-p384`, RSA), a missing key or a key whose latest version has no readable public key is refused when the URI is resolved.
- Environment, read each time the backend connects (a running process cannot see a changed value, so replace a token by restarting):
  - `VAULT_ADDR`, else `BAO_ADDR`: the Vault address, `http` or `https` with a host and no user info (required);
  - `VAULT_TOKEN`, else `BAO_TOKEN`: the Vault token (required). The Vault CLI's token helper and `~/.vault-token` are not used, and the server does not log in or renew the token: use a token that outlives the process, such as a periodic token renewed outside the server;
  - `TRANSIT_SECRET_ENGINE_PATH`: the transit mount, default `transit`; slash-separated names (`team/transit`) with no leading or trailing slash. The mount is not part of the pinned key reference, so keep it the same on every replica;
  - the Vault client's own variables also apply: `VAULT_NAMESPACE`, `VAULT_HEADERS`, `VAULT_CACERT`, `VAULT_CACERT_BYTES`, `VAULT_CAPATH`, `VAULT_CLIENT_CERT`, `VAULT_CLIENT_KEY`, `VAULT_SKIP_VERIFY`, `VAULT_TLS_SERVER_NAME`, `VAULT_PROXY_ADDR` (which supersedes `VAULT_HTTP_PROXY`) and the standard `HTTP_PROXY` family. `VAULT_CLIENT_TIMEOUT` is parsed but does not set a timeout, and the server sets no retries (one attempt per request). A malformed value of any of them fails the connection (not retryable);
  - an `http://` address sends the token in clear: use `https://` except on a loopback or otherwise trusted link.
- Time bounds: resolving the key (`ca csr`, `ca install`) and each use of it to sign are limited to 30 seconds, for every backend. A stuck connection can outlive its deadline inside sigstore's signer, which cannot be canceled; the 16-request limit below caps those.
- What the server calls: a read of `transit/keys/NAME` when `ca csr` and `ca install` resolve the URI and, at most every five minutes, before it signs (sigstore's signer reads the key to learn its type); and a write to `transit/sign/NAME/sha2-256` for each leaf, each leaf CRL and the request, asking for a pre-hashed ECDSA signature by the pinned version. The policy is exactly: `path "transit/keys/NAME" { capabilities = ["read"] }` and `path "transit/sign/NAME/sha2-256" { capabilities = ["update"] }` (with your mount in place of `transit`). The server never creates, rotates or deletes a key.
- Pinning: `ca install` reads the key's `latest_version` and stores `hashivault://NAME/VERSION` as the certificate's key reference, so every leaf is signed by the version whose public half the certificate holds, even after you add a version in Vault. The version, not the key, is what a new certificate pins.
- Changing the key: add a version in Vault (`vault write -f transit/keys/NAME/rotate`) or point `intermediate_key_uri` at another key, then follow "Renewing the intermediate certificate, and changing its key": `ca csr` (it signs with the latest version), `ca sign -same-installation`, `ca install`, restart. A running server keeps signing with the version it has pinned. Retire the old version yourself once the leaves it signed have expired or been revoked (for example by raising the key's `min_encryption_version`); the server never deletes the Vault key or a version.
- Wrong key: after Vault signs, the server verifies the signature under the key the certificate pins; a signature that does not verify (a replica with another `TRANSIT_SECRET_ENGINE_PATH` or `VAULT_NAMESPACE`, or a key deleted and recreated under the same name) is a non-retryable error, and a leaf signed by the wrong key never passes the chain check. Vault's error text in messages is limited to 256 bytes and the token is replaced by `[redacted]`; a dial error shows the Vault `host:port`. The cause is in the server log (`signingkeys: issuing the leaf failed`) and in the health document's `signing.last_failure`.
- Failures: Vault unreachable, a timeout, HTTP 429, any 5xx and a sealed or standby node (HTTP 503) are the service's own failure: `ca csr`, `ca install`, `signing-key rotate` and `signing-key revoke` answer `unavailable` (retryable, exit 1), a start that cannot sign its first leaf exits 1, and a renewal that fails is retried and shown in `GET /v1/health`. A bad or expired token (403), a missing key, a key of another type and a key whose latest version cannot be read are not retryable; the host commands report Vault's message with the key name, never the URI, the token or the request URL. A malformed URI, an unset or invalid `VAULT_ADDR` or `BAO_ADDR`, an unset `VAULT_TOKEN` or `BAO_TOKEN` and an invalid mount exit 2, at start and for the host commands. At most 16 sign requests may wait on Vault at once (sigstore's signer cannot be canceled, so a Vault that never answers is not allowed to strand more); beyond that a sign fails at once as `unavailable`.
- Trust boundary: whoever holds a token that may update `transit/sign/NAME/sha2-256` can issue leaves and so mint a bearer for any identity. Keep that token on the server alone and audit it with Vault's audit device.

## gcpkms

Build: `go build -tags gcpkms .` (the default binary and the release archives link no Google SDK; the Docker image of this repository is built with this tag, `ARG BUILD_TAGS` in its `Dockerfile`).

- Key URI: `gcpkms://projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY`, optionally followed by `/cryptoKeyVersions/VERSION` (a number of 1 or more), for example `gcpkms://projects/my-project/locations/global/keyRings/agentmesh/cryptoKeys/token-signing`. Each name is letters, digits, `_` and `-` (a project may also hold `.` and `:`). User info, a query, a fragment, a trailing slash, any other path segment and sigstore's `/versions/V` spelling are refused at start (exit 2), and the refusal does not print the URI.
- The key: a Cloud KMS key with purpose `ASYMMETRIC_SIGN` and algorithm `EC_SIGN_P256_SHA256`. With no version in the URI, `ca install` pins the `ENABLED` version with the highest number; with one, that version, which must be `ENABLED`. Another algorithm (P-384, Ed25519, RSA), another purpose, a missing key or no `ENABLED` version is refused when the URI is resolved (not retryable).
- Credentials: Application Default Credentials, found the way the Google client libraries find them, in this order: the file named by `GOOGLE_APPLICATION_CREDENTIALS` (a service account key, an authorized-user file, a workload identity federation configuration or an impersonated service account), then `~/.config/gcloud/application_default_credentials.json` (`%APPDATA%\gcloud\...` on Windows), then the metadata server of a Compute Engine, GKE or Cloud Run host (`GCE_METADATA_HOST` overrides its address). The server stores none, and asks for the `cloud-platform` scope. Other variables the libraries read and that therefore apply: `GOOGLE_CLOUD_QUOTA_PROJECT`, `GOOGLE_CLOUD_UNIVERSE_DOMAIN`, `GOOGLE_API_USE_CLIENT_CERTIFICATE`, `GOOGLE_API_USE_MTLS_ENDPOINT`, `GOOGLE_API_USE_MTLS` (deprecated spelling of the mTLS switch), `EXPERIMENTAL_GOOGLE_API_USE_S2A`, `GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED`, `GOOGLE_CLOUD_PROJECT` (the project ID the credentials report, when the credentials file names none), `GOOGLE_CLOUD_DISABLE_DIRECT_PATH`, `GOOGLE_CLOUD_ENABLE_DIRECT_PATH_XDS` and `GOOGLE_CLOUD_ENABLE_DIRECT_PATH_XDS_OVER_INTERCONNECT` (Direct Path routing), and for a federation file `AWS_*` and `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES` (set to `1` to let the file run an executable; the server never sets it). The gRPC connection to Cloud KMS follows the standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`). The server has no setting for an endpoint or a credentials path of its own. Leave `GOOGLE_SDK_GO_LOGGING_LEVEL` unset: the Google libraries read it, and at `debug` they log requests and responses.
- What the server calls (IAM permissions): `cloudkms.cryptoKeys.get` and `cloudkms.cryptoKeyVersions.get` and `cloudkms.cryptoKeyVersions.viewPublicKey` when `ca csr` and `ca install` resolve the URI, plus `cloudkms.cryptoKeyVersions.list` when the URI names no version; the same `get` and `viewPublicKey` reads once when a signer first signs (sigstore caches a pinned version for that signer's life); and `cloudkms.cryptoKeyVersions.useToSign` for each leaf, each leaf CRL and the request (`AsymmetricSign` with a SHA-256 digest). Grant exactly those on the key. The server never creates a key, a version or a key ring and never schedules a version's destruction. The permission names are from Google's IAM reference, not from the client modules, so check them against the role you grant.
- The signer's gRPC connection to Cloud KMS is held for the life of the process and never closed (the sigstore signer has no `Close`); one connection per signer.
- Pinning: `ca install` stores `gcpkms://.../cryptoKeys/KEY/cryptoKeyVersions/VERSION` as the certificate's key reference, so every leaf is signed by the version whose public half the certificate holds, even after you add or disable versions in Cloud KMS.
- Changing the key: create a new version (`gcloud kms keys versions create --key KEY --keyring RING --location LOCATION`) or point `intermediate_key_uri` at another key, then follow "Renewing the intermediate certificate, and changing its key": `ca csr`, `ca sign -same-installation`, `ca install` (with no version in the URI it pins the `ENABLED` version with the highest number), restart. A running server keeps signing with the version it has pinned. Disable or destroy the old version yourself once the leaves it signed have expired or been revoked; the server never touches the Cloud KMS key. A version you disable or destroy while it is still pinned can no longer sign, and the server then cannot issue leaves.
- Wrong key: after Cloud KMS signs, the server verifies the signature under the key the certificate pins; one that does not verify is a non-retryable error. A pinned version name is unique across Cloud KMS, so this is a guard, not an expected case. The cause is in the server log (`signingkeys: issuing the leaf failed`) and in the health document's `signing.last_failure`.
- Time bounds: resolving the key (`ca csr`, `ca install`) is limited to 30 seconds, for every backend, and makes one attempt per request (no client retry). A sign is limited by the same 30 seconds; inside it the Cloud KMS client retries an `Unavailable` or `DeadlineExceeded` answer with backoff. Reading the key the first time a signer is used runs on a context sigstore does not take from the caller, so it ends at the client's own 60-second per-call limit; a sign abandoned at its deadline leaves that read running to its end. At most 16 sign requests may be outstanding at once; beyond that a sign fails at once as `unavailable`.
- Failures: gRPC `Unavailable`, `DeadlineExceeded`, `ResourceExhausted`, `Internal` and `Unknown`, an unreachable endpoint, and a credential fetch that hit the network or a timeout (the metadata server unreachable, answering 429 or 5xx, or too slow) are the service's own failure: `ca csr`, `ca install`, `signing-key rotate` and `signing-key revoke` answer `unavailable` (retryable, exit 1), a start that cannot sign its first leaf exits 1, and a renewal that fails is retried and shown in `GET /v1/health`. `PermissionDenied`, `Unauthenticated`, `NotFound`, `InvalidArgument`, `FailedPrecondition`, no credentials found, a malformed credentials file, a key of another algorithm or purpose and no `ENABLED` version are not retryable; the host commands report Cloud KMS's message (cut at 256 bytes, and with the access token replaced by `[redacted]`) with the key name, never the URI. A malformed URI exits 2.
- Trust boundary: whoever may call `AsymmetricSign` on the key as the server's identity can issue leaves and so mint a bearer for any identity. Keep `useToSign` on the server's service account alone and audit it with Cloud Audit Logs (data access logs for Cloud KMS).

## azurekms

Build: `go build -tags azurekms .` (the default binary and the release archives link no Azure SDK; the Docker image of this repository is built with this tag, `ARG BUILD_TAGS` in its `Dockerfile`).

- Key URI: `azurekms://VAULT-HOST/KEY`, optionally followed by `/VERSION`, for example `azurekms://my-vault.vault.azure.net/token-signing`. `VAULT-HOST` is the vault's DNS name: 3 to 24 letters, digits and hyphens (starting and ending with a letter or digit) under `vault.azure.net`, `vault.azure.cn`, `vault.usgovcloudapi.net`, `managedhsm.azure.net`, `managedhsm.azure.cn` or `managedhsm.usgovcloudapi.net`. `KEY` is letters, digits and `-` (up to 127). `VERSION` is the 32 lowercase hex digits Key Vault assigns. User info, a port, an IP address or any other host, a query, a fragment, a trailing slash, any other path segment and a version in another form (`latest`, upper case) are refused at start (exit 2), and the refusal does not print the URI.
- The key: an `EC` (or `EC-HSM`) key on curve `P-256` whose key operations include `sign`, enabled, and inside its not-before and expiry times. With no version in the URI, `ca install` pins the key's current version (the one Key Vault answers for the key name); with one, that version. A key of another type or curve (P-384, P-521, P-256K, RSA, oct), without the `sign` operation, disabled, expired, not valid yet, or missing is refused when the URI is resolved (not retryable). The answer's key identifier must name the same vault, key and (when the URI has one) version, or the answer is refused.
- Credentials: the Azure SDK's default credential chain (`azidentity.DefaultAzureCredential`, azidentity v1.14.1), tried in this order until one gives a token: environment, workload identity, managed identity, the Azure CLI (`az`), the Azure Developer CLI (`azd`) and Azure PowerShell (`pwsh`). The server stores none. The variables the chain reads, checked against the module source:
  - `AZURE_TOKEN_CREDENTIALS` is required: `prod` (environment, workload identity, managed identity), `dev` (the three CLI credentials) or one credential's name (`EnvironmentCredential`, `WorkloadIdentityCredential`, `ManagedIdentityCredential`, `AzureCLICredential`, `AzureDeveloperCLICredential`, `AzurePowerShellCredential`). With it unset or empty the start refuses `azurekms://` (exit 2), because without it the chain, after the first three fail, would run `az`, `azd` or `pwsh` from the server's `PATH` and pick up any `az login` session of the service account; any other value makes building the credential fail with an error naming the variable (not retryable).
  - Environment credential: `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` with either `AZURE_CLIENT_SECRET`, or `AZURE_CLIENT_CERTIFICATE_PATH` (with `AZURE_CLIENT_CERTIFICATE_PASSWORD` and `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN`), or `AZURE_USERNAME` with `AZURE_PASSWORD`.
  - Workload identity (for example on Kubernetes): `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_FEDERATED_TOKEN_FILE`; through a token proxy also `AZURE_KUBERNETES_TOKEN_PROXY`, `AZURE_KUBERNETES_CA_FILE`, `AZURE_KUBERNETES_CA_DATA` and `AZURE_KUBERNETES_SNI_NAME`.
  - Managed identity: `AZURE_CLIENT_ID` picks a user-assigned identity; the host sets `IDENTITY_ENDPOINT`, `IDENTITY_HEADER`, `IDENTITY_SERVER_THUMBPRINT`, `IMDS_ENDPOINT`, `MSI_ENDPOINT`, `MSI_SECRET` and `DEFAULT_IDENTITY_CLIENT_ID` (App Service, Functions, Service Fabric, Arc, Cloud Shell and Azure ML); a virtual machine reaches the instance metadata service at 169.254.169.254 with none of them.
  - All credentials: `AZURE_ADDITIONALLY_ALLOWED_TENANTS` (a `;`-separated list), `AZURE_REGIONAL_AUTHORITY_NAME` and `MSAL_FORCE_REGION` (regional sign-in endpoints).
  - The CLI credentials run `az`, `azd` or `pwsh` from the server's `PATH` with that user's sign-in (`az` reads `AZURE_CONFIG_DIR`; the server does not).
  - `AZURE_ENVIRONMENT` is read by the server: `AZUREPUBLICCLOUD` or `AZURECLOUD` (the default), `AZUREUSGOVERNMENT` or `AZUREUSGOVERNMENTCLOUD`, or `AZURECHINACLOUD` picks the cloud whose sign-in authority the credential uses; any other value is the public cloud, as in sigstore. A sovereign-cloud vault host (`.azure.cn`, `.usgovcloudapi.net`) needs `AZURE_ENVIRONMENT` set to match; the server does not cross-check them. On AKS workload identity the webhook-injected `AZURE_AUTHORITY_HOST` is ignored for that reason, so without a matching `AZURE_ENVIRONMENT` the sign-in goes to the public authority and fails, without a retry. Because that choice always names an authority, `AZURE_AUTHORITY_HOST` has no effect.
  - The Azure SDK follows the standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`). `AZURE_SDK_GO_LOGGING=all` makes it log requests to standard error; leave it unset. The server has no setting for a vault endpoint or a credential of its own.
- What the server calls (permissions): one `Get Key` (`GET /keys/KEY[/VERSION]`) when `ca csr` and `ca install` resolve the URI; the same `Get Key` when a signer first signs and again after sigstore's 300-second cache of the public key expires; and one `Sign` (`POST /keys/KEY/VERSION/sign`, algorithm `ES256`, a SHA-256 digest) for each leaf, each leaf CRL and the request. In Azure RBAC for a vault those are the data actions `Microsoft.KeyVault/vaults/keys/read` and `Microsoft.KeyVault/vaults/keys/sign/action`; with an access policy, the key permissions Get and Sign; a managed HSM uses its own local RBAC roles for the same two operations. Grant exactly those on the one key (the built-in Key Vault Crypto User role grants more). The server never creates, updates or deletes a key or a version. The permission names are from Microsoft's reference, not from the SDK modules, so check them against the role you grant.
- TLS: the Azure SDK checks the vault's certificate against the system roots and requires the authentication challenge to name the vault's own domain (the SDK's check, left on).
- Pinning: `ca install` stores `azurekms://VAULT-HOST/KEY/VERSION` as the certificate's key reference, so every leaf is signed by the version whose public half the certificate holds, even after you create or disable versions in Key Vault.
- Changing the key: create a new key version (`az keyvault key rotate --vault-name VAULT --name KEY`, or import one) or point `intermediate_key_uri` at another key, then follow "Renewing the intermediate certificate, and changing its key": `ca csr`, `ca sign -same-installation`, `ca install` (with no version in the URI it pins the key's current version), restart. A running server keeps signing with the version it has pinned. Disable or delete the old version yourself once the leaves it signed have expired or been revoked; the server never touches the Key Vault key. A version you disable, or whose key you delete, while it is still pinned can no longer sign.
- Wrong key: after Key Vault signs, the server verifies the signature under the key the certificate pins; one that does not verify is a non-retryable error that names the likely causes (a replaced key version, a key that is not ES256, a reply that is not from Key Vault). The cause is in the server log (`signingkeys: issuing the leaf failed`) and in the health document's `signing.last_failure`.
- Time bounds: resolving the key (`ca csr`, `ca install`) is limited to 30 seconds, for every backend, and makes one attempt (no retry in the Key Vault client; the credential's own Azure SDK pipeline keeps its default retries, inside the 30 seconds). A sign is limited by the same 30 seconds. Sigstore's signer uses the Azure SDK's default retry (three retries from 0.8 seconds, on 408, 429, 500, 502, 503 and 504) inside it, and passes the call's context to every request. The sign runs in a goroutine so that a panic in sigstore's code (it dereferences the key type of a malformed reply unchecked) is an error and not the end of the server, and so that the caller returns at its deadline whatever the credential step is doing. At most 16 sign requests may be outstanding at once; beyond that a sign fails at once as `unavailable`.
- Failures: HTTP 408, 429 and 5xx from Key Vault or from the sign-in service, an unreachable or slow endpoint, and a context deadline are the service's own failure: `ca csr`, `ca install`, `signing-key rotate` and `signing-key revoke` answer `unavailable` (retryable, exit 1), a start that cannot sign its first leaf exits 1, and a renewal that fails is retried and shown in `GET /v1/health`. 401, 403, 404 and other 4xx, no credential found, a malformed credential setting, and a key of another type, curve or state are not retryable; the host commands report the HTTP status and Key Vault's error code (cut at 256 bytes, with the access token and the credential secrets in the environment replaced by `[redacted]`) with the key name, never the URI or the response body. One limit: the default chain joins its members' errors into text, so a network failure inside the chain (for example the sign-in endpoint unreachable) reaches the server as an authentication failure with no response and is reported as not retryable; the next command or the next renewal tries again. A malformed URI exits 2.
- Two credentials: the host commands build one default chain, and sigstore's signer builds its own (the same chain, with the cloud chosen from `AZURE_ENVIRONMENT` the same way), so both read the same environment. The signer's chain is exercised only by the opt-in live test (`AGENTMESH_LIVE_AZUREKMS_URI`); the unit tests replace sigstore's signer.
- Trust boundary: whoever may call `sign` on the key as the server's identity can issue leaves and so mint a bearer for any identity. Keep the sign permission on the server's identity alone and audit it with the vault's diagnostic logs.

## Leaf renewal

- Each process makes its leaf at start and a new one at W/2. It signs with the new one from then on; the previous one stays valid for verification until it expires, so two leaves per process are valid at any time. Each replica has leaves of its own.
- A failed renewal is retried after one eighth of the time left before the current leaf expires, never sooner than one minute. The log line is `signingkeys: issuing the leaf failed` with the error and `retry_at`; `GET /v1/health` shows the failure (administrator tier, `signing.last_failure`) and the status is `degraded` until a renewal succeeds.
- A bearer expires at the earlier of its lifetime and its leaf's "not after". The server refuses to start (exit 2) when `token_lifetime_seconds` or an issuer's human token lifetime (900 seconds when unset) is more than W/2, so a bearer minted by a healthy process always gets its full lifetime.
- When the leaf has expired and no renewal has succeeded, the token endpoint answers a retryable 503 `temporarily_unavailable`. Other requests are served as long as their bearer verifies, and on a single server none does (rule 7 above): the bearers it signed expired no later than the leaf.
- A process never signs outside its leaf's validity period as its own clock sees it; when the clock is outside it, the process treats the leaf as expired and issues a new one. A leaf's "not before" is set 60 seconds back, so a small clock difference does not make it look not yet valid. A verifier refuses a leaf valid for longer than 720 hours plus 60 seconds, the top of `leaf_validity_hours` plus that setback.
- When the process finds that its intermediate or the root has expired, or that its intermediate key is revoked, it stops issuing and signing, logs it at every reload (`signingkeys: this process no longer issues or signs leaf certificates`, with the reason) and reports it in the health document. A start in that state exits 2.
- A process that finds its own leaf on the leaf CRL issues a new one at once.

## Renewing the intermediate certificate, and changing its key

A certificate renewal is `ca csr`, `ca sign` and `ca install` again with the same key:

```
$ agentmesh server admin ... ca csr -out renew.csr
$ agentmesh ca sign -dir root renew.csr > renew.pem
installation example-prod
$ agentmesh server admin ... ca install renew.pem
installed Xppcmkidlsm3MI4_qE-6SNKwYhTjTJenIrmS-TP7rN8 installation example-prod until 2027-12-21T05:28:22Z
```

The earlier certificates stay in the table, so history signed under an expired intermediate still verifies. A running process picks the newest valid certificate for its key the next time it issues a leaf; no restart is needed. `ca sign` run twice for the same request issues two certificates with different serial numbers; both are valid until they expire or their key is revoked.

Changing the intermediate key is: point the setting at the new key; `ca csr`; have the root sign it (the shipped tool needs `-same-installation`, because the name is already recorded with the old key: Decision 37); `ca install`; restart every replica. Replicas still running with the old key keep issuing leaves under the old certificate until they restart. The old key's leaves are cut off by revoking the old intermediate (below) or expire within W.

```
$ agentmesh ca sign -dir root int2.csr
agentmesh ca: rootca: refused: the name "example-prod" is recorded with another key (8ae664d7d262afd61b4e39e0dc1ec49a4f4575af); a second installation needs a name of its own, and one installation that changes its key passes -same-installation
$ agentmesh ca sign -dir root -same-installation int2.csr > int2.pem
installation example-prod
```

(the first command exits 2 and writes nothing.) `-same-installation` is your statement that this is the same installation. Given for a new name, or for the key the name is already recorded with, it changes nothing. A name counts as taken by every certificate the tool ever issued under it, the expired and the revoked included, because clients that pinned the name would accept a new installation under it as the old one.

## Forced renewal and what it costs

A forced renewal issues a new leaf and puts every other unexpired leaf of the installation's intermediate key on the leaf CRL. It always revokes and is never refused for being too soon.

- API: an administrator runs `agentmesh signing-keys rotate [-key K]` (`POST /v1/admin/signing-keys/rotate`, which honors `Idempotency-Key`: a retry with the same key returns the first answer, counts included, and changes nothing). The answer is `current` (the new leaf), `revoked` (one entry per leaf revoked: `thumbprint` and `human_messages`) and `trust_number`. `agentmesh signing-keys list` (`GET /v1/admin/signing-keys`) shows the unexpired leaves, this process's current leaf first, each with `state` `current`, `previous`, `other` or `revoked`. A key's `not_before` and `not_after` are its chain's validity period (the leaf's, cut to the intermediate's and the root's), which equals the certificate's own unless an issuer's period is narrower. A forced renewal that finds the `trust` lock held by another process answers a retryable `unavailable`.
- Host: `agentmesh server admin ... signing-key rotate` does the lock, the reload and the CRL without issuing a leaf: it revokes every unexpired leaf under the configured key, and the running processes issue new ones. `signing-key list` prints one line per unexpired leaf. Both are run with the three trust settings:

```
$ agentmesh server admin ... signing-key list
leaf gV3TYWeKtDndfq2snaj89AKT9YPZOmgW_sSNbMzA3Ns serial 1c42295346962a65d1919c10b52132d8 2026-11-16T05:20:13Z 2026-11-23T05:20:13Z other
leaf 497oiIxPd-gADpsXyJeC27TNS4HWwIUudxVU7YpHlrE serial 49a46eb0b9f3789a1999813a4359672a 2026-11-16T05:21:49Z 2026-11-23T05:22:49Z other
trust-number 1794806413729
$ agentmesh server admin ... signing-key rotate
revoked gV3TYWeKtDndfq2snaj89AKT9YPZOmgW_sSNbMzA3Ns human-messages 0
revoked 497oiIxPd-gADpsXyJeC27TNS4HWwIUudxVU7YpHlrE human-messages 0
trust-number 1794806572985
```

The cost: whatever a revoked leaf signed stops verifying (Decision 5; Decision 16). Today that is bearers, so the caller exchanges again; the report's `human_messages` count is always 0 until human messages are signed (ADR 0019 spec 2). Nothing else is signed. Expiry alone never invalidates anything signed earlier; only revocation does. There is no re-sign path. A bearer a leaf signed is refused by the replica that revoked it at once, and by the others once they reload the trust material: at most 30 seconds (`token.ReloadInterval`), or sooner on a Postgres notification. The two commands only cut off leaves under the configured key; a leaf of another key is reported on standard error as `not-covered <thumbprint>` (see "Renewing the intermediate certificate, and changing its key").

A leaf another process issues while a rotation or revocation runs is not revoked by it: the leaf CRL lists the unexpired leaf rows present when it is built (spec section 4.8, step 5), and a row that lands afterwards is that process's own fresh leaf. The next rotation or a `signing-key revoke` covers it.

## Revoking one leaf

`agentmesh server admin ... signing-key revoke -cert FILE | -serial S` puts one leaf on the leaf CRL of the configured intermediate key, with the same lock, reload and transaction as the host rotate, and issues no leaf. Exactly one flag: with `-cert` the file is one PEM certificate that must be signed by the configured key (exit 2 otherwise); with `-serial` the number (hexadecimal, as `signing-key list` prints it, no sign, `0x` prefix or separators) is listed as given, because without the certificate nothing about it can be checked. A wrong serial number revokes nothing or, at worst, one live leaf, whose process then issues a new one. It prints one `revoked` entry with the human message count of the leaf's row (0 when it has none), and `unchanged <serial>` with exit 0 when the number is already listed:

```
$ agentmesh server admin ... signing-key revoke -serial 0abc
revoked abc human-messages 0
trust-number 1794806573103
$ agentmesh server admin ... signing-key revoke -serial 0abc
unchanged abc
trust-number 1794806573103
$ agentmesh server admin ... signing-key revoke
signing-key revoke: exactly one of -cert or -serial is required; usage: agentmesh server admin signing-key list | rotate | revoke -cert FILE | -serial S
```

(the last command exits 2.) A revoked entry stays on the leaf CRL for the life of the intermediate key, because dropping it would make that leaf's history verify again.

## Revoking an intermediate

Revoke an intermediate with the root tool, which revokes every certificate of that key, and install the CRL on the server:

```
$ agentmesh ca revoke -dir root intermediate.pem
-----BEGIN X509 CRL-----
...
-----END X509 CRL-----
revoked mnT2J9hcnQLZuuZlAXBzf7hLxuYQdMTgKxyAsM5IYAY
revoked EcBTB2xrXvBYREGZE4Ma1Pvmt4RpkrUsuYQuF-skmX4
$ agentmesh server admin ... ca install-crl root/root.crl
installed root-crl 1794806584700
```

`ca revoke` marks the certificate in the file and every other certificate of `state.json` with the same public key, names each on standard error, writes `root/root.crl` and prints the CRL as PEM on standard output. Run again when everything is already revoked, it prints the current CRL with the number unchanged. The new CRL's number is the time of issue in Unix milliseconds (or the previous number plus one when that is higher); the CRL lists every intermediate ever revoked. `ca install-crl` checks that the root signed it and that its number is above the stored one (`check failed: number N is not above the stored M`, exit 2) and stores it; the same CRL again prints `unchanged root-crl N`.

A running process finds the revoked key at its next reload (at most 30 seconds). Until then it still accepts the bearers the revoked key's leaves signed, and the same window applies to a leaf revoked on the leaf CRL (at most 30 seconds on the replicas that did not make the change). A process that finds its intermediate key revoked stops issuing and signing, logs it and reports it in the health document, and a start in that state exits 2:

```
agentmesh server: signing key: signingkeys: the stored root CRL revokes the configured intermediate key
```

A client picks the new root CRL up with its next receive, discover or watch wake (`install.md`).

## Renewing or replacing the root

The pin is the certificate (Decision 34). A root renewal is a new root to every client, a renewal that keeps the key included, and each client needs `-accept-new-root` on `register` or `login` (on `agentmesh-mcponly`, `register` or `check`). The flag prints the old and the new root and installation name and replaces the pin, the stored chain, the stored CRLs and the kept revocations; it also rebinds the pin to a changed server URL. What happens to history depends on the new certificate: a new root with another key means history signed under the old root no longer verifies for a client that has pinned the new one; a root renewed with the same key and subject name keeps history where its signed time is inside the new certificate's validity period, so a renewed certificate that starts no later than the old one keeps all history, and one that starts later loses the history before its start.

When the root expires, bearers stop, because a bearer's chain is checked at the current time, and each server process stops issuing and signing as it does for an expired intermediate (health `degraded`, the token endpoint answers 503). Signed messages from before the expiry keep verifying, because a message's chain is checked at its signed time. The way out is a new root and `-accept-new-root` on every client, so a root should live long: the root tool's default is ten years, and an outside CA's root may live much less. A start with an expired root exits 2.

## When the key service is down

- A start that cannot get the key service to sign the first leaf exits 1 (a configuration error, such as a bad URI or a missing backend, exits 2). It leaves nothing behind and the next start retries.
- While the server runs, a leaf renewal that fails is retried on the schedule above, the current leaf keeps signing until it expires, and health is `degraded` with the failure's message (redacted and capped by the backend, never the URI). Verification keeps working, because it needs only certificates and CRLs from the database.
- `ca csr`, `ca install`, a forced renewal and `signing-key revoke` answer `unavailable` (retryable; exit 1 for the host commands) and change nothing.

## Trust boundary

- The database holds no private key: it holds certificates and CRLs, which are public, and a forged row is never trusted. Reading the database or a backup does not let anyone mint a bearer. Writing the database is still administrator-equivalent (it can change administrator flags and keys of identities), as before.
- Whoever holds the intermediate key file, or may ask the key service to sign with the intermediate key, can issue leaves and so mint bearers for any identity. Keep the file as secret as the database credential; keep the sign permission on the server's identity alone.
- Whoever can read a server process's memory has its leaf key, and mints bearers until the leaf expires or is revoked.
- Whoever can write the database can hide a revocation from a process or a client that has not seen it yet by putting back an older CRL; a process that restarts forgets what it had seen, a client does not. For bearers the harm ends when the hidden leaf expires. A forced renewal lists the leaves from the table, so a writer who removed a leaf's row first keeps that leaf off the CRL until it expires; `signing-key revoke` lists it once its certificate or serial number is known.

## Backups

The database holds no private key, so a backup does not hold one either. A restore puts back the CRLs and the trust number of the backup; `backup.md` says what to run after one.
