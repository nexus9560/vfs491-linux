# VFS491 SSL session layer (VCSFW command `0x11`)

Self-contained notes so this repo does not depend on the (gitignored) clones
under `reference/`. The protocol spec below is distilled from
`saifulmd0/vfs495-linux` (MIT) and `mbtech-nl/nixos-validity-VFS491` (MIT);
everything under **Measured here** is from this machine, 2026-10-16.

## Verdict, in one paragraph

Two questions drove this work. (1) Does the `0x11` tunnel open on the VFS491
without HP's patches? **No** -- the sensor answers a constant status `0x0426`
until HP's two RAM patches are uploaded (measured, see below). (2) Does the
sensor then accept a host-built SSLv3 session, or fire the VFS495's firmware
alert `0x2f`? **It accepts it -- for HP's own client.** With the patches in
place we captured the vendor session end to end (`capture/parse_hp_usblog.py`
over a `usblog.so` trace): the tunnel opens, the handshake completes with **no
`0x2f` alert**, the session carries the capture commands as TLS AppData, and a
fingerprint image comes back on EP `0x82`. So `0x2f` is **not** a sensor-wide
gate -- it is something the open VFS495 client did not do. The vendor flight
contains two messages the published open spec omitted: a **Certificate** (270 B;
the sensor's own RSA-2048 public key) and a **`0x0f` message** (256 B), sent in
answer to a **CertificateRequest** that *this* sensor puts in its ServerHello
flight. Reproducing those is the leading candidate fix for `0x2f`. The remaining
unknown is whether the sensor actually verifies the `0x0f` message: it does not
validate as an RSA signature under the sensor key by any convention we tried
(both endiannesses, e=3/17/65537).

## Measured here (2026-10-16)

`tools/vfs491_session.c` (`make run-session`), against `138a:003d` on bus 2.

| Command | Result |
| --- | --- |
| `0x01` GET_VERSION | status `0x0000`, 38 bytes (unchanged) |
| `0x19` GET_START_INFO | status `0x0000`, 68 bytes -- see `docs/protocol.md` |
| `0x11` + self-built ClientHello | status `0x0426`, 2 bytes, **no TLS record** |
| `0x11` + {nothing, zero length, truncated record, garbage} | **all** status `0x0426` |

The last row is the key measurement: the refusal does not depend on the payload
at all, so the sensor rejects at the command layer (a state gate) and never
parses the record. Sending any of this leaves the sensor healthy -- a following
GET_VERSION still succeeds.

Our ClientHello bytes (60-byte record, 63-byte command), built from the spec
without any captured template:

```
11 3c 00                          command 0x11, record length 0x003c (LE)
16 03 00 00 37                    record: handshake, SSL 3.0, length 0x37
01 00 00 33                       ClientHello, length 0x33
03 00                             client_version = SSL 3.0
<32 bytes client_random>
07 <7 bytes session id>
00 06 00 44 00 43 00 42           cipher suites: AES-256/192/128-CBC-SHA1
00                                compression: null
```

## The unlock sequence (ground truth, measured 2026-10-16)

From the full vendor init capture (`getprintwait -doinit` under `usblog.so`;
`capture/parse_hp_usblog.py` reproduces the trace). This is HP's
`scsFalconDeviceInit` as it actually runs on the VFS491:

```
OUT 01                 GET_VERSION                -> IN 38 B
OUT 19                 GET_START_INFO             -> IN 68 B
OUT 06 <692 B>         DOWNLOAD_PATCH  #1         -> IN 0000
OUT 01                 GET_VERSION                -> IN 38 B
OUT 1f <116 B>         SPI/flash read             -> IN 0000 + EP82 128 B
OUT 1f <120 B>         SPI/flash read             -> IN 0000 + EP82 4096 B
OUT 06 <1300 B>        DOWNLOAD_PATCH  #2         -> IN 0000
OUT 01                 GET_VERSION                -> IN 38 B
OUT 11 <60 B record>   SSL ClientHello            -> IN 66 B raw TLS
                                                     (ServerHello + CertificateRequest
                                                      + ServerHelloDone)
OUT 11 <874 B record>  Certificate + ClientKeyExchange + CertificateVerify
                       + CCS + Finished           -> IN 144 B raw TLS (CCS + Finished + AppData)
...                    42 AppData records (capture command + config) ...
                       scan lines / image on EP 0x82
OUT 15                 alert (teardown)           -> IN 15 alert
```

Differences from the published VFS495 spec, all measured here:

* **Patch #1** is byte-identical to `flcn_patch302810` (692 B, `falconPatchConfigList`).
* **Patch #2** (1300 B) is **not** any blob in HP's binary and is **not** the
  8-blob security-management set: it is assembled at runtime (it lands after the
  two `1f` reads, so it is sensor-state dependent). We have its bytes from the
  capture but not its origin.
* The two `0x1f` reads return the sensor's **persistent data region** (the second
  is a 4096-byte EP `0x82` read).
* **The tunnel opens after patch #2** (status `0x0000`), confirming the `0x0426`
  refusal was exactly "patches not loaded".
* The sensor answers the tunnelled ClientHello with a **raw, un-tunnelled TLS
  record** on EP `0x81` (not wrapped in `0x11`); later AppData records are raw
  `17 03 00 <len> <ciphertext>`.
* The ServerHello flight is `ServerHello + CertificateRequest + ServerHelloDone`
  (one 61-byte record). The published spec said "no Certificate is sent" and did
  not mention a CertificateRequest.
* The sensor's session id is ASCII `FALCSSL`; cipher suite `0x0044`.
* The client flight is a full **mutually-authenticated** exchange:
  `Certificate`(270) + `ClientKeyExchange`(256) + `0x0f`/CertificateVerify(256),
  then CCS + Finished. The published open spec's flight was only
  `CKE + CCS + Finished` (tunnel len `0x0154` = 340 B; the vendor's is
  `0x036a` = 874 B).
* The session ends with alert records both ways (bodies encrypted, so the
  levels/descriptions are not readable).

The two `0x06` payloads are HP's firmware patches, running in sensor RAM only.
Without them the sensor will not open the tunnel.

## Where the host gets the sensor's public key (measured)

The published spec says the host reads the sensor's RSA-2048 public key "from
sensor storage id 10" via an internal function, and that the read is not on the
wire. That is not what happens here:

* the vendor's client `Certificate` message body is
  `00 01 15 00 01 08 00 01 00 00 01 00 01 00` followed by **256 bytes**, and
* those 256 bytes are **byte-identical to the sensor's flash region** read by the
  `1f` command, at offset **`0x5b6`** in the 4096-byte read.

So the sensor's public key **is** on the wire -- it is part of the persistent
region the `0x1f` read returns, and the vendor simply echoes it back inside the
`Certificate` message. `capture/parse_hp_usblog.py` prints the `1f` reads; the
modulus is located by offset in the returned 4096-byte block.

Modulus endianness: the bytes as stored form a valid 2048-bit **odd** modulus
under *both* interpretations, so the byte order cannot be pinned offline. The
prior-art VFS495 work found its modulus is stored **little-endian** (read as
big-endian it was even, i.e. not a valid RSA modulus); ours is odd either way, so
`tools/vfs491_ssl.c` just tries `--modle` then `--modbe` against the sensor and
reports which one yields a matching Finished.

**The `0x0f` (CertificateVerify) is a real RSA signature over the handshake
transcript -- but not by the id-10 key.** Disassembly of HP's client
(`scsSSLCertificateVerifyWrite` at `0x513890`) shows the construction: hash the
handshake transcript (`scsSSLHsHashFinish`, MD5‖SHA1 = 36 B), sign it with
`scsSSLRsaPrivateEncrypt` (`0x516290`) and byte-reverse `pal`'s output onto the
wire, wrapped as handshake type `0x0f`, length `0x104`. The signing key is
installed by `scsSSLEstablishSession` (`0x515efc`) from
`scsGetDataFromStorage(ctx, 0xd, …)` -- 1184 B from **SPI-flash partition slot
13** (`scsDeserializeFromSPIFlash` → `xvfsGetRawPartitionEntry`) -- then
`palCryptoRsaCreatePrivateKeyHandle` (a `"VIRP"` key handle). That read is **not**
on the wire in our capture, so HP's client already had the key cached/derived;
here it must come from the sensor. Decoding the captured `0x0f` under the id-10
modulus (both endiannesses, e = 3/17/65537) yields neither a PKCS#1 block nor the
transcript hash, and **no** 256-byte window of the 4096-B flash image decodes to
something containing the hash. So id-10 is **not** the signer, and the signer key
is not recoverable from the two `0x1f` reads alone. Whether the sensor actually
verifies the client `0x0f` at all is now a device experiment
(`tools/vfs491_ssl.c --no-cv` / `--cv-rsa` / `--own-key`). Testing whether a dummy `0x0f` is accepted is now a one-command
experiment with `tools/vfs491_ssl.c` (default `--cv-zeros`).

## The SSLv3 spec (distilled)

Proprietary SSLv3 with custom cipher-suite IDs. All primitives are standard.
Handshake records are tunneled in `0x11`; AppData records are raw
`17 03 00 <len> <ciphertext>` on EP `0x81`.

**Cipher suites** (`id` u16 + key length): `0x0044` AES-256-CBC-SHA1 (chosen),
`0x0043` AES-192, `0x0042` AES-128. (`0x0030`-`0x0032` = pre-shared-key variant,
unused.)

**Handshake**

1. ClientHello (above): record `16 03 00 <len>`, handshake
   `01 <u24> 03 00 <32B client_random> 07 <7B session id> 00 06 <3 suites> 00`.
2. ServerHello: `16 03 00 <len> 02 <u24> 03 00 <32B server_random>
   <sid_len> <sid> 0044 00`, then ServerHelloDone `0e 00 00 00`. **No
   Certificate is sent.** The VFS495 sensor's session id is the ASCII
   `FALCSSL`.
3. **Sensor RSA public key** comes from the sensor itself, not the wire: the
   host reads it from sensor storage **id 10** (2048-bit, exp 65537, modulus
   **stored little-endian**). The host command for that storage read is *not*
   documented -- the VFS495 project read it via an internal function
   (`scsGetDataFromStorage`) and baked the dumped value. Storage id 11 is a
   certificate the host uses to validate id 10; it is not sent on the wire.
4. ClientKeyExchange: premaster = `03 00` + 46 random (48 B), RSA-encrypted
   PKCS#1 v1.5 with the sensor key -> 256 B. Record
   `16 03 00 01 04` + `10 00 01 00` + 256 B.
5. master secret and key block: SSLv3 KDF.
   PRF(secret, a, b, n) = MD5(secret + SHA1(salt + secret + a + b)) concatenated
   for salts `A`, `BB`, `CCC`, ... (salt for round i = `0x41+i` repeated i+1).
   master = PRF(premaster, client_random, server_random) (48 B);
   key block = PRF(master, server_random, client_random) (136 B) split as
   client_MAC(20) server_MAC(20) client_key(32) server_key(32) client_IV(16)
   server_IV(16).
6. ChangeCipherSpec `14 03 00 00 01 01`, then Finished, sent AES-encrypted.
   SSLv3 Finished label `'CLNT'` is hashed as the little-endian int
   `0x434c4e54` (bytes `54 4e 4c 43`), **not** as ASCII; `'SRVR'`
   (`0x53525652`) for the server.

**Record encryption** (once active): SSLv3 MAC
`SHA1(mac_key + pad2(0x5c x 40) + SHA1(mac_key + pad1(0x36 x 40) + seq[8] +
type[1] + data))` -- note the Validity variant **omits the length** from the
inner hash. seq starts at 0 and increments per record. Payload is padded to a
16-byte AES block (SSLv3 padding, last byte = padlen-1), then AES-CBC with
client_key / client_IV, chaining the previous ciphertext block as the next IV.

**Image data stays plaintext.** Even with the session up, the swipe image on
EP `0x82` is not encrypted by this layer (the VFS495 measured full-entropy data
there, so on that chip the *sensor* encrypts the image separately under keys
derived from the session; `nixos-validity-VFS491` measured the same for the
491). Either way the keys are needed.

## Reproducing this with open code

`tools/vfs491_session.c unlock P1 P2` replays the exact init above with our own
libusb client: GET_VERSION, GET_START_INFO, patch #1 (from your file), the two
`0x1f` reads (payloads built in), patch #2 (from your file), GET_VERSION, then
our ClientHello. It is the first half of an open client, and the test of whether
the `0x0426` gate really is just "patches not loaded".

`tools/vfs491_ssl.c` is the full open client. It unlocks (same sequence) and then
carries the handshake through to the sensor's Finished:

1. build a ClientHello (7 zero session-id bytes, suites `0044 0043 0042`), tunnel
   it as `11 <u16 LE len> <record>`;
2. read the raw ServerHello flight, taking `server_random` from it;
3. build `Certificate` (from the modulus) + `ClientKeyExchange` (RSA PKCS#1 v1.5
   premaster) + `CertificateVerify`(`0x0f`) into one `16` record, then CCS, then
   the AES-256-CBC Finished, all in one `0x11` tunnel -- matching the vendor
   capture byte-for-byte in structure;
4. decrypt the sensor's CCS/Finished with the server keys and **verify its
   Finished** (this is the real proof the keys agree).

The crypto ports the byte-exact-validated VFS495 work (SSLv3 MD5/SHA1 PRF,
Finished with the label as the raw LE int, Validity's length-less record MAC).
The tool has offline self-tests (`--selftest`, `--rsatest MOD`) that this repo
cross-checked against an independent Python implementation of the same spec
(identical master / key block / Finished / record bytes, and a PKCS#1 EM round
trip against a generated 2048-bit key). The one device-specific unknown -- the
modulus byte order -- is tried both ways in a single run unless pinned with
`--modle` / `--modbe`.

```
sudo ./build/vfs491_ssl P1 P2 --pubkey SENSOR_MOD.bin [--cv FILE] [--app]
```

`--cv FILE` sends a real 256-byte `0x0f` body (e.g. the one from the capture);
the default is 256 zero bytes. The experiments that probe whether/how the sensor
checks the client flight:

* `--no-cv` -- omit the `0x0f` entirely (does a missing CV change the alert?).
* `--cv-rsa` -- send a well-formed but arbitrary PKCS#1 block (format check only?).
* `--cv-premaster` -- make the `0x0f` an RSA encryption of the premaster.
* `--own-key` -- generate a fresh RSA-2048 key, put **its** modulus in the
  `Certificate`, and sign the transcript with it (standard TLS MD5+SHA1). If the
  sensor trusts the certificate we present, this completes the handshake with no
  vendor key at all.
* `--cv-rev` -- byte-reverse the signed `0x0f` body (the alternate wire order the
  vendor's copy loop hints at).

Offline validation, no device needed: `--cvselftest` exercises the
`--own-key` signing path (keygen, `md5_sha1`, sign, byte-reverse, verify).

## What an open session needs now

1. The two `0x06` patch blobs. #1 is `flcn_patch302810` in HP's
   `validity-sensor` (extractable); #2 is runtime-assembled and must be captured
   or reconstructed. Both are **vendor IP**, so they must stay outside the repo
   and be supplied by the user at runtime (the accepted model here, as prior art
   does).
2. The sensor's RSA-2048 public key -- read it live from the `0x1f` persistent
   region (offset `0x5b6` of the 4096-byte read), **not** a hard-coded constant.
   `tools/vfs491_ssl.c` currently takes it as `--pubkey FILE`; wiring the live
   `0x1f` read into it is the next step.
3. A client flight that *answers the CertificateRequest* -- the message layout is
   done in `tools/vfs491_ssl.c`. The open question is the `0x0f` signer: HP signs
   with an SPI-flash partition-13 key that is not the id-10 modulus and is not in
   the `0x1f` reads. Either the sensor pins that key (and we must read slot 13) or
   it trusts the certificate we present (`--own-key` decides which).
4. The post-handshake command protocol: the vendor sends the capture command and
   its config as encrypted AppData (`0x17` records), so learning it means
   decrypting the captured AppData now that we can reproduce the keys.


## Options (decided 2026-10-16)

* **A -- use HP's package strictly as a measurement instrument.** *Chosen.* Its
  patches open the tunnel; we captured the real handshake and showed the `0x2f`
  gate does **not** fire for the vendor client. Nothing from it enters the repo
  or the shipped driver.
* **B -- stay strictly open.** Still the shipping rule; A is measurement only.
* **C -- park the sensor.** Not taken.

## Sensor flash storage map (from the vendor `0x1f` read, 2026-10-16)

The second `0x1f` read (`1f 05 00 00 00 00 10 00 …`, `req=4096`) returns a
storage page whose first bytes are a slot table.  The page is flash
`0x1000..0x1fff`; a slot's flash offset minus `0x1000` gives its offset inside
the read.  Entries decode as `ff <id> <u32 LE offset> <u32 LE len>`:

| DataID | flash off | len  | read off | role |
|--------|-----------|------|----------|------|
| `0x0d` | `0x1100`  | 1206 | `0x100`  | client **private** key blob (RSA-2048, 1184 B used) |
| `0x0c` | `0x15b6`  | 256  | `0x5b6`  | client cert public modulus |
| `0x0a` | `0x16b6`  | 256  | `0x6b6`  | **server** public modulus (CKE) |
| `0x0b` | `0x17b6`  | 256  | `0x7b6`  | signature by `0x0a` over the sensor SS pubkey |
| `0x08` | `0x18b6`  | 96   | `0x8b6`  | misc |
| `0x0e` | `0x1916`  | 20   | `0x916`  | misc |

### Two distinct keys (the `0x2f` root cause candidate)

Disassembly of `scsSSLEstablishSession` (0x515870) shows the vendor loads the
SSL context from **two different** storage slots:

* `ctx->[0x124]` (Certificate modulus)  <- `scsGetDataFromStorage(ctx, 0x0c, …)`
  (0x515b38).  `scsSSLCertificateWrite` (0x5134a0) copies it into the client
  Certificate.  This is the key echoed in the Certificate, `--pubkey`.
* `ctx->[0x11c]` (CKE RSA public key)   <- `scsGetDataFromStorage(ctx, 0x0a, …)`
  (0x515a6e).  `scsSSLRsaPublicEncrypt` (0x5161c0) uses `ctx->[0x11c]` to
  encrypt the premaster.  **This is a different modulus** (flash `0x6b6`),
  `--cke-key`.  The old tool wrongly reused the Certificate key here.
* `ctx->[0x530]` (CV signing handle)    <- `scsGetDataFromStorage(ctx, 0x0d, …)`
  (0x515efc), 1184 B, fed to `palCryptoRsaCreatePrivateKeyHandle(0x494, …)`.

`scsSSLCertificateVerifyWrite` (0x513890) builds the 0x0f CertificateVerify.
It hashes the transcript with `scsSSLHsHashFinish` (0x513500) using sender `0`
and signs the 36-byte result with `scsSSLRsaPrivateEncrypt` (0x516290).  See
"The CertificateVerify construction" below.

`scsSensorValidateCertificate` (0x4e8dd0) only *reads* `ctx->[0x11c]` (builds a
temporary handle from key `0x0a` and RSA-verifies the slot-`0x0b` blob); it does
not replace the CKE key.

### The client private key is recoverable (slot 0x0d)

The 1206-byte slot `0x0d` blob is **not** obfuscated with a per-device secret:
it is AES-256-CBC encrypted under a hard-coded key compiled into
`validity-sensor`.  The call chain is

`scsGetDataFromStorage` (0x511c30) -> `scsGetSSProtector` (0x511990) ->
`scsDecryptWithGSKGlobal` (0x512500) -> `palCryptoDecrypt` (0x520130, algo 5)
-> `palCryptoAesCbc` (0x51fe00),  with protector id 1 = "GSKGlobal".

The GSKGlobal key is a 32-byte constant that `scsDecryptWithGSKGlobal` builds
on the stack as 32 consecutive `movb $imm, 0x40+n(%rsp)` instructions
(0x512655..0x5126f0) and then hands to `palCryptoDecrypt` as key/length 32.  It
is therefore recoverable from *your own* copy of `validity-sensor` but is a
vendor secret, so it is deliberately **not** written into this repo: the
decryption helper (and the open client) take it as a runtime input.  See
`capture/extract_hp_artifacts.py` (`--sensor-bin`).

Blob layout (version >= 2):

```
[0]      version (0x02)
[1]      0x00
[2..5]   CRC32(zlib) LE over (IV || ciphertext)
[6..21]  AES-256-CBC IV
[22..]   AES-256-CBC ciphertext
```

Decrypting the 1184-byte plaintext yields a `VIRP`-style RSA-2048 private key
whose integers are all stored **little-endian**:

| field | offset | len |
|-------|--------|-----|
| n     | `0x014` | 256 |
| p     | `0x114` | 128 |
| q     | `0x194` | 128 |
| dmp1  | `0x214` | 128 |
| dmq1  | `0x294` | 128 |
| iqmp  | `0x314` | 128 |
| d     | `0x394` | 256 |

`p*q == n`, `d*e == 1 (mod (p-1)(q-1))` and every CRT parameter checks out, so
this is a real signing key.  Its modulus `n` is **different** from both the
Certificate key (`0x0c`) and the CKE key (`0x0a`) in every byte order, and does
not appear in the 4096-byte flash page -- the sensor therefore verifies the
CertificateVerify against its own stored copy of `n`, not against the modulus
carried in the presented Certificate.  This is why the Certificate still carries
key `0x0c` while the 0x0f is signed by key `0x0d`.

### The CertificateVerify construction

`scsSSLHsHashFinish` computes the SSLv3 **Finished** construction:

```
inner_md5  = MD5 ( transcript || [sender:4] || S || 0x36 x 48 )
md5_part   = MD5 ( S || 0x5c x 48 || inner_md5 )              (16 bytes)
inner_sha1 = SHA1( transcript || [sender:4] || S || 0x36 x 40 )
sha1_part  = SHA1( S || 0x5c x 40 || inner_sha1 )             (20 bytes)
out        = md5_part || sha1_part                            (36 bytes)
```

where `S` is the 48-byte **master secret** at `ctx+8` (zeroed and then filled by
`scsSSLKeyBlockGenerate` 0x513b80; `ctx+0x48` holds the 136-byte key block).
The `[sender:4]` label is the raw little-endian bytes of a 32-bit constant
(`0x434c4e54` = "CLNT" -> bytes `54 4e 4c 43`, `0x53525652` = "SRVR" ->
`52 56 52 53`).

The 0x0f CertificateVerify is the **same construction with an empty sender
label** (`edx = 0` skips the 4-byte update), i.e. keyed only by the master
secret.  The 36-byte digest is then signed **raw** (PKCS#1 v1.5 type 1, *no*
`DigestInfo` header) with key `0x0d`, and the signature appears on the wire
standard big-endian.

Both facts were verified against the captured vendor CV:

* decrypting the captured 0x0f with `n` yields
  `00 01 FF x217 00 || <36-byte digest>` (raw, no DigestInfo);
* signing the very same digest with the recovered key reproduces the captured
  signature byte-for-byte (`build/vfs491_ssl --signraw ...`, `--cv-key`).


## Handshake confirmed on hardware (open client)

`build/vfs491_ssl` now completes the *whole* session against the real sensor:

```
== unlock ==  GET_VERSION(0x01) 4.60/104 -> GET_START_INFO(0x19) ->
              DOWNLOAD_PATCH(0x06, 692 B) -> 0x06 (1300 B) -> GET_VERSION (patch 0x07)
== handshake ==  ClientHello -> ServerHello(0044, "FALCSSL") ->
                 Certificate(274) + CKE(260) + CertificateVerify(260) + CCS + Finished
<- 14 03 00 00 01 01 | 16 03 00 00 40 <Finished> | 17 03 00 00 40 <AppData>
   [Finished] decrypted 40 bytes, verify=OK (keys agree!)
```

The client is derived from the `reference/vfs495-linux` prior art, which got as
far as a *rejected* flight (`15 03 00 00 02 02 2f`) and concluded the 0x2f alert
was an unfixable "sensor pairing gate".  **It is not.**  The prior-art PoC sent
only `ClientKeyExchange + CCS + Finished`; this client additionally sends the
`Certificate(0x0b)` and `CertificateVerify(0x0f)` messages, and the sensor
accepts it.  So the community blocker was a missing pair of handshake messages,
not a firmware gate.

### Why the server Finished verifies with a "short" transcript

The transcript hashed for Finished deliberately omits the Finished messages
themselves, because the vendor's `scsSSLHandshakeHeaderWrite` (0x513320):

```
cmp  $0x14,%r8b     ; handshake type == Finished?
je   513358         ; yes -> return WITHOUT calling scsSSLHsHashUpdate
```

returns before folding a type-0x14 message into the transcript.  So both
Finished digests cover the handshake through the CertificateVerify only
(no client Finished).  The server sender label is `0x53525652` (`52 56 52 53`).
An earlier self-check compared against a transcript that wrongly included the
client Finished and therefore reported MISMATCH; the tool now hashes through the
CV and reports `verify=OK`.

### Post-handshake application layer

* Application frames are ordinary SSL records (`17 03 00 ...`), **not** tunneled
  in the `0x11` command; only the handshake records are tunneled.
* VCSFW commands run *inside* the session.  `GET_VERSION` (0x01) sent as AppData
  returns the same 38 bytes as the plaintext pre-handshake `GET_VERSION`.
* The `reference/vfs495-linux` FINDINGS note the fingerprint-capture command is
  `0x02` and that it is **refused (status 0x0404) unless an SSL session is
  active** -- consistent with everything above.
* The sensor streams the fingerprint **plaintext** on EP `0x82` (the SSL layer
  protects only the EP `0x01`/`0x81` command channel).
* `scsSensorSendGetFingerprint_V4` (0x5065f0) builds the capture command:
  `palRealMalloc`, `movb $0x2,(%rsi)`, then two `palHostToSensor16` words
  (`0x0120`, `0x03ff`=1023 lines) and a trailing print-config blob.

`build/vfs491_ssl --cmd <hex> --image` sends an arbitrary VCSFW command inside
the session and then drains EP 0x82.



## Safety

Never send `provision`, `write_otp`, `spiflashwrite`, `setowner`, `resetowner`,
`makeprod`, `serialize`, `set_prod_opts` -- they write permanently to OTP /
flash / ownership. Everything in `tools/vfs491_session.c` is read-only
(`0x01`, `0x19`, `0x11`); the patches above only ever land in sensor RAM.
