# DidjiSeal: the formats, byte by byte

This is how Didji locks what people keep in it, written so that anyone can check the code against it
or write their own reader. Where this and the code differ, the code is what ships and this document
is wrong: please report it (SECURITY.md).

Every primitive is Apple's CryptoKit, except PBKDF2, which is Apple's CommonCrypto. Nothing here is
invented: AES-256-GCM, HKDF-SHA256, HMAC-SHA256, SHA-256, PBKDF2-HMAC-SHA256. Integers are
big-endian unless a section says otherwise. UUIDs are their 16 bytes in RFC 4122 order.


## 1. Keys

Every key is 32 random bytes from the system's secure random source
(`SymmetricKey(size: .bits256)`).

| Key | Seals | Lives |
|---|---|---|
| Vault key | every record | the person's iCloud Keychain, synchronised to their devices |
| Kit key | nothing directly: wraps a copy of the vault key and each backup's key | printed on the recovery kit |
| Backup key | one backup | inside that backup, wrapped twice (section 5) |
| Space key | what is shared with one person | the vault (sealed), and the sharing code given to that person |
| Watch key | the records put on an Apple Watch | the watch and its paired iPhone, never synchronised |
| Emergency key | the emergency copy | one device, never synchronised |

**Key ID**: the first 6 bytes of SHA-256 over the key, as 12 lowercase hex characters. Not secret.
Each sealed record carries the Key ID of the key that sealed it, so a record under another key is
named as such. The Key ID is a label beside the seal and is not authenticated.

**Kit ID**: the first 6 bytes of SHA-256 over `"didji-kit-id"` (ASCII) followed by the kit key, as 12
lowercase hex characters. Not secret.


## 2. A record's context

Every record is sealed with authenticated data that says what it is and where it belongs. The
context is never stored: the opener rebuilds it from the record's envelope, so an envelope swapped
onto another record's seal fails to open.

```
offset  length  field
0       6       "PVSEAL" (ASCII)
6       1       format: 1 (sealed with the key itself) or 2 (a key of its own)
7       1       record kind (table below)
8       16      the record's UUID
24      1       1 if a parent follows, else 0
25      16      the parent's UUID, only if present
+       4       revision, UInt32
+       4       chunk index, UInt32, media chunks only
+       4       chunk count, UInt32, media chunks only
```

Kinds (wire values, never renumbered): 1 record, 2 document details, 3 document bytes, 4 passkey,
5 category, 6 person or place, 7 template, 8 settings, 9 logo cache, 10 address cache, 11 a backup's
list of contents, 12 photo details, 13 photo thumbnail, 14 photo piece, 15 album, 16 sharing
connection, 17 to 20 a shared record, document details, document bytes and passkey, 21 a shared
space's list, 22 a reply to an invitation, 23 a record's earlier version, 24 text read from
documents, 25 a password AutoFill held, 26 when records were used, 27 downloaded website lists, 28 a
room, box or move, 29 the access log, 30 a change to a shared record.

What the context covers: kind, id, parent, revision, and a chunk's place. What it does not: the
record's created and changed dates and its Key ID, which sit beside the seal. The revision gives
consistency, not freshness: someone able to write to the store can put back an older copy of a whole
record. In a backup the dates and Key IDs are covered too, by the backup's sealed list (section 5).


## 3. A sealed record

**Format 1**, sealed with the key itself:

```
"PVSEAL" | 0x01 | nonce (12) | ciphertext | tag (16)
```

AES-256-GCM, a fresh random 96-bit nonce for every seal, the context (section 2, format byte 1) as
the authenticated data.

**Format 2**, a key of its own:

```
"PVSEAL" | 0x02 | length n (UInt16) | wrapped key (n) | sealed payload
```

A fresh 256-bit key is made for the record. The wrapped key is that key sealed (AES-256-GCM, random
nonce, combined form) under the vault key with the context at format 2 plus one byte `0x01` as the
authenticated data; the payload is sealed under the record's key with the context at format 2. The
extra byte means the wrap and the payload never authenticate the same bytes.

**Before binding**: records sealed before contexts existed (16 September 2026) were the GCM combined
form alone (nonce, ciphertext, tag) with no authenticated data. Only the makers' own vaults ever held
any, and every one was resealed in format 1; since 25 November 2026 a record in this form is refused.
Its vector stays, as one that must fail.

**Choosing how to open**: by the first seven bytes, never by trying one form and falling back. A blob
beginning `PVSEAL` and a format byte is opened as that format and nothing else; a failure is a
failure. A blob beginning `PVSEAL` with an unknown format byte is refused as "made by a newer Didji". Anything
else is refused. (The Apple Watch's copy is sealed apart, under the watch key, as a combined form with
no context; it never passes through a record's opener.)

**What is sealed** is the record as JSON (dates ISO 8601), except a document's bytes, a photograph's
thumbnail and its pieces, which are sealed as they are.


## 4. Nonces

- Every seal outside a backup uses a fresh random 96-bit nonce from CryptoKit. A vault is far below
  the 2^32 messages per key that random 96-bit nonces allow: a vault of 100,000 records resealed
  daily for a century is under 2^32.
- **Inside a backup**, records are sealed under the backup's own key with a nonce derived from what is
  sealed, so the export, which reads the photographs twice, produces the same bytes both times:

  ```
  nonceKey = HKDF-SHA256(ikm: backup key, info: "PVSEAL nonce", 32 bytes)   (no salt)
  nonce    = first 12 bytes of HMAC-SHA256(nonceKey, context || SHA-256(plaintext))
  ```

  A nonce repeats only for the same key, the same context and the same plaintext, which gives the
  same ciphertext and reveals nothing new. Each backup's key is fresh, so nothing ties one backup to
  another. A restore uses the same form under the vault key: the one thing that gives away is that a
  record restored twice into one vault has the same bytes both times.


## 5. Backups

**The file**: either the JSON alone (it begins `{`), or a container:

```
"DIDJIBK" | 0x01 | frames...
frame:  kind (1) | header length (UInt32, little-endian) | header (JSON)
        | body length (UInt64, little-endian) | body
kinds:  1 the JSON backup (no header) | 2 the sealed list of the media that follows (no header)
        | 3 an album | 4 a photo or video (its sealed details in the header, its thumbnail as the body)
        | 5 one piece of a photo or video
```

**The JSON** (format 6) holds the records, each with its id, revision, dates, Key ID and sealed
payload; `keys`; and `manifest`, the sealed list of contents.

**The backup key**, made fresh for each backup, seals every record in it (section 4). It is carried
twice in `keys`, each a key wrap (below): `forVault` under the vault key (purpose 3), and `forKit`
under the kit key current that day (purpose 4), with `kitID`. So the kit of that day opens that
backup and nothing else: never the vault, never a later backup.

**The lists**: `manifest` (the record list, context kind 11, the backup's id, revision 1) and the
container's frame 2 (the media list, revision 2), each sealed under the backup key, name every sealed
blob in the file: kind, id, parent, piece index, revision, dates, Key ID and the SHA-256 of the sealed
bytes. A reader refuses the whole file if anything is added, removed, duplicated or changed, before
opening any of it. A format 6 backup without its list is refused.

**Key wraps** (`KeyWrap`): a 32-byte key sealed under another with AES-256-GCM, random nonce, combined
form, and this authenticated data:

```
"PVKIT" | 0x01 | purpose (1) | n (1) | first name (n, ASCII) | m (1) | second name (m, ASCII)
purposes: 1 vault key under a kit key (names: Kit ID, vault Key ID)
          2 kit key under the vault key (names: Kit ID, vault Key ID)
          3 backup key under the vault key (names: backup Key ID, vault Key ID)
          4 backup key under a kit key (names: backup Key ID, Kit ID)
```


## 6. The recovery code

The kit prints a key and a 4-byte checksum, 36 bytes as 72 uppercase hex characters in nine groups
of eight, joined by hyphens. The checksum says what the key is:

- **Kit key**: first 4 bytes of SHA-256 over `"didji-kit"` (ASCII) followed by the key.
- **Vault key** (a vault's first kit, and every kit before 11 November 2026): first 4 bytes of
  SHA-256 over the key.

A code whose checksum matches neither is mistyped. Codes of eight groups (no checksum) are not read.
The printed square code holds `DIDJI-RECOVERY:` followed by the code.


## 7. Smaller pieces

- **The Didji passcode** is a lock on the app, not on the data: it derives no key. The vault keeps a
  16-byte random salt and PBKDF2-HMAC-SHA256 (600,000 rounds, 32 bytes) over the passcode in Unicode
  canonical composition (NFC), and compares in constant time.
- **The password check** sends the first 5 hex characters of a password's SHA-1 to Have I Been
  Pwned's range service, with padding asked for, and compares the rest on the device.
- **Password fingerprints**: SHA-256, unsalted, 8 bytes for the reuse and breach checks, 32 for a
  password AutoFill held. Only in memory or inside a sealed record.
- **The emergency copy**: AES-256-GCM under its own key, random nonce, combined form, authenticated
  data `"didji-emergency-copy-1"`. Readable by anyone holding the unlocked phone, by design.


## 8. Versions

This document describes backup format 6, container version 1, seal formats 1 and 2, and key wrap
format 1. A later format raises its number under the same marker, so an older reader names it as
newer and touches nothing. The test vectors (`Tests/DidjiSealTests/vectors.json`) and the fixture
backup are tagged with the formats they hold and stay for good: every later Didji must still read
what 1.0 wrote. The vectors' `mustFail` cases, each one change to a recorded seal or key wrap, are
ones every reader must refuse; only the one marked `newerFormat` is to be named as a later Didji's.
