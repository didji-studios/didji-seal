# Where we would attack our own code

A guide for anyone reviewing DidjiSeal: the places we think deserve the hardest look, and why. This
is where we would start if we were attacking it ourselves. SPEC.md has the formats;
the Didji security document has the whole design, including where its protection ends.

1. **The deterministic seal** (`VaultCrypto.sealDeterministic`). A nonce derived from the key, the
   context and a hash of the plaintext, used for a backup's own key so the export can read twice and
   write the same bytes. The argument for it is in SPEC.md, section 4. Attack: any way the same nonce
   meets two different plaintexts under one key; whether the restore's use of it under the vault key
   gives away more than "this record was restored twice".

2. **Choosing the form.** The opener reads the first seven bytes and never falls back: a blob without
   the `PVSEAL` marker is refused (the form from before binding, SPEC.md section 3), and an unknown
   format byte is named as a later Didji's. Attack: a downgrade, making one form read as another
   (`HostileTests` tries stripping the marker and changing the format byte).

3. **What the context does not cover.** Dates and the Key ID sit beside the seal; the revision is
   consistency, not freshness. Attack: what someone who can write to a person's iCloud store, but has
   no key, can achieve by rolling a record back, replaying it, or editing its labels.

4. **Format 2's length field.** A record with a key of its own reads a two-byte length, then the
   wrapped key, then the payload. Attack: lengths at and past the edges, a wrap read as a payload.

5. **Key wraps' names** (`KeyWrap.context`). Each name is a length byte and up to 255 ASCII bytes.
   Attack: two different pairs of names giving the same bytes, a wrap of one purpose opened as
   another.

6. **The recovery code.** A 32-bit checksum, two readings (kit or vault key) told apart by it, and a
   reader that accepts hyphens, spaces and lower case. Attack: a code that reads as both, a mistyped
   kit that reads as some other valid key.

7. **The backup's lists** (`BackupReader.compare`, and the app's own check). Attack: a file with
   records added, removed, reordered, duplicated or changed that still passes; photographs' pieces
   moved between photographs or into another order.

8. **`didji-open`** reads files people give it. Attack: a crafted backup that makes it write outside
   the folder it was given (file names come from the backup), read past the end of the file, or
   allocate without bound.

What is not here, on purpose: where the vault key is kept (Apple's iCloud Keychain), the app's
screens, and passkeys and sign-in codes, which are protocols Didji speaks to websites. The rule for
what must be here is in the README.

Found something? SECURITY.md says how to tell us, and we will thank you by name if you want.
