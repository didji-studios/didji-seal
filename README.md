# DidjiSeal

The code that locks what people keep in [Didji](https://didji.app), a private vault for iPhone, iPad
and Mac: the seals, the key wraps, the recovery code, and a reader for Didji's backups. Published so
that anyone can read it, check it against its test vectors, and open their own backup without the app.

- **SPEC.md**: every format, byte by byte.
- **REVIEWING.md**: where we would attack our own code.
- **SECURITY.md**: how to report a problem.
- **CHANGELOG.md**: the versions. This is 1.0.0.
- `Tests/DidjiSealTests/vectors.json`: the test vectors, made from the app's own code, with the cases
  every reader must refuse under `mustFail`.

## What "this is the code Didji ships" means, exactly

The Didji app, its AutoFill, Didji for Safari and the Apple Watch app use this package as a Swift
package dependency; it is not a copy. Each Didji release names the version of this package it was
built with, so anyone can check that a release depends on exactly that tagged source. And
`didji-open` needs no trust in our build at all: build it yourself and it opens your own backup.
(Apple's signed apps cannot be rebuilt bit for bit by anyone else, so no App Store binary, ours or
anyone's, can be proved to come from its source.)

**The rule**: everything that locks, unlocks, wraps or derives a key of Didji's own, or decides what
leaves the device about a secret, lives here. A check in Didji's own test run fails if such code
appears anywhere else. Outside, by design: making a key (Apple's random source), keeping it (Apple's
iCloud Keychain), and passkeys and sign-in codes, which are protocols Didji speaks to websites.

## Open your own backup in five minutes

You need a Mac with Xcode or the Swift toolchain, your `.didjibackup` file, and your recovery kit.

```bash
git clone https://github.com/didji-studios/didji-seal.git
cd didji-seal
swift build -c release --product didji-open
.build/release/didji-open ~/Downloads/Didji.didjibackup ~/Desktop/My-Didji
```

It asks for your recovery kit's code (typed or pasted; it is not shown, and never lands in your
shell's history), checks the backup is whole, and writes everything in it into the new folder: each
record as readable JSON, each document and photograph as its own file. **That folder holds your
vault unlocked**: keep it as safe as the kit, and delete it when done.

`didji-open` only reads the backup and reaches no network. It links Foundation and CryptoKit and
nothing else, which `otool -L .build/release/didji-open` shows. Building it yourself, as above, is
the way to be sure of what you are running.

## Checking it

```bash
swift test
```

Runs the vectors (made from the app's code before it moved here), the hostile cases (every bit of a
seal changed, cut short, the marker stripped, the format changed, moved to another record), and the
backup reader against a real backup the app made, opened with its recovery kit.

## Licence

Apache License 2.0 (LICENSE), copyright 2026 Didji Studios Ltd (NOTICE). The Didji app itself is not
open source; this package is.
