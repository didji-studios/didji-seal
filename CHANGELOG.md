# Changes

Each Didji release names the version of DidjiSeal it was built with. A version changes the formats
only by raising a format number (SPEC.md, section 8); everything an earlier version wrote still opens.

## 1.0.0, 25 November 2026

The first published version: the code that locks Didji, moved out of the app unchanged and held to
test vectors made from the app before the move.

- **Seals**: record seals in format 1 (sealed with the key itself) and format 2 (a key of its own),
  each tied to its record; the deterministic seal used inside backups.
- **Key wraps**, the **recovery code**, the **Didji passcode**'s derivation, the **password check**'s
  range lookup, **password fingerprints** and the **emergency copy**'s seal.
- **DidjiBackupReader** and **`didji-open`**: open a Didji backup with its recovery kit, without the
  app, refusing a file that is altered, cut short, from a later Didji, or for another kit.
- **The form from before binding is refused.** Records sealed before 16 September 2026 carried no
  marker and no tie; only the makers' own vaults ever held any, all were resealed, and this version
  opens none.
- **Test vectors**, including sixteen cases every reader must refuse (`mustFail` in `vectors.json`).
