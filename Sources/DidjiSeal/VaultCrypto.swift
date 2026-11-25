//
//  VaultCrypto.swift
//  Part of DidjiSeal: the code that locks what people keep in Didji.
//  This is the code the app ships; the app, its AutoFill, Didji for Safari and
//  the Apple Watch app all use it. References to docs/ are to Didji's own
//  design notes; what matters from them is in SPEC.md beside this package.
//
//  AES-256-GCM, through Apple's CryptoKit. Everything a person keeps in
//  Didji is sealed here before it is stored, so iCloud only ever holds
//  opaque blobs. The app adds, in its own module, the reading and writing of
//  its records as JSON and the words its errors are shown in.
//

import CryptoKit
import Foundation

public enum VaultCryptoError: Error {
    case decryptionFailed
    case keyFingerprintMismatch(expected: String, found: String)
    /// Sealed in a form this build does not know: a later Didji wrote it.
    /// Its own case since 16 November 2026, so the vault says "needs a newer
    /// version" and not "may be damaged", which is false and offers no way
    /// forward (the fourth code review, door 1, W1.2). A version that is
    /// never updated will meet this the day a later one changes the seal.
    case newerFormat
}

public struct VaultCrypto: Sendable {

    public let key: SymmetricKey
    /// Tries every record with this key whatever its Key ID says, so the
    /// label, which the seal does not authenticate, is judged only after
    /// the attempt to open. For the way out of a vault where nothing can be
    /// changed alone, which must never remove a record that opens (the
    /// fourth code review, A159); everything else refuses a record labelled
    /// another key's before trying it.
    public let readsPastLabels: Bool

    public init(key: SymmetricKey) {
        self.key = key
        readsPastLabels = false
    }

    public init(key: SymmetricKey, readsPastLabels: Bool) {
        self.key = key
        self.readsPastLabels = readsPastLabels
    }

    public var fingerprint: String { key.fingerprint }

    private func checkFingerprint(_ recordFingerprint: String) throws {
        guard readsPastLabels || recordFingerprint.isEmpty || recordFingerprint == fingerprint else {
            throw VaultCryptoError.keyFingerprintMismatch(
                expected: fingerprint,
                found: recordFingerprint
            )
        }
    }

    public func seal(raw plaintext: Data, context: SealContext) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: context.bytes)
        guard let combined = box.combined else { throw VaultCryptoError.decryptionFailed }
        return SealContext.marker + combined
    }

    /// As `seal(raw:context:)`, with the nonce taken from the key, the context
    /// and the plaintext rather than at random, so the same record sealed twice
    /// gives the same bytes. Made for a backup's own key, which is fresh for
    /// each backup and seals each record once: the export reads the photos
    /// twice (once to list them in the manifest, once to write them), and both
    /// passes must produce what the manifest's digests describe. **A restore
    /// uses it too, under the vault's own key** (`BackupSealer.blob`, with the
    /// vault as its target), which this comment denied until 16 November 2026
    /// (the fourth code review, A83). That is sound all the same: a nonce
    /// repeats only for the same key, context and plaintext, which gives the
    /// same ciphertext and nothing else, so the one thing given away is that
    /// a record restored twice into one vault has the same bytes. Opened by `open(raw:recordFingerprint:context:)`
    /// like any bound blob. See docs/key-hierarchy-plan.md, section 4.
    public func sealDeterministic(raw plaintext: Data, context: SealContext) throws -> Data {
        let nonceKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: key, info: Data("PVSEAL nonce".utf8),
                                              outputByteCount: 32)
        var input = context.bytes
        input.append(contentsOf: SHA256.hash(data: plaintext))
        let mac = HMAC<SHA256>.authenticationCode(for: input, using: nonceKey)
        let nonce = try AES.GCM.Nonce(data: Data(mac).prefix(12))
        let box = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: context.bytes)
        guard let combined = box.combined else { throw VaultCryptoError.decryptionFailed }
        return SealContext.marker + combined
    }

    /// Opens a blob of either form, chosen by the marker in front of it — never
    /// by trying one and falling back when it fails.
    ///
    /// That distinction is the whole protection. An opener that tried the bound
    /// form and fell back on failure could be downgraded by anyone who could
    /// corrupt the context: the bound open would fail, the fallback would accept
    /// the blob unbound, and moving ciphertext between records would work again.
    /// So: a blob carrying the marker is opened bound, and a failure is a
    /// failure; one without it is from before binding and is refused; a marker
    /// with an unknown format is refused as a later Didji's.
    public func open(raw sealed: Data, recordFingerprint: String, context: SealContext) throws -> Data {
        // A later Didji's form, said before the key is looked at: such a
        // record may be under a key of that Didji's own, and until 17
        // November 2026 that read as "locked with a different vault key",
        // whose remedy (put the other key back) would have been the wrong
        // one (the fourth code review, A136).
        if Self.isLaterFormat(sealed) { throw VaultCryptoError.newerFormat }
        try checkFingerprint(recordFingerprint)

        guard let (format, body) = Self.boundBlob(sealed) else {
            // The form from before binding (16 September 2026): refused since
            // 25 November 2026, once the makers' devices, the only ones that
            // ever held it, counted none left (docs/code-review.md, decision 1).
            throw VaultCryptoError.decryptionFailed
        }
        switch format {
        case SealContext.currentFormat:
            guard format == context.format else { throw VaultCryptoError.decryptionFailed }
            do {
                let box = try AES.GCM.SealedBox(combined: body)
                return try AES.GCM.open(box, using: key, authenticating: context.bytes)
            } catch {
                throw VaultCryptoError.decryptionFailed
            }

        case SealContext.wrappedFormat:
            return try openWrapped(body: body, context: context)

        default:
            // A format this build does not know. Refused rather than guessed
            // at, like every other unknown marker here, and by name: a later
            // Didji wrote it.
            throw VaultCryptoError.newerFormat
        }
    }

    // MARK: - A key of its own, wrapped under the vault key

    /// Seals with a key made for this record alone, wrapped under the vault
    /// key. See docs/finished/key-hierarchy-brief.md.
    ///
    ///     0   6   domain, ASCII "PVSEAL"
    ///     6   1   format, 2
    ///     7   2   wrapped key length, big-endian
    ///     9   n   the record's key, sealed under the vault key
    ///     +   -   the payload, sealed under the record's key
    ///
    /// Both halves authenticate the record's context, so neither the payload
    /// nor the key that opens it can be moved to another record — and the
    /// length is read rather than assumed, so a later key or nonce size does
    /// not silently shift the payload.
    public func sealWrapped(raw plaintext: Data, context: SealContext) throws -> Data {
        let context = context.withFormat(SealContext.wrappedFormat)
        let dataKey = SymmetricKey(size: .bits256)
        let dataKeyBytes = dataKey.withUnsafeBytes { Data($0) }

        let wrapped = try AES.GCM.seal(dataKeyBytes,
                                       using: key,
                                       authenticating: context.wrapBytes)
        let payload = try AES.GCM.seal(plaintext,
                                       using: dataKey,
                                       authenticating: context.bytes)

        guard let wrappedKey = wrapped.combined,
              let body = payload.combined,
              wrappedKey.count <= Int(UInt16.max)
        else { throw VaultCryptoError.decryptionFailed }

        var blob = SealContext.domain
        blob.append(SealContext.wrappedFormat)
        blob.append(contentsOf: withUnsafeBytes(of: UInt16(wrappedKey.count).bigEndian) { Array($0) })
        blob.append(wrappedKey)
        blob.append(body)
        return blob
    }

    private func openWrapped(body: Data, context: SealContext) throws -> Data {
        let context = context.withFormat(SealContext.wrappedFormat)

        guard body.count > 2 else { throw VaultCryptoError.decryptionFailed }
        let start = body.startIndex
        let length = Int(body[start]) << 8 | Int(body[start + 1])
        let rest = body.dropFirst(2)
        guard rest.count > length else { throw VaultCryptoError.decryptionFailed }

        do {
            let keyBox = try AES.GCM.SealedBox(combined: rest.prefix(length))
            let dataKey = SymmetricKey(
                data: try AES.GCM.open(keyBox, using: key, authenticating: context.wrapBytes)
            )
            let box = try AES.GCM.SealedBox(combined: rest.dropFirst(length))
            return try AES.GCM.open(box, using: dataKey, authenticating: context.bytes)
        } catch {
            throw VaultCryptoError.decryptionFailed
        }
    }

    /// Whether a stored blob is bound, and its body if so. Nil for the older
    /// form, whose first bytes are a random nonce.
    ///
    /// The chance of a legacy blob's nonce beginning with the six-byte domain
    /// is one in 2^48; such a blob is then read as bound, and either its format
    /// byte is unknown and it is refused, or — one in 2^56 overall — it reaches
    /// the bound opener and fails to authenticate. Either way it is refused
    /// rather than mis-opened, so the cost is a record that reads as damaged,
    /// not a record opened as the wrong thing.
    public static func boundBlob(_ sealed: Data) -> (format: UInt8, body: Data)? {
        let markerLength = SealContext.domain.count + 1
        guard sealed.count > markerLength,
              sealed.prefix(SealContext.domain.count) == SealContext.domain
        else { return nil }
        let format = sealed[sealed.startIndex + SealContext.domain.count]
        return (format, sealed.dropFirst(markerLength))
    }

    public func isBound(_ sealed: Data) -> Bool { Self.boundBlob(sealed) != nil }

    /// Whether a stored blob says it was sealed in a form this build does
    /// not know: the six-byte domain, and then a format that is neither of
    /// this build's two. Read from the blob's first seven bytes alone, with
    /// no key and nothing opened, so anything that works on the store
    /// directly can ask before it writes over a record or deletes one.
    ///
    /// **This is the one thing a later Didji can count on this build to
    /// read.** Whatever it changes about how a record of a kind this build
    /// knows is sealed (what is authenticated with it, the kind it is
    /// sealed as, the key it is under, what it belongs to), it must raise
    /// the format byte under the same domain: then this build says "needs a
    /// newer Didji" and leaves the record alone. Anything else it changes
    /// reads here as damage (`VaultHealth`).
    public static func isLaterFormat(_ sealed: Data) -> Bool {
        guard let (format, _) = boundBlob(sealed) else { return false }
        return format != SealContext.currentFormat && format != SealContext.wrappedFormat
    }

    /// Thrown before this build seals over a blob a later Didji sealed: the
    /// record's seal helpers each ask, so no save here (a star from a copy
    /// in memory read before the later Didji's arrived, say) can write over
    /// what it could not have read (A136).
    public static func refuseToSealOver(_ stored: Data...) throws {
        for blob in stored where isLaterFormat(blob) { throw VaultCryptoError.newerFormat }
    }

    // MARK: - Raw bytes (attachments)

    public func seal(raw plaintext: Data) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: key)
        guard let combined = box.combined else { throw VaultCryptoError.decryptionFailed }
        return combined
    }

    public func open(raw sealed: Data, recordFingerprint: String) throws -> Data {
        try checkFingerprint(recordFingerprint)
        // A bound blob never opens here: without its context it cannot
        // authenticate, and its marker is not part of the box.
        do {
            let box = try AES.GCM.SealedBox(combined: sealed)
            return try AES.GCM.open(box, using: key)
        } catch {
            throw VaultCryptoError.decryptionFailed
        }
    }
}

// Here rather than beside the keychain plumbing it came from, because it is
// pure CryptoKit and the watch needs it: every sealed record carries the
// fingerprint of the key that sealed it, and a watch opening its own subset
// checks it exactly as the phone does.
extension SymmetricKey {

    /// A short, non-secret identifier for this key. Stored alongside every
    /// encrypted record so a key mismatch is detected as a clear error rather
    /// than as silent decryption failure.
    public var fingerprint: String {
        let digest = SHA256.hash(data: withUnsafeBytes { Data($0) })
        return digest.prefix(6).map { String(format: "%02x", $0) }.joined()
    }
}
