//
//  RecoveryCode.swift
//  Part of DidjiSeal: the code that locks what people keep in Didji.
//  This is the code the app ships; the app, its AutoFill, Didji for Safari and
//  the Apple Watch app all use it. References to docs/ are to Didji's own
//  design notes; what matters from them is in SPEC.md beside this package.
//
//  A printed recovery kit's code: the key, a checksum that says whether it is
//  a vault key or a kit key, and reading one back as it was typed.
//

import CryptoKit
import Foundation

extension SymmetricKey {

    /// Grouped hex for a printed recovery kit: the key, then four bytes of
    /// checksum, in nine groups of eight.
    ///
    /// The checksum is what makes a mistyped character *look* mistyped. Without
    /// it, any 64 hex characters are a perfectly valid 256-bit key, so one
    /// wrong digit silently means a different vault — and the fingerprint shown
    /// beside it would be a fingerprint of the wrong key, which reads as
    /// confirmation rather than as a warning.
    public var recoveryCode: String {
        let keyBytes = withUnsafeBytes { Data($0) }
        let hex = (keyBytes + RecoveryCode.checksum(of: keyBytes))
            .map { String(format: "%02X", $0) }
            .joined()
        return stride(from: 0, to: hex.count, by: 8).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: min(8, hex.count - offset))
            return String(hex[start..<end])
        }.joined(separator: "-")
    }

    /// A kit key's printed code: the key, then four bytes of the kit's own
    /// checksum, in nine groups of eight, laid out as `recoveryCode` is.
    public var kitCode: String {
        let keyBytes = withUnsafeBytes { Data($0) }
        let hex = (keyBytes + RecoveryCode.kitChecksum(of: keyBytes))
            .map { String(format: "%02X", $0) }
            .joined()
        return stride(from: 0, to: hex.count, by: 8).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: min(8, hex.count - offset))
            return String(hex[start..<end])
        }.joined(separator: "-")
    }

    /// A kit key's non-secret name, printed on the kit as its Kit ID. Taken
    /// over a prefix of its own, so a kit's ID can never be mistaken for a
    /// data key's Key ID (`fingerprint`) even for the same 32 bytes.
    public var kitID: String {
        let digest = SHA256.hash(data: Data("didji-kit-id".utf8) + withUnsafeBytes { Data($0) })
        return digest.prefix(6).map { String(format: "%02x", $0) }.joined()
    }

    /// Reconstructs a key from a first kit's code, the data key itself.
    public static func fromRecoveryCode(_ code: String) -> SymmetricKey? {
        if case .key(let key) = RecoveryCode.read(code) { return key }
        return nil
    }
}

/// Reading a recovery code, and saying which way it failed.
public enum RecoveryCode {

    public static let checksumBytes = 4

    /// The code's groups, three to a row, for copying out by hand: nine groups
    /// make three even rows, where one wrapped line broke wherever the width
    /// fell. The screen and the printed page both lay it out this way, so the
    /// paper and the phone look the same when checked against each other.
    public static func rows(of code: String) -> [[String]] {
        let groups = code.split(separator: "-").map(String.init)
        return stride(from: 0, to: groups.count, by: 3).map {
            Array(groups[$0..<min($0 + 3, groups.count)])
        }
    }

    // MARK: - Typing one in

    /// Eight characters to a group and nine groups: what a kit shows, and
    /// what "Replace vault key" offers boxes for — the same three-by-three
    /// grid, so a code is copied box for box rather than as one line that
    /// wraps wherever the width falls (the owner, 28 September 2026, the
    /// first time the screen was used in earnest).
    public static let groupLength = 8
    public static let groupCount = 9

    /// What somebody typed or pasted, as the code's own characters: dashes,
    /// spaces and line breaks dropped, letters uppercased. Anything else is
    /// kept, so a wrong character still reads as one rather than vanishing.
    public static func typed(_ text: String) -> String {
        String(text.uppercased().filter { !$0.isWhitespace && $0 != "-" })
    }

    /// The boxes a code fills, always `groupCount` of them, each up to
    /// `groupLength` characters, empty past the end of what was given. More
    /// than nine groups' worth is cut off: there are no boxes for it.
    public static func groups(of text: String) -> [String] {
        let characters = Array(typed(text).prefix(groupLength * groupCount))
        return (0..<groupCount).map { group in
            let start = min(group * groupLength, characters.count)
            let end = min(start + groupLength, characters.count)
            return String(characters[start..<end])
        }
    }

    /// The boxes back as one code, for reading. Empty boxes may trail (a
    /// code still being typed), never sit between filled ones: a middle box left empty gave eight groups, which read as a
    /// pre-checksum code for another key entirely, with the checksum never
    /// consulted (until 23 October 2026). Such boxes join to nothing, which
    /// reads as "not a complete code yet".
    public static func joined(_ groups: [String]) -> String {
        let filled = groups.prefix { !$0.isEmpty }
        guard groups.dropFirst(filled.count).allSatisfy(\.isEmpty) else { return "" }
        return filled.joined(separator: "-")
    }

    // MARK: - As a QR code, on the printed kit

    /// What marks a QR code as a recovery code, so Didji can tell one when it
    /// sees it — and so the New Item scanner can say what it is rather than
    /// act on it. Only "Replace vault key" accepts one. See
    /// docs/finished/qr-codes-brief.md, stage 3.
    public static let qrPrefix = "DIDJI-RECOVERY:"

    /// The text the printed kit's QR code holds.
    public static func qrText(for code: String) -> String {
        qrPrefix + code
    }

    /// The code in a scanned recovery QR code, or nil for any other.
    public static func code(fromQR text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.uppercased().hasPrefix(qrPrefix) else { return nil }
        return String(trimmed.dropFirst(qrPrefix.count))
    }

    public enum Reading: Equatable, Sendable {
        /// The vault's data key itself: every kit printed before kit keys
        /// existed (11 November 2026), and a vault's first kit.
        case key(SymmetricKey)
        /// A kit key: it opens nothing itself, and unwraps the copy of the
        /// data key kept in iCloud or in a backup (`RecoveryKitRecord`). Told
        /// apart from a data key by its checksum, taken over a prefix of its
        /// own (`kitChecksum`), so the code alone says which it is. See
        /// docs/key-hierarchy-plan.md.
        case kit(SymmetricKey)
        /// The right length, and the checksum does not match: a typo, not a
        /// different vault's code.
        case mistyped
        /// Not a recovery code at all — wrong length, or characters that are
        /// not hexadecimal.
        case notACode
    }

    public static func checksum(of keyBytes: Data) -> Data {
        Data(SHA256.hash(data: keyBytes).prefix(checksumBytes))
    }

    /// What makes a kit key's checksum its own: a data key's checksum is over
    /// the key alone, a kit key's over this and the key. Pinned by a test;
    /// changing it would turn every printed kit into "a character wrong".
    public static let kitPrefix = Data("didji-kit".utf8)

    public static func kitChecksum(of keyBytes: Data) -> Data {
        Data(SHA256.hash(data: kitPrefix + keyBytes).prefix(checksumBytes))
    }

    public static func read(_ code: String) -> Reading {
        let hex = code
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .uppercased()

        guard let bytes = bytes(fromHex: hex) else { return .notACode }

        switch bytes.count {
        // A code with no checksum (eight groups, from before 28 September
        // 2026) is no longer read, since 16 November 2026. With kit keys, the
        // first eight groups of a kit's code are the kit key's own bytes, so
        // that reading turned a kit half typed into a different vault key,
        // which Replace vault key then offered to install (the fourth code
        // review, A70). No kit a customer holds has eight groups.
        case 32 + checksumBytes:
            let keyBytes = Data(bytes.prefix(32))
            let given = Data(bytes.suffix(checksumBytes))
            // Which checksum it carries says what it is. One random code in
            // four thousand million would pass both; the data key's reading
            // comes first, as it always has.
            if checksum(of: keyBytes) == given { return .key(SymmetricKey(data: keyBytes)) }
            if kitChecksum(of: keyBytes) == given { return .kit(SymmetricKey(data: keyBytes)) }
            return .mistyped
        default:
            return .notACode
        }
    }

    private static func bytes(fromHex hex: String) -> Data? {
        guard hex.count % 2 == 0, !hex.isEmpty else { return nil }
        // Every character its own hexadecimal digit: `UInt8(_:radix:)` would
        // also take a sign, so "+A" read as the byte 10 (until 23 October
        // 2026), a mistyped character counted as right, and a pre-checksum
        // code with one in it as a different key.
        guard hex.allSatisfy(\.isHexDigit) else { return nil }
        var bytes = Data()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }
}
