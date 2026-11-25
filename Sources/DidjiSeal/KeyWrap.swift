//
//  KeyWrap.swift
//  Part of DidjiSeal: the code that locks what people keep in Didji.
//  This is the code the app ships; the app, its AutoFill, Didji for Safari and
//  the Apple Watch app all use it. References to docs/ are to Didji's own
//  design notes; what matters from them is in SPEC.md beside this package.
//
//  How the recovery kit and backups carry keys: one key sealed under another.
//

import CryptoKit
import Foundation

/// A wrapped key that will not open, or is not a key.
public enum KeyWrapError: Error, Equatable {
    case damaged
}

/// One 32-byte key sealed under another, bound to what it is for and to both
/// keys' names, so a wrapped key cannot be passed off as another, or moved
/// between kits, vaults or backups.
public enum KeyWrap {

    /// What the sealed key is. Wire format: authenticated, never renumber.
    public enum Purpose: UInt8, Sendable {
        /// The data key, sealed under a kit key.
        case dataKey = 1
        /// A kit key, sealed under the data key.
        case kitKey = 2
        /// A backup's own key, sealed under the data key (`BackupKeys`).
        case backupKeyForVault = 3
        /// A backup's own key, sealed under a kit key (`BackupKeys`).
        case backupKeyForKit = 4
    }

    public static let domain = Data("PVKIT".utf8)
    public static let format: UInt8 = 1

    /// The exact bytes authenticated with the ciphertext:
    ///
    ///     0   5   domain, ASCII "PVKIT"
    ///     5   1   format, 1
    ///     6   1   purpose
    ///     7   1   length of the first name, n
    ///     8   n   the first name, ASCII (a kit ID, or a backup's ID)
    ///     +   1   length of the second name, m
    ///     +   m   the second name, ASCII (the data key's ID, or a kit ID)
    public static func context(_ purpose: Purpose, kitID: String, dataKeyID: String) -> Data {
        var bytes = domain
        bytes.append(format)
        bytes.append(purpose.rawValue)
        for name in [kitID, dataKeyID] {
            let utf8 = Data(name.utf8)
            bytes.append(UInt8(min(utf8.count, 255)))
            bytes.append(utf8.prefix(255))
        }
        return bytes
    }

    public static func seal(_ key: SymmetricKey, under wrapping: SymmetricKey, purpose: Purpose,
                     kitID: String, dataKeyID: String) throws -> Data {
        let plain = key.withUnsafeBytes { Data($0) }
        let box = try AES.GCM.seal(plain, using: wrapping,
                                   authenticating: context(purpose, kitID: kitID, dataKeyID: dataKeyID))
        guard let combined = box.combined else { throw KeyWrapError.damaged }
        return combined
    }

    public static func open(_ sealed: Data, under wrapping: SymmetricKey, purpose: Purpose,
                     kitID: String, dataKeyID: String) throws -> SymmetricKey {
        do {
            let box = try AES.GCM.SealedBox(combined: sealed)
            let plain = try AES.GCM.open(box, using: wrapping,
                                         authenticating: context(purpose, kitID: kitID, dataKeyID: dataKeyID))
            guard plain.count == 32 else { throw KeyWrapError.damaged }
            return SymmetricKey(data: plain)
        } catch {
            throw KeyWrapError.damaged
        }
    }
}
