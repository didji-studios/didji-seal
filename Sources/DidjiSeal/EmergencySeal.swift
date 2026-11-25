//
//  EmergencySeal.swift
//  Part of DidjiSeal: the code that locks what people keep in Didji.
//  This is the code the app ships; the app, its AutoFill, Didji for Safari and
//  the Apple Watch app all use it. References to docs/ are to Didji's own
//  design notes; what matters from them is in SPEC.md beside this package.
//
//  The emergency copy: the Health cards a person switched on for "Open without
//  Face ID", in one file per device under a key made on that device and never
//  synchronised. Readable by anyone holding the unlocked phone, by design.
//

import CryptoKit
import Foundation

public enum EmergencySeal {
    /// Authenticated with every copy, so nothing else sealed under the same key
    /// could be passed off as one.
    public static let context = Data("didji-emergency-copy-1".utf8)

    /// AES-256-GCM with a fresh random nonce. Nil only if CryptoKit hands back no
    /// combined form, which it does for its standard nonce size.
    public static func seal(_ plain: Data, using key: SymmetricKey) throws -> Data? {
        try AES.GCM.seal(plain, using: key, authenticating: context).combined
    }

    public static func open(_ sealed: Data, using key: SymmetricKey) -> Data? {
        guard let box = try? AES.GCM.SealedBox(combined: sealed) else { return nil }
        return try? AES.GCM.open(box, using: key, authenticating: context)
    }
}
