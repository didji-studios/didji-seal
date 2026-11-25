//
//  BreachLookup.swift
//  Part of DidjiSeal: the code that locks what people keep in Didji.
//  This is the code the app ships; the app, its AutoFill, Didji for Safari and
//  the Apple Watch app all use it. References to docs/ are to Didji's own
//  design notes; what matters from them is in SPEC.md beside this package.
//
//  What the password check sends to Have I Been Pwned, if a person leaves it
//  on: the first five characters of the password's SHA-1, and nothing else.
//  The rest of the hash stays on the device and is compared with the reply
//  ("k-anonymity"). SHA-1 because that is the service's index, not to protect
//  anything.
//

import CryptoKit
import Foundation

public enum BreachLookup {
    /// The hash in uppercase hex, split where the service splits it: `prefix`
    /// is sent, `suffix` is not.
    public static func split(_ password: String) -> (prefix: String, suffix: String) {
        let digest = Insecure.SHA1.hash(data: Data(password.utf8))
        let hex = digest.map { String(format: "%02X", $0) }.joined()
        return (String(hex.prefix(5)), String(hex.dropFirst(5)))
    }
}
