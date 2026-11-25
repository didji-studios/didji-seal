//
//  PasscodeDerivation.swift
//  Part of DidjiSeal: the code that locks what people keep in Didji.
//  This is the code the app ships; the app, its AutoFill, Didji for Safari and
//  the Apple Watch app all use it. References to docs/ are to Didji's own
//  design notes; what matters from them is in SPEC.md beside this package.
//
//  The Didji passcode is never stored: the vault keeps a random salt and
//  PBKDF2-HMAC-SHA256 over the passcode, and a check derives again and compares
//  in constant time. The passcode is a lock on the app, not on the data: it
//  derives no key. The app holds the salt, the rounds and the tries.
//

import CommonCrypto
import Foundation

public enum PasscodeDerivation {
    /// How the app names this scheme in what it stores.
    public static let schemeName = "pbkdf2-hmac-sha256"
    /// Bytes derived, and so stored.
    public static let derivedBytes = 32

    /// PBKDF2-HMAC-SHA256 over the passcode in its composed Unicode form, so
    /// an accent typed two ways is one passcode.
    public static func derive(_ passcode: String, salt: Data, rounds: Int) -> Data {
        let password = Array(normalised(passcode).utf8)
        let saltBytes = [UInt8](salt)
        var output = [UInt8](repeating: 0, count: derivedBytes)
        let status = password.withUnsafeBufferPointer { passwordBuffer in
            saltBytes.withUnsafeBufferPointer { saltBuffer in
                output.withUnsafeMutableBufferPointer { outputBuffer in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         passwordBuffer.baseAddress.map { UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self) },
                                         passwordBuffer.count,
                                         saltBuffer.baseAddress, saltBuffer.count,
                                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                         UInt32(max(1, rounds)),
                                         outputBuffer.baseAddress, outputBuffer.count)
                }
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 failed: \(status)")
        return Data(output)
    }

    /// The passcode as derived: its composed Unicode form.
    public static func normalised(_ passcode: String) -> String {
        passcode.precomposedStringWithCanonicalMapping
    }

    /// Whether two derivations are the same, in time that does not depend on
    /// where they first differ.
    public static func matches(_ candidate: Data, _ stored: Data) -> Bool {
        guard candidate.count == stored.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(candidate, stored) { difference |= a ^ b }
        return difference == 0
    }
}
