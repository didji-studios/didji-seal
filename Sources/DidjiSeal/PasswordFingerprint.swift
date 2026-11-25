//
//  PasswordFingerprint.swift
//  Part of DidjiSeal: the code that locks what people keep in Didji.
//  This is the code the app ships; the app, its AutoFill, Didji for Safari and
//  the Apple Watch app all use it. References to docs/ are to Didji's own
//  design notes; what matters from them is in SPEC.md beside this package.
//
//  Telling passwords apart without keeping them: plain SHA-256, unsalted, so
//  the same password gives the same fingerprint in one vault. Only ever held in
//  memory or inside a sealed record (the password check's results, a password
//  AutoFill held after the trial), never anywhere readable: unsalted, a
//  fingerprint of a weak password could be guessed by anyone who could read it.
//

import CryptoKit
import Foundation

public enum PasswordFingerprint {
    /// The first eight bytes, in hex: enough to tell a vault's passwords apart
    /// for the reuse and breach checks, and a shorter thing to leak into a log.
    public static func short(_ value: String) -> String {
        let digest = SHA256.hash(data: Data(value.utf8))
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// All 32 bytes, in hex: what a held password records of the record's own
    /// password, so applying it later can tell whether that changed meanwhile.
    public static func full(_ password: String) -> String {
        SHA256.hash(data: Data(password.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
