//
//  HostileTests.swift
//  DidjiSeal
//
//  What must fail: a seal changed by one bit, cut short, with its marker
//  stripped to pass it off as the refused older form, or moved to another
//  record. And the three smaller pieces: the passcode's derivation, what the
//  password check sends, and the emergency copy's seal.
//

import CryptoKit
import Foundation
import Testing
@testable import DidjiSeal

@Suite("A seal refuses anything but itself")
struct HostileSealTests {
    let crypto = VaultCrypto(key: v.key("vault"))

    @Test(arguments: ["bound", "wrapped"])
    func everyBitOfASealIsCovered(form: String) {
        let sealed = hex(form == "bound" ? v.seals.bound : v.seals.wrapped)
        // Past the marker, every byte: nonce, ciphertext and tag.
        for i in 7..<sealed.count {
            var changed = sealed
            changed[changed.startIndex + i] ^= 0x01
            #expect(throws: (any Error).self, "byte \(i)") {
                try crypto.open(raw: changed, recordFingerprint: "", context: itemContext)
            }
        }
    }

    @Test(arguments: ["bound", "wrapped"])
    func aSealCutShortIsRefused(form: String) {
        let sealed = hex(form == "bound" ? v.seals.bound : v.seals.wrapped)
        for keep in [0, 1, 7, 12, sealed.count - 16, sealed.count - 1] where keep < sealed.count {
            #expect(throws: (any Error).self, "kept \(keep)") {
                try crypto.open(raw: sealed.prefix(keep), recordFingerprint: "", context: itemContext)
            }
        }
    }

    /// The downgrade: a bound seal with its marker taken off reads as the form
    /// from before binding, which is refused; and even opened with no context
    /// at all, its tag covers the context it was sealed with.
    @Test func aBoundSealWithItsMarkerStrippedDoesNotOpen() {
        let stripped = hex(v.seals.bound).dropFirst(7)
        #expect(throws: VaultCryptoError.self) {
            try crypto.open(raw: Data(stripped), recordFingerprint: "", context: itemContext)
        }
        #expect(throws: VaultCryptoError.self) {
            try crypto.open(raw: Data(stripped), recordFingerprint: "")
        }
    }

    /// A wrapped seal's format byte changed to the bound form's: refused.
    @Test func aSealsFormatCannotBeChanged() {
        var sealed = hex(v.seals.wrapped)
        sealed[sealed.startIndex + 6] = SealContext.currentFormat
        #expect(throws: VaultCryptoError.self) {
            try crypto.open(raw: sealed, recordFingerprint: "", context: itemContext)
        }
    }

    @Test func aSealDoesNotOpenAsAnotherKindRevisionOrParent() {
        let sealed = hex(v.seals.bound)
        let id = itemContext.recordID
        for other in [SealContext(.passkey, id: id, revision: 3), SealContext(.item, id: id, revision: 2),
                      SealContext(.item, id: id, parent: UUID(), revision: 3)] {
            #expect(throws: VaultCryptoError.self) {
                try crypto.open(raw: sealed, recordFingerprint: "", context: other)
            }
        }
    }

    @Test func aRecordLabelledWithAnotherKeyIsNamedBeforeTrying() {
        do {
            _ = try crypto.open(raw: hex(v.seals.bound), recordFingerprint: "000000000000", context: itemContext)
            Issue.record("opened under another key's label")
        } catch VaultCryptoError.keyFingerprintMismatch(let expected, let found) {
            #expect(expected == v.names.vaultKeyID && found == "000000000000")
        } catch {
            Issue.record("\(error)")
        }
    }

    /// Two seals of the same record under the same key never share a nonce.
    @Test func aRandomSealNeverRepeatsItsNonce() throws {
        var nonces = Set<Data>()
        for _ in 0..<1000 {
            let sealed = try crypto.seal(raw: hex(v.plaintext), context: itemContext)
            nonces.insert(sealed.dropFirst(7).prefix(12))
        }
        #expect(nonces.count == 1000)
    }
}

@Suite("The passcode, the password check and the emergency copy")
struct SmallerPiecesTests {
    /// RFC 7914, section 11: PBKDF2-HMAC-SHA256, "passwd", "salt", one round;
    /// the first 32 of its 64 bytes.
    @Test func thePasscodeDerivationIsPBKDF2HMACSHA256() {
        let derived = PasscodeDerivation.derive("passwd", salt: Data("salt".utf8), rounds: 1)
        #expect(hex(derived) == "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc")
    }

    @Test func anAccentTypedTwoWaysIsOnePasscode() {
        let salt = Data(repeating: 7, count: 16)
        #expect(PasscodeDerivation.derive("caf\u{e9}", salt: salt, rounds: 10)
                == PasscodeDerivation.derive("cafe\u{301}", salt: salt, rounds: 10))
    }

    @Test func aMatchIsExact() {
        let a = Data([1, 2, 3]), b = Data([1, 2, 4])
        #expect(PasscodeDerivation.matches(a, a))
        #expect(!PasscodeDerivation.matches(a, b))
        #expect(!PasscodeDerivation.matches(a, a.prefix(2)))
    }

    /// SHA-1 of "password", as Have I Been Pwned's own documentation gives it.
    @Test func thePasswordCheckSendsFiveCharactersOfTheHash() {
        let split = BreachLookup.split("password")
        #expect(split.prefix == "5BAA6")
        #expect(split.suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
    }

    @Test func theEmergencyCopyOpensOnlyAsItself() throws {
        let key = SymmetricKey(size: .bits256)
        let sealed = try #require(try EmergencySeal.seal(Data("cards".utf8), using: key))
        #expect(EmergencySeal.open(sealed, using: key) == Data("cards".utf8))
        #expect(EmergencySeal.open(sealed, using: SymmetricKey(size: .bits256)) == nil)
        // Not openable as an ordinary seal under the same key: its context is its own.
        #expect(throws: (any Error).self) {
            try VaultCrypto(key: key).open(raw: sealed, recordFingerprint: "")
        }
        var changed = sealed
        changed[changed.startIndex] ^= 1
        #expect(EmergencySeal.open(changed, using: key) == nil)
    }
}
