//
//  VectorTests.swift
//  DidjiSeal
//
//  The test vectors in vectors.json were made from the app's own code before it
//  moved into this package (main at 152061e3, 25 November 2026), compiled
//  unchanged. These tests hold the package to them, byte for byte where the
//  output is fixed (contexts, names, codes, the deterministic seal) and by
//  opening where a seal's nonce is random.
//

import CryptoKit
import Foundation
import Testing
@testable import DidjiSeal

struct Vectors: Decodable {
    struct Keys: Decodable { let vault, kit, backup, wrong: String }
    struct Names: Decodable { let vaultKeyID, kitID, vaultRecoveryCode, kitCode: String }
    struct Context: Decodable {
        let name: String
        let kind: UInt8
        let id: String
        let parent: String?
        let revision: UInt32
        let chunkIndex: UInt32?
        let chunkCount: UInt32?
        let bytes: String
        let wrapBytes: String?
        let format2Bytes: String?
    }
    struct Seals: Decodable { let bound, wrapped, legacy, deterministicUnderBackupKey, laterFormat: String }
    struct Wrap: Decodable {
        let purpose: UInt8
        let firstName, secondName, context, sealed, under, opensTo: String
    }
    struct Reading: Decodable { let code, reads: String }
    /// A case every reader must refuse: one change to a recorded seal or wrap.
    struct MustFail: Decodable {
        let name, why, opener, key, sealed, refusedAs: String
        let context: String?
        let purpose: UInt8?
        let firstName, secondName: String?
    }
    let keys: Keys
    let plaintext: String
    let names: Names
    let contexts: [Context]
    let seals: Seals
    let keyWraps: [Wrap]
    let mustFail: [MustFail]
    let codeReadings: [Reading]

    static let loaded: Vectors = {
        let url = Bundle.module.url(forResource: "vectors", withExtension: "json")!
        return try! JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }()

    func key(_ name: String) -> SymmetricKey {
        switch name {
        case "vault": SymmetricKey(data: hex(keys.vault))
        case "kit": SymmetricKey(data: hex(keys.kit))
        case "backup": SymmetricKey(data: hex(keys.backup))
        default: SymmetricKey(data: hex(keys.wrong))
        }
    }
}

func hex(_ string: String) -> Data {
    var data = Data()
    var index = string.startIndex
    while index < string.endIndex {
        let next = string.index(index, offsetBy: 2)
        data.append(UInt8(string[index..<next], radix: 16)!)
        index = next
    }
    return data
}

func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

let v = Vectors.loaded
let itemContext = SealContext(.item, id: UUID(uuidString: v.contexts[0].id)!, revision: v.contexts[0].revision)

@Test func namesAreAsBefore() {
    #expect(v.key("vault").fingerprint == v.names.vaultKeyID)
    #expect(v.key("kit").kitID == v.names.kitID)
    #expect(v.key("vault").recoveryCode == v.names.vaultRecoveryCode)
    #expect(v.key("kit").kitCode == v.names.kitCode)
}

@Test func contextBytesAreAsBefore() throws {
    for c in v.contexts {
        let kind = try #require(SealedRecordKind(rawValue: c.kind))
        let id = UUID(uuidString: c.id)!
        let parent = c.parent.map { UUID(uuidString: $0)! }
        let context: SealContext
        if let index = c.chunkIndex, let count = c.chunkCount {
            context = .chunk(id: id, ofMedia: parent!, index: index, count: count, revision: c.revision)
        } else {
            context = SealContext(kind, id: id, parent: parent, revision: c.revision)
        }
        #expect(hex(context.bytes) == c.bytes, "\(c.name)")
        if let wrapBytes = c.wrapBytes { #expect(hex(context.wrapBytes) == wrapBytes) }
        if let format2 = c.format2Bytes { #expect(hex(context.withFormat(2).bytes) == format2) }
    }
}

@Test func theDeterministicSealIsByteForByteTheSame() throws {
    let sealed = try VaultCrypto(key: v.key("backup")).sealDeterministic(raw: hex(v.plaintext), context: itemContext)
    #expect(hex(sealed) == v.seals.deterministicUnderBackupKey)
}

@Test func everyRecordedSealOpens() throws {
    let crypto = VaultCrypto(key: v.key("vault"))
    let id = v.key("vault").fingerprint
    let plaintext = hex(v.plaintext)
    #expect(try crypto.open(raw: hex(v.seals.bound), recordFingerprint: id, context: itemContext) == plaintext)
    #expect(try crypto.open(raw: hex(v.seals.wrapped), recordFingerprint: id, context: itemContext) == plaintext)
    #expect(try VaultCrypto(key: v.key("backup")).open(raw: hex(v.seals.deterministicUnderBackupKey),
                                                        recordFingerprint: "", context: itemContext) == plaintext)
}

/// The form from before binding: the recorded vector is still the same bytes,
/// and a record's opener refuses it whatever the context (since 25 November
/// 2026, when the makers' devices counted none left). Opened with no context,
/// as the watch's own seal is, it is still what it always was.
@Test func theFormFromBeforeBindingIsRefused() throws {
    let crypto = VaultCrypto(key: v.key("vault"))
    let legacy = hex(v.seals.legacy)
    for context in [itemContext, SealContext(.item, id: UUID(), revision: 1)] {
        let refused = #expect(throws: VaultCryptoError.self) {
            try crypto.open(raw: legacy, recordFingerprint: "", context: context)
        }
        // Refused as unreadable, never named as a later Didji's.
        if case .newerFormat? = refused { Issue.record("read as a later format") }
    }
    #expect(try crypto.open(raw: legacy, recordFingerprint: "") == hex(v.plaintext))
}

@Test func aSealRefusesTheWrongKeyTheWrongRecordAndALaterFormat() {
    let bound = hex(v.seals.bound)
    let otherRecord = SealContext(.item, id: UUID(), revision: 3)
    #expect(throws: VaultCryptoError.self) {
        try VaultCrypto(key: v.key("wrong")).open(raw: bound, recordFingerprint: "", context: itemContext)
    }
    #expect(throws: VaultCryptoError.self) {
        try VaultCrypto(key: v.key("vault")).open(raw: bound, recordFingerprint: "", context: otherRecord)
    }
    let later = hex(v.seals.laterFormat)
    #expect(VaultCrypto.isLaterFormat(later))
    do {
        _ = try VaultCrypto(key: v.key("vault")).open(raw: later, recordFingerprint: "", context: itemContext)
        Issue.record("a later format opened")
    } catch VaultCryptoError.newerFormat {
    } catch {
        Issue.record("a later format gave \(error), not newerFormat")
    }
}

@Test func everyRecordedKeyWrapOpens() throws {
    for wrap in v.keyWraps {
        let purpose = try #require(KeyWrap.Purpose(rawValue: wrap.purpose))
        #expect(hex(KeyWrap.context(purpose, kitID: wrap.firstName, dataKeyID: wrap.secondName)) == wrap.context)
        let opened = try KeyWrap.open(hex(wrap.sealed), under: v.key(wrap.under), purpose: purpose,
                                      kitID: wrap.firstName, dataKeyID: wrap.secondName)
        #expect(opened == v.key(wrap.opensTo))
        #expect(throws: KeyWrapError.damaged) {
            try KeyWrap.open(hex(wrap.sealed), under: v.key("wrong"), purpose: purpose,
                             kitID: wrap.firstName, dataKeyID: wrap.secondName)
        }
    }
}

/// Every case in `mustFail` is refused, and only the later format is named as
/// a later Didji's. The cases are in the vectors file, not only here, so a
/// reader written in another language can be held to them too.
@Test func everyMustFailCaseIsRefused() throws {
    #expect(v.mustFail.count >= 16)
    for c in v.mustFail {
        var refused: (any Error)?
        do {
            switch c.opener {
            case "record":
                let named = try #require(v.contexts.first { $0.name == c.context }, "\(c.name)")
                let kind = try #require(SealedRecordKind(rawValue: named.kind))
                let context = SealContext(kind, id: UUID(uuidString: named.id)!,
                                          parent: named.parent.map { UUID(uuidString: $0)! }, revision: named.revision)
                _ = try VaultCrypto(key: v.key(c.key)).open(raw: hex(c.sealed), recordFingerprint: "", context: context)
            case "keyWrap":
                let raw = try #require(c.purpose)
                let purpose = try #require(KeyWrap.Purpose(rawValue: raw))
                let first = try #require(c.firstName)
                let second = try #require(c.secondName)
                _ = try KeyWrap.open(hex(c.sealed), under: v.key(c.key), purpose: purpose,
                                     kitID: first, dataKeyID: second)
            default:
                Issue.record("\(c.name): an opener this test does not know")
                continue
            }
        } catch {
            refused = error
        }
        guard let refused else {
            Issue.record("\(c.name) opened: \(c.why)")
            continue
        }
        let namedLater = (refused as? VaultCryptoError).map { if case .newerFormat = $0 { true } else { false } } ?? false
        #expect(namedLater == (c.refusedAs == "newerFormat"), "\(c.name)")
    }
}

@Test func codesReadAsBefore() {
    for reading in v.codeReadings {
        let read: String
        switch RecoveryCode.read(reading.code) {
        case .key: read = "key"
        case .kit: read = "kit"
        case .mistyped: read = "mistyped"
        case .notACode: read = "notACode"
        }
        #expect(read == reading.reads, "\(reading.code)")
    }
}
