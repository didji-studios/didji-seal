//
//  BackupReaderTests.swift
//  DidjiSeal
//
//  The backup reader against a real backup: the one the app wrote on 16
//  November 2026 (format 6) and keeps in its own tests for good, in both
//  layouts, with the recovery kit that opens it. The vault that made it held a
//  login with a document, a note in a category of its own, a person, and its
//  settings; nothing in it is anyone's.
//

import CryptoKit
import Foundation
import Testing
@testable import DidjiBackupReader
@testable import DidjiSeal

enum Fixture {
    static let kitCode = "05101B26-313C4752-5D68737E-89949FAA-B5C0CBD6-E1ECF702-0D18232E-39444F5A-F63E64EB"
    /// The vault's own key: the first kit, replaced before the backup was made.
    static let vaultKeyCode = "030A1118-1F262D34-3B424950-575E656C-737A8188-8F969DA4-ABB2B9C0-C7CED5DC-AB5F8B5C"

    static func file(_ name: String) -> Data {
        let url = Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures")!
        return try! Data(contentsOf: url)
    }
    static let papers = file("backup-2026-11-16.json")
    static let whole = file("backup-2026-11-16.didjibackup")
}

func field(_ json: Data, _ name: String) -> Any? {
    (try? JSONSerialization.jsonObject(with: json) as? [String: Any])?[name]
}

@Suite("The backup reader, against the app's own backup")
struct BackupReaderTests {
    @Test(arguments: ["papers", "whole"])
    func theKitOpensItAndEverythingIsThere(layout: String) throws {
        let file = layout == "papers" ? Fixture.papers : Fixture.whole
        let backup = try BackupReader.open(file, code: Fixture.kitCode)
        #expect(backup.formatVersion == 6)
        #expect(backup.structureVerified)
        #expect(backup.underAnotherKey == 0)
        #expect(backup.kitID == "793a9901145f")
        let items = backup.records.filter { $0.kind == .item }
        #expect(Set(items.compactMap { field($0.plaintext, "title") as? String }) == ["Harbour Bank", "Sailing club"])
        let document = try #require(backup.records.first { $0.kind == .attachmentData })
        #expect(document.plaintext == Data("A statement, as a scan would be.".utf8))
        let details = try #require(backup.records.first { $0.kind == .attachmentMetadata })
        #expect(field(details.plaintext, "filename") as? String == "statement.txt")
        #expect(backup.records.contains { $0.kind == .preferences })
        #expect(backup.records.contains { $0.kind == .category })
        #expect(backup.records.contains { $0.kind == .subject })
    }

    @Test func theReplacedFirstKitIsRefusedAsTheAppRefusesIt() {
        #expect(throws: BackupReaderError.firstKitReplaced) {
            try BackupReader.open(Fixture.whole, code: Fixture.vaultKeyCode)
        }
    }

    @Test func anotherKitAMistypedCodeAndNoCodeAreRefused() {
        let another = SymmetricKey(size: .bits256).kitCode
        #expect(throws: BackupReaderError.wrongKit) { try BackupReader.open(Fixture.whole, code: another) }
        var typo = Array(Fixture.kitCode)
        typo[0] = typo[0] == "0" ? "1" : "0"
        #expect(throws: BackupReaderError.mistypedCode) { try BackupReader.open(Fixture.whole, code: String(typo)) }
        #expect(throws: BackupReaderError.notACode) { try BackupReader.open(Fixture.whole, code: "hello") }
    }

    @Test func aFileCutShortIsRefused() {
        let cut = Fixture.whole.prefix(Fixture.whole.count - 10)
        #expect(throws: BackupReaderError.truncated) { try BackupReader.open(Data(cut), code: Fixture.kitCode) }
    }

    /// Any one byte of a sealed record changed: refused whole, nothing opened.
    @Test func aChangedRecordIsRefusedWhole() throws {
        var json = try #require(try JSONSerialization.jsonObject(with: Fixture.papers) as? [String: Any])
        var items = try #require(json["items"] as? [[String: Any]])
        let text = try #require(items[0]["sealedPayload"] as? String)
        var sealed = try #require(Data(base64Encoded: text))
        sealed[sealed.count - 1] ^= 0x01
        items[0]["sealedPayload"] = sealed.base64EncodedString()
        json["items"] = items
        let changed = try JSONSerialization.data(withJSONObject: json)
        #expect(throws: BackupReaderError.altered("a record that is not on its list")) {
            try BackupReader.open(changed, code: Fixture.kitCode)
        }
    }

    /// A record taken out of the file: its list still names it.
    @Test func aRemovedRecordIsRefusedWhole() throws {
        var json = try #require(try JSONSerialization.jsonObject(with: Fixture.papers) as? [String: Any])
        var items = try #require(json["items"] as? [[String: Any]])
        items.removeLast()
        json["items"] = items
        let changed = try JSONSerialization.data(withJSONObject: json)
        #expect(throws: BackupReaderError.altered("a record on its list is missing")) {
            try BackupReader.open(changed, code: Fixture.kitCode)
        }
    }

    /// The list taken away, to hide a change: a format 6 backup always has one.
    @Test func aBackupWithItsListTakenAwayIsRefused() throws {
        var json = try #require(try JSONSerialization.jsonObject(with: Fixture.papers) as? [String: Any])
        json["manifest"] = nil
        let changed = try JSONSerialization.data(withJSONObject: json)
        #expect(throws: BackupReaderError.altered("its list of contents is missing")) {
            try BackupReader.open(changed, code: Fixture.kitCode)
        }
    }

    @Test func aLaterFormatIsNamedNotGuessedAt() throws {
        var json = try #require(try JSONSerialization.jsonObject(with: Fixture.papers) as? [String: Any])
        json["formatVersion"] = 7
        let changed = try JSONSerialization.data(withJSONObject: json)
        #expect(throws: BackupReaderError.newerFormat(7)) { try BackupReader.open(changed, code: Fixture.kitCode) }
    }

    @Test func somethingElseEntirelyIsNotABackup() {
        #expect(throws: BackupReaderError.notABackup) { try BackupReader.open(Data("hello".utf8), code: Fixture.kitCode) }
    }
}
