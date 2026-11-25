//
//  BackupReader.swift
//  DidjiBackupReader
//
//  Reads a Didji backup (`.didjibackup`, or the older `.json`) with a recovery
//  kit's code, checks it is whole, and hands back everything in it, opened.
//  It is a second reader of the format, written from SPEC.md and the app's own
//  code, and held by its tests to a real backup the app made: the app does
//  not use it. It only reads: nothing here writes, and nothing here reaches
//  the network.
//

import CryptoKit
import DidjiSeal
import Foundation

public enum BackupReaderError: Error, Equatable, CustomStringConvertible {
    case notABackup
    case containerVersion(UInt8)
    case truncated
    case newerFormat(Int)
    case notACode
    case mistypedCode
    case wrongKit
    case firstKitReplaced
    case altered(String)

    public var description: String {
        switch self {
        case .notABackup: "This is not a Didji backup."
        case .containerVersion(let v): "This backup's container is version \(v), which this tool does not know. A newer didji-open will read it."
        case .truncated: "This backup ends part of the way through. It may not have finished copying."
        case .newerFormat(let v): "This backup is format \(v), made by a newer Didji. A newer didji-open will read it."
        case .notACode: "That is not a recovery kit code: it should be nine groups of eight letters and digits."
        case .mistypedCode: "That code has a character wrong. Check it against the kit, group by group."
        case .wrongKit: "That code does not open this backup. It may be another vault's kit, or a kit made after this backup."
        case .firstKitReplaced: "This backup was made after that kit was replaced. Use the kit that was current when the backup was made."
        case .altered(let what): "This backup has been changed since it was made (\(what)), so nothing in it was opened."
        }
    }
}

/// One record, opened.
public struct OpenedRecord: Sendable {
    public let kind: SealedRecordKind
    public let id: UUID
    public let parentID: UUID?
    /// What was sealed: JSON for every kind but a document's bytes, a
    /// thumbnail and a photograph's or video's pieces.
    public let plaintext: Data
}

/// A photograph or video, its pieces put back together.
public struct OpenedMedia: Sendable {
    public let id: UUID
    public let albumID: UUID?
    public let metadata: Data
    public let thumbnail: Data
    public let original: Data
}

public struct OpenedBackup: Sendable {
    public let formatVersion: Int
    public let backupID: UUID
    public let vaultKeyID: String
    public let kitID: String?
    /// Every record in the file, in the file's order. A document is two:
    /// its details, then its bytes.
    public let records: [OpenedRecord]
    public let albums: [OpenedRecord]
    public let media: [OpenedMedia]
    /// Whether the file's sealed list of contents was there and matched.
    /// False only for a backup from before such lists existed.
    public let structureVerified: Bool
    /// Records locked under a key that is not this backup's (a vault part of
    /// the way through changing its key keeps them so). Left unopened.
    public let underAnotherKey: Int
    /// The file is the backup's first part alone, and its list says photos
    /// followed: Private Photos are not in this file.
    public let photosMissing: Bool
}

public enum BackupReader {
    /// The highest backup format this reader knows.
    public static let knownFormat = 6
    static let containerMagic = Data("DIDJIBK".utf8)
    static let containerVersion: UInt8 = 1

    public static func open(_ file: Data, code: String) throws -> OpenedBackup {
        let reading = RecoveryCode.read(code)
        switch reading {
        case .notACode: throw BackupReaderError.notACode
        case .mistyped: throw BackupReaderError.mistypedCode
        case .key, .kit: break
        }
        let (json, frames) = try split(file)
        let archive: Archive
        do { archive = try JSONDecoder().decode(Archive.self, from: json) } catch { throw BackupReaderError.notABackup }
        guard archive.formatVersion <= knownFormat else { throw BackupReaderError.newerFormat(archive.formatVersion) }
        let key = try backupKey(archive, reading)
        let crypto = VaultCrypto(key: key)

        // The sealed lists first, so nothing is opened from a file that was changed.
        var structureVerified = false
        var mediaFollowed: Bool?
        if let sealed = archive.manifest {
            let manifest = try openManifest(sealed, crypto: crypto, archive: archive, revision: 1)
            guard manifest.formatVersion == archive.formatVersion else { throw BackupReaderError.altered("its format") }
            try compare(manifest.entries, archive.entries)
            mediaFollowed = manifest.mediaFollowed
            structureVerified = true
        } else if archive.keys != nil {
            throw BackupReaderError.altered("its list of contents is missing")
        }
        if let frames {
            guard let first = frames.first, first.kind == 2 else { throw BackupReaderError.altered("no list of its photos") }
            let manifest = try openManifest(first.body, crypto: crypto, archive: archive, revision: 2)
            try compare(manifest.entries, try frames.dropFirst().flatMap(mediaEntries))
        }

        var records: [OpenedRecord] = []
        var underAnotherKey = 0
        func take(_ kind: SealedRecordKind, _ blob: Blob, parent: UUID? = nil) throws {
            guard blob.keyFingerprint == key.fingerprint || blob.keyFingerprint.isEmpty else {
                underAnotherKey += 1
                return
            }
            let context = SealContext(kind, id: blob.id, parent: parent, revision: UInt32(truncatingIfNeeded: blob.revision))
            let plain = try opened(crypto, blob.sealed, blob.keyFingerprint, context)
            records.append(OpenedRecord(kind: kind, id: blob.id, parentID: parent, plaintext: plain))
        }
        for r in archive.categories { try take(.category, r.blob) }
        for r in archive.subjects { try take(.subject, r.blob) }
        for r in archive.templates { try take(.template, r.blob) }
        if let r = archive.preferences { try take(.preferences, r.blob) }
        for r in archive.things { try take(.thing, r.blob) }
        for item in archive.items {
            try take(.item, item.blob)
            for a in item.attachments ?? [] {
                try take(.attachmentMetadata, a.metadataBlob, parent: item.id)
                try take(.attachmentData, a.dataBlob, parent: item.id)
            }
            for p in item.passkeys ?? [] { try take(.passkey, p.blob, parent: item.id) }
            for v in item.versions ?? [] { try take(.itemVersion, v.blob, parent: item.id) }
        }

        var albums: [OpenedRecord] = []
        var media: [OpenedMedia] = []
        if let frames {
            var current: (header: MediaHeader, metadata: Data, thumbnail: Data, count: Int, pieces: [Data])?
            func finish() {
                guard let c = current else { return }
                media.append(OpenedMedia(id: c.header.id, albumID: c.header.folderID, metadata: c.metadata,
                                         thumbnail: c.thumbnail, original: c.pieces.reduce(Data(), +)))
                current = nil
            }
            for frame in frames.dropFirst() {
                switch frame.kind {
                case 3:
                    let album = try header(AlbumHeader.self, frame)
                    let context = SealContext(.mediaFolder, id: album.id, revision: UInt32(truncatingIfNeeded: album.revision))
                    albums.append(OpenedRecord(kind: .mediaFolder, id: album.id, parentID: nil,
                                               plaintext: try opened(crypto, frame.body, album.keyFingerprint, context)))
                case 4:
                    finish()
                    let m = try header(MediaHeader.self, frame)
                    let revision = UInt32(truncatingIfNeeded: m.revision)
                    let metadata = try opened(crypto, m.sealedMetadata, m.keyFingerprint,
                                              SealContext(.mediaMetadata, id: m.id, revision: revision))
                    let thumbnail = try opened(crypto, frame.body, m.keyFingerprint,
                                               SealContext(.mediaThumbnail, id: m.id, revision: revision))
                    let count = (try? JSONSerialization.jsonObject(with: metadata) as? [String: Any])?["chunkCount"] as? Int ?? 1
                    current = (m, metadata, thumbnail, count, [])
                case 5:
                    let chunk = try header(ChunkHeader.self, frame)
                    guard let c = current, chunk.mediaID == c.header.id, chunk.index == c.pieces.count,
                          chunk.index < c.count else { throw BackupReaderError.altered("a photograph's pieces are out of place") }
                    let context = SealContext.chunk(id: chunk.id, ofMedia: chunk.mediaID, index: UInt32(chunk.index),
                                                    count: UInt32(c.count))
                    current?.pieces.append(try opened(crypto, frame.body, chunk.keyFingerprint, context))
                default:
                    throw BackupReaderError.altered("a part this tool does not know")
                }
            }
            finish()
        }
        return OpenedBackup(formatVersion: archive.formatVersion, backupID: archive.backupID,
                            vaultKeyID: archive.keys?.dataKeyID ?? archive.keyFingerprint, kitID: archive.keys?.kitID,
                            records: records, albums: albums, media: media, structureVerified: structureVerified,
                            underAnotherKey: underAnotherKey, photosMissing: frames == nil && mediaFollowed == true)
    }

    // MARK: - The key

    /// The backup's own key (format 6), from the kit current when it was made;
    /// or, for a backup from before backups had keys of their own, the vault
    /// key itself, from a first kit.
    static func backupKey(_ archive: Archive, _ reading: RecoveryCode.Reading) throws -> SymmetricKey {
        guard let keys = archive.keys else {
            guard case .key(let key) = reading, key.fingerprint == archive.keyFingerprint else {
                throw BackupReaderError.wrongKit
            }
            return key
        }
        switch reading {
        case .kit(let kit):
            guard kit.kitID == keys.kitID, let forKit = keys.forKit,
                  let key = try? KeyWrap.open(forKit, under: kit, purpose: .backupKeyForKit,
                                              kitID: keys.backupKeyID, dataKeyID: kit.kitID),
                  key.fingerprint == keys.backupKeyID else { throw BackupReaderError.wrongKit }
            return key
        case .key(let dataKey):
            guard dataKey.fingerprint == keys.dataKeyID else { throw BackupReaderError.wrongKit }
            if keys.retired { throw BackupReaderError.firstKitReplaced }
            guard let key = try? KeyWrap.open(keys.forVault, under: dataKey, purpose: .backupKeyForVault,
                                              kitID: keys.backupKeyID, dataKeyID: dataKey.fingerprint),
                  key.fingerprint == keys.backupKeyID else { throw BackupReaderError.wrongKit }
            return key
        case .mistyped, .notACode:
            throw BackupReaderError.notACode
        }
    }

    static func opened(_ crypto: VaultCrypto, _ sealed: Data, _ fingerprint: String, _ context: SealContext) throws -> Data {
        do {
            return try crypto.open(raw: sealed, recordFingerprint: fingerprint, context: context)
        } catch VaultCryptoError.newerFormat {
            throw BackupReaderError.newerFormat(knownFormat + 1)
        } catch {
            throw BackupReaderError.altered("a record will not open")
        }
    }

    // MARK: - The file

    struct Frame { let kind: UInt8; let header: Data; let body: Data }

    /// The JSON, and the frames after it for a container (nil for a JSON backup).
    static func split(_ file: Data) throws -> (json: Data, frames: [Frame]?) {
        if file.first == UInt8(ascii: "{") { return (file, nil) }
        guard file.count >= 8, file.prefix(7) == containerMagic else { throw BackupReaderError.notABackup }
        let version = file[file.startIndex + 7]
        guard version == containerVersion else { throw BackupReaderError.containerVersion(version) }
        var offset = file.startIndex + 8
        func take(_ n: Int) throws -> Data {
            guard n >= 0, file.endIndex - offset >= n else { throw BackupReaderError.truncated }
            defer { offset += n }
            return file[offset..<(offset + n)]
        }
        func integer<T: FixedWidthInteger>(_: T.Type) throws -> T {
            try take(MemoryLayout<T>.size).withUnsafeBytes { $0.loadUnaligned(as: T.self) }.littleEndian
        }
        var frames: [Frame] = []
        while offset < file.endIndex {
            guard let kind = try take(1).first else { throw BackupReaderError.truncated }
            let headerLength = try integer(UInt32.self)
            let header = try take(Int(headerLength))
            let bodyLength = try integer(UInt64.self)
            guard bodyLength <= UInt64(Int.max) else { throw BackupReaderError.truncated }
            let body = try take(Int(bodyLength))
            frames.append(Frame(kind: kind, header: Data(header), body: Data(body)))
        }
        guard let first = frames.first, first.kind == 1 else { throw BackupReaderError.notABackup }
        return (first.body, Array(frames.dropFirst()))
    }

    static func header<T: Decodable>(_ type: T.Type, _ frame: Frame) throws -> T {
        do { return try JSONDecoder().decode(type, from: frame.header) } catch {
            throw BackupReaderError.altered("a part's details will not read")
        }
    }

    // MARK: - The sealed lists

    struct Manifest: Decodable {
        let formatVersion: Int
        let entries: [Entry]
        let mediaFollowed: Bool?
    }

    /// One blob as a list names it. Dates are compared as the text the file
    /// holds, which is how both the list and the file write them.
    struct Entry: Decodable, Hashable {
        let kind: UInt8
        let id: UUID
        let parentID: UUID?
        let index: Int?
        let revision: Int
        let createdAt: String
        let updatedAt: String
        let keyFingerprint: String
        let digest: Data
    }

    static func openManifest(_ sealed: Data, crypto: VaultCrypto, archive: Archive, revision: UInt32) throws -> Manifest {
        let context = SealContext(.backupManifest, id: archive.backupID, revision: revision)
        guard let plain = try? crypto.open(raw: sealed, recordFingerprint: archive.keyFingerprint, context: context),
              let manifest = try? JSONDecoder().decode(Manifest.self, from: plain)
        else { throw BackupReaderError.altered("its list of contents will not open") }
        return manifest
    }

    /// The same blobs, as many times each: nothing added, taken away or changed.
    static func compare(_ listed: [Entry], _ found: [Entry]) throws {
        var waiting: [Entry: Int] = [:]
        for entry in listed { waiting[entry, default: 0] += 1 }
        for entry in found {
            guard let n = waiting[entry], n > 0 else { throw BackupReaderError.altered("a record that is not on its list") }
            waiting[entry] = n - 1
        }
        guard waiting.values.allSatisfy({ $0 == 0 }) else { throw BackupReaderError.altered("a record on its list is missing") }
    }

    static func entry(_ kind: SealedRecordKind, _ blob: Blob, parent: UUID? = nil, index: Int? = nil,
                      updatedAt: String? = nil) -> Entry {
        Entry(kind: kind.rawValue, id: blob.id, parentID: parent, index: index, revision: blob.revision,
              createdAt: blob.createdAt, updatedAt: updatedAt ?? blob.updatedAt, keyFingerprint: blob.keyFingerprint,
              digest: Data(SHA256.hash(data: blob.sealed)))
    }

    static func mediaEntries(_ frame: Frame) throws -> [Entry] {
        switch frame.kind {
        case 3:
            let a = try header(AlbumHeader.self, frame)
            return [Entry(kind: SealedRecordKind.mediaFolder.rawValue, id: a.id, parentID: nil, index: nil,
                          revision: a.revision, createdAt: a.createdAt, updatedAt: a.updatedAt,
                          keyFingerprint: a.keyFingerprint, digest: Data(SHA256.hash(data: frame.body)))]
        case 4:
            let m = try header(MediaHeader.self, frame)
            return [(SealedRecordKind.mediaMetadata, m.sealedMetadata), (.mediaThumbnail, frame.body)].map {
                Entry(kind: $0.0.rawValue, id: m.id, parentID: m.folderID, index: nil, revision: m.revision,
                      createdAt: m.createdAt, updatedAt: m.updatedAt, keyFingerprint: m.keyFingerprint,
                      digest: Data(SHA256.hash(data: $0.1)))
            }
        case 5:
            let c = try header(ChunkHeader.self, frame)
            return [Entry(kind: SealedRecordKind.mediaChunk.rawValue, id: c.id, parentID: c.mediaID, index: c.index,
                          revision: 0, createdAt: c.createdAt, updatedAt: c.createdAt,
                          keyFingerprint: c.keyFingerprint, digest: Data(SHA256.hash(data: frame.body)))]
        default:
            throw BackupReaderError.altered("a part this tool does not know")
        }
    }
}

// MARK: - The backup's JSON, as much of it as reading needs

struct Blob {
    let id: UUID
    let revision: Int
    let createdAt: String
    let updatedAt: String
    let keyFingerprint: String
    let sealed: Data
}

struct Archive: Decodable {
    struct Keys: Decodable {
        let backupKeyID: String
        let dataKeyID: String
        let forVault: Data
        let kitID: String?
        let forKit: Data?
        let firstKitRetired: Bool?
        var retired: Bool { firstKitRetired ?? false }
    }
    struct Record: Decodable {
        let id: UUID
        let createdAt: String?
        let updatedAt: String?
        let keyFingerprint: String?
        let revision: Int?
        let sealedPayload: Data?
        var blob: Blob {
            Blob(id: id, revision: revision ?? 0, createdAt: createdAt ?? "", updatedAt: updatedAt ?? "",
                 keyFingerprint: keyFingerprint ?? "", sealed: sealedPayload ?? Data())
        }
    }
    struct Attachment: Decodable {
        let id: UUID
        let createdAt: String?
        let keyFingerprint: String?
        let revision: Int?
        let sealedMetadata: Data?
        let sealedData: Data?
        var metadataBlob: Blob {
            Blob(id: id, revision: revision ?? 0, createdAt: createdAt ?? "", updatedAt: createdAt ?? "",
                 keyFingerprint: keyFingerprint ?? "", sealed: sealedMetadata ?? Data())
        }
        var dataBlob: Blob {
            Blob(id: id, revision: revision ?? 0, createdAt: createdAt ?? "", updatedAt: createdAt ?? "",
                 keyFingerprint: keyFingerprint ?? "", sealed: sealedData ?? Data())
        }
    }
    struct Item: Decodable {
        let id: UUID
        let createdAt: String?
        let updatedAt: String?
        let keyFingerprint: String?
        let revision: Int?
        let sealedPayload: Data?
        let attachments: [Attachment]?
        let passkeys: [Record]?
        let versions: [Record]?
        var blob: Blob {
            Blob(id: id, revision: revision ?? 0, createdAt: createdAt ?? "", updatedAt: updatedAt ?? "",
                 keyFingerprint: keyFingerprint ?? "", sealed: sealedPayload ?? Data())
        }
    }

    let formatVersion: Int
    let keyFingerprint: String
    let backupID: UUID
    let manifest: Data?
    let keys: Keys?
    let categories: [Record]
    let subjects: [Record]
    let templates: [Record]
    let preferences: Record?
    let things: [Record]
    let items: [Item]

    enum CodingKeys: String, CodingKey {
        case formatVersion, keyFingerprint, backupID, manifest, keys
        case categories, subjects, templates, preferences, things, items
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        formatVersion = try c.decodeIfPresent(Int.self, forKey: .formatVersion) ?? 1
        keyFingerprint = try c.decodeIfPresent(String.self, forKey: .keyFingerprint) ?? ""
        // A backup always names itself; one that does not cannot have a list.
        backupID = try c.decodeIfPresent(UUID.self, forKey: .backupID) ?? UUID()
        manifest = try c.decodeIfPresent(Data.self, forKey: .manifest)
        keys = try c.decodeIfPresent(Keys.self, forKey: .keys)
        categories = try c.decodeIfPresent([Record].self, forKey: .categories) ?? []
        subjects = try c.decodeIfPresent([Record].self, forKey: .subjects) ?? []
        templates = try c.decodeIfPresent([Record].self, forKey: .templates) ?? []
        preferences = try c.decodeIfPresent(Record.self, forKey: .preferences)
        things = try c.decodeIfPresent([Record].self, forKey: .things) ?? []
        items = try c.decodeIfPresent([Item].self, forKey: .items) ?? []
    }

    /// Every blob in the JSON, in the order the app's list names them.
    var entries: [BackupReader.Entry] {
        var out: [BackupReader.Entry] = []
        categories.forEach { out.append(BackupReader.entry(.category, $0.blob)) }
        subjects.forEach { out.append(BackupReader.entry(.subject, $0.blob)) }
        templates.forEach { out.append(BackupReader.entry(.template, $0.blob)) }
        if let preferences { out.append(BackupReader.entry(.preferences, preferences.blob)) }
        things.forEach { out.append(BackupReader.entry(.thing, $0.blob)) }
        for item in items {
            out.append(BackupReader.entry(.item, item.blob))
            for a in item.attachments ?? [] {
                out.append(BackupReader.entry(.attachmentMetadata, a.metadataBlob, parent: item.id))
                out.append(BackupReader.entry(.attachmentData, a.dataBlob, parent: item.id))
            }
            for p in item.passkeys ?? [] { out.append(BackupReader.entry(.passkey, p.blob, parent: item.id)) }
            for v in item.versions ?? [] { out.append(BackupReader.entry(.itemVersion, v.blob, parent: item.id)) }
        }
        return out
    }
}

struct AlbumHeader: Decodable {
    let id: UUID
    let createdAt: String
    let updatedAt: String
    let keyFingerprint: String
    let revision: Int
}

struct MediaHeader: Decodable {
    let id: UUID
    let folderID: UUID?
    let createdAt: String
    let updatedAt: String
    let keyFingerprint: String
    let revision: Int
    let sealedMetadata: Data
}

struct ChunkHeader: Decodable {
    let id: UUID
    let mediaID: UUID
    let index: Int
    let createdAt: String
    let keyFingerprint: String
}
