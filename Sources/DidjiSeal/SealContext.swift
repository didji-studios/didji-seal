//
//  SealContext.swift
//  Part of DidjiSeal: the code that locks what people keep in Didji.
//  This is the code the app ships; the app, its AutoFill, Didji for Safari and
//  the Apple Watch app all use it. References to docs/ are to Didji's own
//  design notes; what matters from them is in SPEC.md beside this package.
//
//  What a sealed blob is, and where it belongs — authenticated alongside the
//  ciphertext so it cannot be moved onto another record. See
//  docs/finished/record-binding.md.
//
//  AES-GCM proves a blob was made with the vault key and has not been altered.
//  It says nothing about which record the blob belongs to, because the envelope
//  around it — id, parent, dates — sits outside the ciphertext. Passing this as
//  the authenticated data ties the two together: the context is rebuilt from the
//  envelope when opening, so a swapped envelope is exactly what makes the open
//  fail.
//
//  The byte layout is written out by hand and pinned by a test. It is part of
//  the cryptographic protocol, so it must never be left to Codable, whose output
//  can move with a compiler or framework change.
//

import Foundation

/// What kind of thing a sealed blob is. The raw values are wire format: they
/// are authenticated, so changing one invalidates every record of that kind.
/// Add new cases with new numbers; never renumber and never reorder.
public enum SealedRecordKind: UInt8, Sendable, CaseIterable {
    case item = 1
    case attachmentMetadata = 2
    case attachmentData = 3
    case passkey = 4
    case category = 5
    case subject = 6
    case template = 7
    case preferences = 8
    case faviconCache = 9
    case addressCache = 10
    case backupManifest = 11
    /// The photo vault's three, added 23 September 2026. See
    /// docs/finished/photo-vault-brief.md. A chunk is the only kind whose context
    /// carries more than the envelope: its index and count. See `chunk`.
    case mediaMetadata = 12
    case mediaThumbnail = 13
    case mediaChunk = 14
    case mediaFolder = 15
    /// Sharing, added 27 September 2026. See docs/shared-vaults-brief.md.
    /// A connection lives in the owner's vault, under the vault key: which
    /// Household person, which space, and that space's key.
    case connection = 16
    /// The four a space may hold, each under that space's key and never the
    /// vault's. A copy keeps its source's id and revision; a space item's
    /// parent is its space, and a space attachment's or passkey's is its item.
    /// `SpaceStoreContainer.permittedKinds` is the list, and nothing else is
    /// sealed into a space.
    case spaceItem = 17
    case spaceAttachmentMetadata = 18
    case spaceAttachmentData = 19
    case spacePasskey = 20
    /// What a space should hold and what was taken out of it — see
    /// `SpaceManifest`. One per space, its id the space's own.
    case spaceManifest = 21
    /// The one record a recipient writes: her reply to an invitation, sealed
    /// under the invitation's space key and bound to that space. See
    /// `SpaceReply`.
    case spaceReply = 22
    /// Item history, added 29 September 2026: one version of an item, bound
    /// to it as a passkey is. Never sealed into a space. See
    /// docs/item-history-brief.md.
    case itemVersion = 23
    /// What this device has read in the vault's documents, for search: a
    /// sealed file of its own, like the logos, never synced. Added 4 October
    /// 2026. See docs/searchable-scans-brief.md.
    case documentText = 24
    /// Passwords AutoFill caught after the trial, waiting for Didji to be
    /// bought: a sealed file of its own on the device that caught them, never
    /// synced or backed up. Added 11 October 2026. See docs/monetisation.md,
    /// "Stage 6, the design".
    case pendingPasswords = 25
    /// When each record was used on this device, for Recently used and Most
    /// used: a sealed file of its own, like the logos, never synced or backed
    /// up. Added 14 October 2026. See docs/1password-gaps-brief.md, section 2.
    case usageHistory = 26
    /// The public lists 2factorauth publishes (the passkey list, the sign-in
    /// code list), each a sealed file of its own on the device, so a link in
    /// one cannot be changed on disk and neither is read while locked. Added
    /// 14 October 2026. See docs/1password-gaps-brief.md, 4.3.
    case siteLists = 27
    /// A room, a container, a line, a load, a move or one of its marks: each
    /// its own small record, so two phones packing at once can never lose
    /// one another's work. Added 27 October 2026. See
    /// docs/rooms-and-moving-brief.md, section 5.6.
    case thing = 28
    /// The access log as iCloud holds it: when the vault was last opened and
    /// on what, with the names its owner gave each device. One a vault, under
    /// a fixed id, sealed since 17 November 2026 (the fourth code review,
    /// A119). See `VaultAccessSnapshot.sealContext`.
    case accessLog = 29
    /// Collaborative editing: one change somebody made to a record shared
    /// with them, waiting to reach its owner; one answer the owner's Didji
    /// gave; or one change that was not kept, until seen. Each its own small
    /// record, never a list inside the connection record, so two devices
    /// adding one at once never lose the other's (the owner's decision of 22
    /// November 2026, option A). See docs/collaborative-editing-brief.md.
    case sharedChange = 30
}

public struct SealContext: Equatable, Sendable {

    /// This app's sealing protocol, so a later format — another primitive, or
    /// another kind of blob entirely — gets its own namespace rather than
    /// colliding with this one.
    public static let domain = Data("PVSEAL".utf8)
    /// Sealed with the vault key itself.
    public static let currentFormat: UInt8 = 1
    /// Sealed with a key of its own, that key wrapped under the vault key and
    /// carried in front of the payload. See docs/finished/key-hierarchy-brief.md.
    public static let wrappedFormat: UInt8 = 2

    /// Marker written in front of a bound blob, so an opener can tell the two
    /// formats apart before it tries either. Its value is also inside the
    /// authenticated bytes below, so it cannot be made to mean anything else.
    public static var marker: Data { domain + Data([currentFormat]) }

    public let format: UInt8
    public let record: SealedRecordKind
    public let recordID: UUID
    /// The owning item, for an attachment or a passkey.
    public let parentID: UUID?
    /// The envelope's revision, authenticated so the two cannot disagree.
    /// Consistency, not freshness — see the document.
    public let revision: UInt32
    /// For a media chunk only: which chunk this is, of how many. Nil for every
    /// other kind, whose bytes must never change — every record in every vault
    /// was sealed against them.
    public let chunk: ChunkPosition?

    /// Where a chunk sits in its file. Both numbers are authenticated, so a
    /// chunk cannot be moved to another position, a file cannot be passed off
    /// as a shorter one by dropping its tail, and a chunk from a file of a
    /// different length is refused even at the same index.
    public struct ChunkPosition: Equatable, Sendable {
        public let index: UInt32
        public let count: UInt32

        public init(index: UInt32, count: UInt32) {
            self.index = index
            self.count = count
        }
    }

    public init(_ record: SealedRecordKind,
         id recordID: UUID,
         parent parentID: UUID? = nil,
         revision: UInt32 = 0,
         format: UInt8 = SealContext.currentFormat) {
        self.record = record
        self.recordID = recordID
        self.parentID = parentID
        self.revision = revision
        self.format = format
        self.chunk = nil
    }

    /// The context for one chunk of a media record's bytes: bound to the media
    /// record as its parent, and to its own place in the file.
    ///
    /// The invariant the brief asks for, made a type: chunk 17 cannot be
    /// transplanted into chunk 18's place, nor any chunk into another record,
    /// nor a shorter file passed off as a longer one — because the media
    /// record's id, the index and the count are all inside what the seal
    /// authenticates. `index` must be below `count`; a chunk with no place in
    /// its file is a programming error, not a value.
    public static func chunk(id chunkID: UUID,
                      ofMedia mediaID: UUID,
                      index: UInt32,
                      count: UInt32,
                      revision: UInt32 = 0) -> SealContext {
        precondition(index < count, "chunk \(index) of \(count) has no place in its file")
        return SealContext(.mediaChunk, id: chunkID, parent: mediaID, revision: revision,
                           chunk: ChunkPosition(index: index, count: count))
    }

    private init(_ record: SealedRecordKind,
                 id recordID: UUID,
                 parent parentID: UUID?,
                 revision: UInt32,
                 format: UInt8 = SealContext.currentFormat,
                 chunk: ChunkPosition?) {
        self.record = record
        self.recordID = recordID
        self.parentID = parentID
        self.revision = revision
        self.format = format
        self.chunk = chunk
    }

    /// The exact bytes authenticated with the ciphertext:
    ///
    ///     0   6   domain, ASCII "PVSEAL"
    ///     6   1   format version
    ///     7   1   record kind
    ///     8   16  record UUID
    ///     24  1   parent present, 0 or 1
    ///     25  16  parent UUID, only when present
    ///     +   4   revision, big-endian
    ///     +   4   chunk index, big-endian — media chunks only
    ///     +   4   chunk count, big-endian — media chunks only
    ///
    /// The two chunk fields come last and only for a chunk, so every other
    /// kind's bytes are exactly what they were before chunks existed.
    public var bytes: Data {
        var bytes = Self.domain
        bytes.append(format)
        bytes.append(record.rawValue)
        bytes.append(contentsOf: Self.uuidBytes(recordID))
        if let parentID {
            bytes.append(1)
            bytes.append(contentsOf: Self.uuidBytes(parentID))
        } else {
            bytes.append(0)
        }
        bytes.append(contentsOf: withUnsafeBytes(of: revision.bigEndian) { Array($0) })
        if let chunk {
            bytes.append(contentsOf: withUnsafeBytes(of: chunk.index.bigEndian) { Array($0) })
            bytes.append(contentsOf: withUnsafeBytes(of: chunk.count.bigEndian) { Array($0) })
        }
        return bytes
    }

    /// The same context at another format. The format is inside the
    /// authenticated bytes, so the two forms of a blob can never be confused
    /// for one another even where everything else about the record matches.
    public func withFormat(_ format: UInt8) -> SealContext {
        SealContext(record,
                    id: recordID,
                    parent: parentID,
                    revision: revision,
                    format: format,
                    chunk: chunk)
    }

    /// What the wrapped key authenticates: the record's own bytes and one more,
    /// so that the wrap and the payload it guards never authenticate the same
    /// thing.
    ///
    /// Belt and braces, and no test proves it, because nothing observable
    /// depends on it: the two are under different keys already, so a wrap read
    /// as a payload yields the wrong key and the open fails a step later
    /// either way. Kept because the cost is one byte and the alternative is
    /// reasoning about that every time this is read.
    public var wrapBytes: Data { bytes + Data([1]) }

    private static func uuidBytes(_ id: UUID) -> [UInt8] {
        withUnsafeBytes(of: id.uuid) { Array($0) }
    }
}
