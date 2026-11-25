//
//  didji-open: open a Didji backup with your recovery kit, without the app.
//
//      didji-open <backup file> <new folder>
//
//  It asks for the recovery kit's code (typed, or pasted; it is not shown),
//  checks the backup is whole, and writes everything in it into the new
//  folder: each record as the JSON Didji sealed, each document and photograph
//  as its own file. It only reads the backup. It reaches no network: it links
//  Foundation and CryptoKit and nothing else (`otool -L` shows it).
//
//  The code is asked for rather than taken as an argument, so it never lands
//  in your shell's history. Piped in, it is read from standard input.
//

import DidjiBackupReader
import DidjiSeal
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("didji-open: \(message)\n".utf8))
    exit(1)
}

let arguments = CommandLine.arguments
guard arguments.count == 3 else {
    fail("usage: didji-open <backup file> <new folder>")
}
let source = URL(fileURLWithPath: arguments[1])
let destination = URL(fileURLWithPath: arguments[2])
guard !FileManager.default.fileExists(atPath: destination.path) else {
    fail("\(destination.path) already exists. Name a new folder, so nothing is written over.")
}
let file: Data
do { file = try Data(contentsOf: source, options: .mappedIfSafe) } catch { fail("cannot read \(source.path)") }

let code: String
if isatty(STDIN_FILENO) != 0 {
    guard let typed = getpass("Recovery kit code: ") else { fail("no code given") }
    code = String(cString: typed)
} else {
    code = readLine() ?? ""
}

let backup: OpenedBackup
do { backup = try BackupReader.open(file, code: code) } catch let error as BackupReaderError {
    fail(error.description)
} catch {
    fail("\(error)")
}

// MARK: - Writing it out

let manager = FileManager.default
@MainActor func folder(_ parts: String...) -> URL {
    let url = parts.reduce(destination) { $0.appendingPathComponent($1, isDirectory: true) }
    try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}
func write(_ data: Data, _ url: URL) {
    do { try data.write(to: url, options: .withoutOverwriting) } catch { fail("cannot write \(url.path)") }
}
/// JSON as people can read it; anything else as it came.
func readable(_ data: Data) -> Data {
    guard let object = try? JSONSerialization.jsonObject(with: data),
          let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    else { return data }
    return pretty
}
/// A file name from the backup, kept to one name inside its own folder.
func safeName(_ name: String?, otherwise: String) -> String {
    let last = (name ?? "").split(separator: "/").last.map(String.init) ?? ""
    let cleaned = last.replacingOccurrences(of: ":", with: "-")
    return cleaned.isEmpty || cleaned == "." || cleaned == ".." ? otherwise : cleaned
}
func string(_ json: Data, _ key: String) -> String? {
    (try? JSONSerialization.jsonObject(with: json) as? [String: Any])?[key] as? String
}

try? manager.createDirectory(at: destination, withIntermediateDirectories: false)
let names: [SealedRecordKind: String] = [
    .item: "records", .category: "categories", .subject: "people-and-places", .template: "templates",
    .preferences: "settings", .thing: "things", .passkey: "passkeys", .itemVersion: "history",
]
var counts: [String: Int] = [:]
var details: [UUID: Data] = [:]
for record in backup.records {
    switch record.kind {
    case .attachmentMetadata:
        details[record.id] = record.plaintext
    case .attachmentData:
        let meta = details[record.id] ?? Data()
        let here = folder("documents", record.id.uuidString)
        write(readable(meta), here.appendingPathComponent("details.json"))
        write(record.plaintext, here.appendingPathComponent(safeName(string(meta, "filename"), otherwise: "document")))
        counts["documents", default: 0] += 1
    default:
        let name = names[record.kind] ?? "other"
        write(readable(record.plaintext), folder(name).appendingPathComponent("\(record.id.uuidString).json"))
        counts[name, default: 0] += 1
    }
}
for album in backup.albums {
    write(readable(album.plaintext), folder("albums").appendingPathComponent("\(album.id.uuidString).json"))
    counts["albums", default: 0] += 1
}
for media in backup.media {
    let here = folder("photos", media.id.uuidString)
    write(readable(media.metadata), here.appendingPathComponent("details.json"))
    write(media.thumbnail, here.appendingPathComponent("thumbnail.jpg"))
    write(media.original, here.appendingPathComponent(safeName(string(media.metadata, "filename"), otherwise: "original")))
    counts["photos and videos", default: 0] += 1
}

var summary = """
Opened a Didji backup, format \(backup.formatVersion), with recovery kit \(backup.kitID ?? "(the vault key)").
\(backup.structureVerified ? "Checked whole: every record its sealed list names is here, unchanged." : "Made before backups listed their contents, so it could not be checked whole.")

"""
for (name, count) in counts.sorted(by: { $0.key < $1.key }) { summary += "  \(count) \(name)\n" }
if backup.underAnotherKey > 0 {
    summary += "\n\(backup.underAnotherKey) records are locked with another vault key and were left out.\n"
}
if backup.photosMissing {
    summary += "\nThis file is the backup without Private Photos; they were in a separate part that is not here.\n"
}
summary += "\nWritten to \(destination.path). It holds everything in the backup, unlocked: keep it as safe as the kit.\n"
print(summary, terminator: "")
