// swift-tools-version: 6.0
//
// DidjiSeal: the code that locks what people keep in Didji, published so that
// anyone can read it, check it against its test vectors, and open their own
// Didji backup without the app (`didji-open`).

import PackageDescription

let package = Package(
    name: "DidjiSeal",
    platforms: [.iOS("26.5"), .watchOS("26.0"), .macOS("15.0")],
    products: [
        .library(name: "DidjiSeal", targets: ["DidjiSeal"]),
        .executable(name: "didji-open", targets: ["didji-open"]),
    ],
    targets: [
        .target(name: "DidjiSeal"),
        // A second reader of the backup format, for didji-open. The app does
        // not use it.
        .target(name: "DidjiBackupReader", dependencies: ["DidjiSeal"]),
        .executableTarget(name: "didji-open", dependencies: ["DidjiBackupReader", "DidjiSeal"]),
        .testTarget(name: "DidjiSealTests", dependencies: ["DidjiSeal", "DidjiBackupReader"],
                    resources: [.copy("vectors.json"), .copy("Fixtures")]),
    ]
)
