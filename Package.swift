// swift-tools-version: 6.4
import PackageDescription

let package = Package(
    name: "sigstore-swift",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "sigstore-swift-conformance", targets: ["sigstore-swift-conformance"]),
        .library(name: "Sigstore", targets: ["Sigstore"]),
        .library(name: "SigstoreBundle", targets: ["SigstoreBundle"]),
        .library(name: "SigstoreRoot", targets: ["SigstoreRoot"]),
        .library(name: "SigstoreTLog", targets: ["SigstoreTLog"]),
        .library(name: "SigstoreTUF", targets: ["SigstoreTUF"]),
        .library(name: "SigstoreVerify", targets: ["SigstoreVerify"]),
        .library(name: "SigstoreProtobufSpecs", targets: ["SigstoreProtobufSpecs"]),
        .library(name: "SigstoreFulcio", targets: ["SigstoreFulcio"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.12.0"..<"6.0.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.21.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.7.0"),
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.41.0"),
    ],
    targets: [
        // Generated from sigstore/protobuf-specs (see scripts/generate-protos.sh).
        .target(
            name: "SigstoreProtobufSpecs",
            dependencies: [.product(name: "SwiftProtobuf", package: "swift-protobuf")],
            exclude: ["Generated/VERSIONS.txt"]
        ),
        // Shared crypto/encoding helpers (not part of the sigstore-go API surface).
        .target(
            name: "SigstoreCommon",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        // Mirrors sigstore-go pkg/fulcio/certificate.
        .target(
            name: "SigstoreFulcio",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        // Mirrors sigstore-go pkg/root.
        .target(
            name: "SigstoreRoot",
            dependencies: [
                "SigstoreProtobufSpecs",
                "SigstoreCommon",
                "SigstoreTUF",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            resources: [.copy("Resources/trusted_root.json")]
        ),
        // Mirrors sigstore-go pkg/tlog.
        .target(
            name: "SigstoreTLog",
            dependencies: [
                "SigstoreProtobufSpecs",
                "SigstoreCommon",
                "SigstoreRoot",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
                .product(name: "X509", package: "swift-certificates"),
            ]
        ),
        // Mirrors sigstore-go pkg/tuf (with go-tuf v2's metadata/updater).
        .target(
            name: "SigstoreTUF",
            dependencies: [
                "SigstoreCommon",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            resources: [.copy("Resources/root.json"), .copy("Resources/staging_root.json")]
        ),
        // Mirrors sigstore-go pkg/verify.
        .target(
            name: "SigstoreVerify",
            dependencies: [
                "SigstoreProtobufSpecs",
                "SigstoreCommon",
                "SigstoreFulcio",
                "SigstoreRoot",
                "SigstoreTLog",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ]
        ),
        // Mirrors sigstore-go pkg/bundle.
        .target(
            name: "SigstoreBundle",
            dependencies: [
                "SigstoreProtobufSpecs",
                "SigstoreCommon",
                "SigstoreTLog",
                "SigstoreVerify",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ]
        ),
        // Umbrella module.
        .target(
            name: "Sigstore",
            dependencies: [
                "SigstoreProtobufSpecs",
                "SigstoreCommon",
                "SigstoreFulcio",
                "SigstoreBundle",
                "SigstoreRoot",
                "SigstoreTLog",
                "SigstoreTUF",
                "SigstoreVerify",
            ]
        ),
        // sigstore-conformance client (verify only). Not a library product.
        .executableTarget(
            name: "sigstore-swift-conformance",
            dependencies: [
                "Sigstore",
                .product(name: "X509", package: "swift-certificates"),
            ]
        ),
        .testTarget(
            name: "SigstoreTests",
            dependencies: [
                "Sigstore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            resources: [.copy("Fixtures")]
        ),
    ]
)
