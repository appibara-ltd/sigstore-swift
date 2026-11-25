// swift-tools-version: 6.4
// libFuzzer harness for sigstore-swift's hand-written parsers. Build and run
// with scripts/fuzz.sh (Linux: the swift.org toolchain ships libFuzzer).
// This package only links with `-sanitize=fuzzer` (libFuzzer provides main).
import PackageDescription

let package = Package(
    name: "SigstoreFuzz",
    platforms: [.macOS(.v26)],
    dependencies: [.package(path: "..")],
    targets: [
        .executableTarget(
            name: "SigstoreFuzz",
            dependencies: [
                .product(name: "Sigstore", package: "sigstore-swift"),
                .product(name: "SigstoreMLDSA", package: "sigstore-swift"),
            ]
        )
    ]
)
