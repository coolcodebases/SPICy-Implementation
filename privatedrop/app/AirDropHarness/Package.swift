// swift-tools-version:5.9
// builds privatedrop base without xcode, as one module with the framework sources and the spicy sources.
// it runs the psi flow end to end and compares psi backends.
// it must be built for x86_64, since privatedrop's macos relic and openssl archives are x86_64 only.
// usage: ../scripts/run-airdrop-harness.sh sets up the sources, builds and runs everything.
import PackageDescription

let base = Context.packageDirectory + "/../../privatedrop-base/Sources"
let spicyLib = Context.packageDirectory + "/../lib/macOS"
let linker: [LinkerSetting] = [
    .unsafeFlags([
        "-L", base + "/PSI/Relic/binary/macOS",
        "-L", base + "/OpenSSL/OpenSSLLib/binary/macOS",
        "-L", base + "/libarchive/LibArc/binary",
        "-L", spicyLib,
        "-lrelic_s", "-lssl", "-lcrypto", "-larchive-ios-mac",
    ]),
    .linkedLibrary("z"), .linkedLibrary("bz2"), .linkedLibrary("iconv"), .linkedLibrary("xml2"),
    .linkedLibrary("compression"), .linkedFramework("Security"),
]

let package = Package(
    name: "AirDropHarness",
    platforms: [.macOS(.v10_15)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.19.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.7.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.8.0"),
        .package(url: "https://github.com/Sn0wfreezeDev/ASN1Decoder.git", branch: "signatures"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.2"..<"2.0.0"),
    ],
    targets: [
        .systemLibrary(name: "Relic", path: "Sources/Relic"),
        .systemLibrary(name: "OpenSSLLib", path: "Sources/OpenSSLLib"),
        .systemLibrary(name: "LibArc", path: "Sources/LibArc"),
        .systemLibrary(name: "CSpicy", path: "Sources/CSpicy"),
        .target(
            name: "RelicImpl", path: "Sources/RelicImpl",
            cSettings: [.headerSearchPath("../Relic"), .headerSearchPath("../Relic/include")]),
        .target(
            name: "OpenSSLImpl", path: "Sources/OpenSSLImpl",
            cSettings: [
                .headerSearchPath("../OpenSSLLib"), .headerSearchPath("../OpenSSLLib/include"),
                .headerSearchPath("../OpenSSLLib/include/openssl"),
            ]),
        .target(name: "PSI", dependencies: ["Relic", "RelicImpl"]),
        .target(name: "OpenSSL", dependencies: ["OpenSSLLib", "OpenSSLImpl"]),
        .target(name: "Libarchive", dependencies: ["LibArc"]),
        .target(
            name: "PrivateDrop_Base",
            dependencies: [
                "PSI", "OpenSSL", "Libarchive", "CSpicy",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "ASN1Decoder", package: "ASN1Decoder"),
            ],
            swiftSettings: [.unsafeFlags(["-enable-testing"])]),  // for @testable in AirDropE2E
        // psi exchange between a privatedrop server and peer with the spicy backend
        .executableTarget(name: "AirDropE2E", dependencies: ["PrivateDrop_Base"], linkerSettings: linker),
        // original psi and spicy on identical inputs
        .executableTarget(name: "LegacyVsSpicy", dependencies: ["PSI", "SpicyPSI"], linkerSettings: linker),
        .target(name: "SpicyPSI", dependencies: ["CSpicy"]),
    ]
)
