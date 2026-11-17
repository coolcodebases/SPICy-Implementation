// swift-tools-version:5.9
// swift interface to the spicy psi library for privatedrop.
// CSpicy is the c module over libspicy_ffi.a in lib/<platform>.
// SpicyPSI is the swift wrapper and privatedrop's mutual psi flow.
// SpicyPSIBench is the benchmark executable.
// the -L flags are for swiftpm builds, the xcode project links lib/<platform> itself.
import Foundation
import PackageDescription

let libDir = Context.packageDirectory + "/lib"

let package = Package(
    name: "SpicyPSI",
    platforms: [.macOS(.v10_15), .iOS(.v13)],
    products: [
        .library(name: "SpicyPSI", targets: ["SpicyPSI"]),
        .executable(name: "spicy-psi-bench", targets: ["SpicyPSIBench"]),
    ],
    targets: [
        .systemLibrary(name: "CSpicy", path: "Sources/CSpicy"),
        .target(
            name: "SpicyPSI",
            dependencies: ["CSpicy"],
            linkerSettings: [
                .unsafeFlags(["-L", libDir + "/macOS"], .when(platforms: [.macOS])),
                .unsafeFlags(["-L", libDir + "/iOS"], .when(platforms: [.iOS])),
                .linkedFramework("Security"),
            ]),
        .executableTarget(name: "SpicyPSIBench", dependencies: ["SpicyPSI"]),
    ]
)
