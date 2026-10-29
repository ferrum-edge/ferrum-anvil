// swift-tools-version: 5.9
import PackageDescription

// Make the standalone branding helper discoverable by CodeQL's Swift autobuild.
// `swift build --package-path apps/desktop/scripts` compiles it without running
// the asset generator; the existing `swift brand.swift ...` usage is unchanged.
let package = Package(
    name: "FerrumBrand",
    platforms: [.macOS(.v12)],
    products: [.executable(name: "ferrum-brand", targets: ["FerrumBrand"])],
    targets: [
        .executableTarget(
            name: "FerrumBrand",
            path: ".",
            exclude: ["gen-contracts.mjs"],
            sources: ["brand.swift"]
        )
    ]
)
