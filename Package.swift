// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PasswordManagerResources",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.115.0")
    ],
    targets: [
        .executableTarget(
            name: "Run",
            dependencies: [.product(name: "Vapor", package: "vapor")],
            path: "Sources/Run"
        )
    ]
)
