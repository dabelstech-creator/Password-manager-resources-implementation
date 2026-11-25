// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PasswordManagerResources",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.115.0"),
        .package(url: "https://github.com/vapor/fluent.git", from: "4.12.0"),
        .package(url: "https://github.com/vapor/fluent-postgres-driver.git", from: "2.10.0"),
        .package(url: "https://github.com/vapor/jwt-kit.git", exact: "5.4.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.1.0")
    ],
    targets: [
        .executableTarget(
            name: "Run",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Fluent", package: "fluent"),
                .product(name: "FluentPostgresDriver", package: "fluent-postgres-driver"),
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "Sources/Run"
        )
    ]
)
