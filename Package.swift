// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "bcrypt",
    platforms: [
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "Bcrypt",
            targets: ["Bcrypt"]
        )
    ],
    targets: [
        .target(
            name: "Bcrypt",
        ),
        .testTarget(
            name: "BcryptTests",
            dependencies: ["Bcrypt"]
        ),
    ]
)
