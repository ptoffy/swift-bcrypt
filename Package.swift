// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "swift-bcrypt",
    products: [
        .library(
            name: "Bcrypt",
            targets: ["Bcrypt"]
        )
    ],
    targets: [
        .target(
            name: "Bcrypt"
        ),
        .testTarget(
            name: "BcryptTests",
            dependencies: ["Bcrypt"]
        ),
    ]
)
