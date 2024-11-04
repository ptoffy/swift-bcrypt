import Foundation
import Testing

@testable import Bcrypt

@Test("Simple Hashing")
func simpleHash() async throws {
    let password = Array("password".utf8)

    let hashedPassword = try Hasher(version: .v2b)
        .hash(password: password, cost: 12)

    print(String(decoding: hashedPassword, as: UTF8.self))
}
