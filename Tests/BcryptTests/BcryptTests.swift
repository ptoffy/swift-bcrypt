import Bcrypt
import Testing

@Suite("Bcrypt Tests")
struct BcryptTests {
    @Test("Test Vectors", arguments: TestVector.all)
    func testVectorsHashing(testVector: TestVector) throws {
        let hash = try Bcrypt.hash(
            password: Array(testVector.password.utf8), cost: testVector.cost, salt: Array(testVector.salt.utf8), version: .v2a
        )

        #expect(
            hash == Array(testVector.expectedHash.utf8),
            "Expected: \(testVector.expectedHash), got: \(String(decoding: hash, as: UTF8.self))"
        )
    }

    @Test("End to end")
    func endToEnd() throws {
        let password = "password"
        let cost = 12

        let hash = try Bcrypt.hash(password: password, cost: cost)

        #expect(try Bcrypt.verify(password: password, hash: hash))
    }

    @Test("Correct Version")
    func correctVersion() throws {
        let hash = try Bcrypt.hash(password: "password", cost: 6)

        #expect(hash.hasPrefix("$2b$06$"))
    }
}
