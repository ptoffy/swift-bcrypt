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

    @Test("Empty password")
    func emptyPassword() throws {
        #expect(throws: Error.self) {
            try Bcrypt.hash(password: "", cost: 6)
        }
    }

    @Test("Maximum length password (72 bytes)")
    func maximumLengthPassword() throws {
        let password = String(repeating: "a", count: 72)
        let hash = try Bcrypt.hash(password: password, cost: 6)
        #expect(try Bcrypt.verify(password: password, hash: hash))
    }

    @Test("Password too long")
    func passwordTooLong() throws {
        let password = String(repeating: "a", count: 73)
        #expect(throws: BcryptError.passwordTooLong) {
            try Bcrypt.hash(password: password, cost: 6)
        }
    }

    @Test("Different passwords produce different hashes")
    func differentPasswordsDifferentHashes() throws {
        let hash1 = try Bcrypt.hash(password: "password1", cost: 6)
        let hash2 = try Bcrypt.hash(password: "password2", cost: 6)

        #expect(hash1 != hash2)
    }

    @Test("Same password with different salts produces different hashes")
    func samePwDifferentSalts() throws {
        let password = "test"
        let hash1 = try Bcrypt.hash(password: password, cost: 6)
        let hash2 = try Bcrypt.hash(password: password, cost: 6)

        #expect(hash1 != hash2)

        #expect(try Bcrypt.verify(password: password, hash: hash1))
        #expect(try Bcrypt.verify(password: password, hash: hash2))
    }

    @Test("Unicode password handling")
    func unicodePassword() throws {
        let passwords = ["πάσσω", "密码", "🔐🔑", "Ñoño"]

        for password in passwords {
            let hash = try Bcrypt.hash(password: password, cost: 4)
            #expect(try Bcrypt.verify(password: password, hash: hash))
        }
    }

    @Test("Wrong password fails verification")
    func wrongPasswordFails() throws {
        let hash = try Bcrypt.hash(password: "correct", cost: 6)
        #expect(try !Bcrypt.verify(password: "wrong", hash: hash))
    }
}
