#if canImport(FoundationEssentials)
    import FoundationEssentials
#else
    import Foundation
#endif

public struct Hasher {
    @usableFromInline static let cipherText = Array("OrpheanBeholderScryDoubt".utf8)
    @usableFromInline static let maxSalt = 16
    @usableFromInline static let saltSpace = 22
    @usableFromInline static let words = 6
    @usableFromInline static let hashSpace = 60

    @usableFromInline let version: BcryptVersion

    public init(version: BcryptVersion = .v2a) {
        self.version = version
    }

    /// Encrypts a password using the bcrypt algorithm.
    /// - Parameters:
    ///   - cost: number of rounds to apply the key derivation function, used as log2(cost)
    ///   - password: the password to hash
    /// - Throws:
    /// - Returns:
    @inlinable
    public func hash(password: [UInt8], cost: Int) throws -> [UInt8] {
        try hash(password: password, cost: cost, salt: Hasher.generateRandomSalt())
    }

    @inlinable
    public func hash(password: [UInt8], cost: Int, salt: [UInt8]) throws -> [UInt8] {
        guard (salt.count * 3 / 4) - 1 < Hasher.maxSalt else {
            throw BcryptError.invalidSaltLength
        }

        let cSalt = Base64.decode(salt, count: UInt(Self.maxSalt))

        guard password.count > 0 else {
            throw BcryptError.emptyPassword
        }

        let password =
            if password[password.endIndex - 1] == 0 {
                Array(password[password.startIndex..<password.endIndex - 1]) + [0]
            } else {
                password + [0]
            }

        if cost < 4 || cost > 31 {
            throw BcryptError.invalidCost
        }

        let (p, s) = EksBlowfish.setup(password: password, salt: cSalt, cost: cost)

        var cData = [UInt32](repeating: 0, count: Hasher.words)

        var i = 0
        var j = 0
        while i < Hasher.words {
            cData[i] = EksBlowfish.stream2word(data: Hasher.cipherText, j: &j)
            i &+= 1
        }

        i = 0
        while i < 64 {
            var j = 0
            var xl: UInt32 = 0
            var xr: UInt32 = 0
            while j < Hasher.words / 2 {
                xl = cData[j * 2]
                xr = cData[j * 2 + 1]
                EksBlowfish.encipher(xl: &xl, xr: &xr, p: p, s: s)
                cData[j * 2] = xl
                cData[j * 2 + 1] = xr
                j &+= 1
            }
            i &+= 1
        }

        var cipherText = Hasher.cipherText
        i = 0
        while i < Hasher.words {
            cipherText[4 * i + 3] = UInt8(cData[i] & 0xff)
            cipherText[4 * i + 2] = UInt8((cData[i] &>> 8) & 0xff)
            cipherText[4 * i + 1] = UInt8((cData[i] &>> 16) & 0xff)
            cipherText[4 * i + 0] = UInt8((cData[i] &>> 24) & 0xff)
            i &+= 1
        }

        var output = [UInt8]()

        let prefix = version.identifier + [UInt8]("\(String(format: "%02d", cost))$".utf8)

        output += prefix
        output += salt
        output += Base64.encode(cipherText, count: 4 * Self.words - 1)

        return output
    }

    // $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
    // \__/\/ \____________________/\_____________________________/
    // Alg Cost      Salt                        Hash
    @usableFromInline
    static func generateRandomSalt() -> [UInt8] {
        var salt = [UInt8](repeating: 0, count: saltSpace)

        var cSalt = [UInt8](repeating: 0, count: maxSalt)
        for i in 0..<maxSalt {
            cSalt[i] = UInt8.random(in: .min ... .max)
        }

        let encodedSalt = Base64.encode(cSalt, count: Self.hashSpace)
        for (i, byte) in encodedSalt.enumerated() {
            if i < saltSpace {
                salt[i] = byte
            }
        }

        return salt
    }
}
