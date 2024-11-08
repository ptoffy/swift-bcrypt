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
        guard let cSalt = [UInt8](bcryptBase64EncodedArray: salt) else {
            throw BcryptError.invalidSalt
        }

        guard (cSalt.count * 3 / 4) <= Hasher.maxSalt else {
            throw BcryptError.invalidSaltLength
        }
        
        let password = switch version {
        case .v2a:
            password + [0]
        case .v2b:
            password
        }
        
        let cost = max(4, min(31, cost))
        let (p, s) = EksBlowfish.setup(password: password, salt: cSalt, cost: cost)

        var cData = [UInt32](repeating: 0, count: 64)

        for var i in 0..<Hasher.words {
            cData[i] = EksBlowfish.stream2word(data: Hasher.cipherText, j: &i)
        }

        for _ in 0..<64 {
            for j in 0..<Hasher.words / 2 {
                let (resultL, resultR) = EksBlowfish.encipher(xl: cData[j * 2], xr: cData[j * 2 + 1], p: p, s: s)
                cData[j * 2] = resultL
                cData[j * 2 + 1] = resultR
            }
        }

        var cipherText = Hasher.cipherText
        for i in 0..<Hasher.words {
            cipherText[4 * i + 0] = UInt8((cData[i] &>> 24) & 0xff)
            cipherText[4 * i + 1] = UInt8((cData[i] &>> 16) & 0xff)
            cipherText[4 * i + 2] = UInt8((cData[i] &>> 8) & 0xff)
            cipherText[4 * i + 3] = UInt8(cData[i] & 0xff)
        }

        var output = [UInt8]()

        let prefix = version.identifier + [UInt8]("\(String(format: "%02d", cost))$".utf8)

        output += prefix
        output += salt
        
        let encodedCipherText = cipherText.bcryptBase64EncodedArray()
        output += encodedCipherText

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

        let encodedSalt = cSalt.bcryptBase64EncodedArray()
        for (i, byte) in encodedSalt.enumerated() {
            if i < saltSpace {
                salt[i] = byte
            }
        }

        return salt
    }
}
