#if canImport(FoundationEssentials)
    import FoundationEssentials
#else
    import Foundation
#endif

struct Hasher {
    private static let separator = 0x24  // $
    private static let cipherText = Array("OrpheanBeholderScryDoubt".utf8)
    private static let maxSalt = 16
    private static let saltSpace = 29
    private static let words = 6

    private let version: BcryptVersion

    init(version: BcryptVersion) {
        self.version = version
    }

    /// Encrypts a password using the bcrypt algorithm.
    /// - Parameters:
    ///   - cost: number of rounds to apply the key derivation function, used as log2(cost)
    ///   - password: the password to hash
    /// - Throws:
    /// - Returns:
    public func hash(password: [UInt8], cost: Int) throws -> [UInt8] {
        try hash(password: password, cost: cost, salt: Hasher.randomSalt(logRounds: cost))
    }

    public func hash(password: [UInt8], cost: Int, salt: [UInt8]) throws -> [UInt8] {
        let cSalt = [UInt8](bcryptBase64EncodedArray: Array(salt[7...]))!

        guard (cSalt.count * 3 / 4) <= Hasher.maxSalt else {
            throw BcryptError.invalidSaltLength
        }

        let passwordWithNullTerminator = password + [0]

        let (p, s) = EksBlowfish.setup(password: passwordWithNullTerminator, salt: cSalt, cost: cost)

        var cData = [UInt32](repeating: 0, count: 64)

        for var i in 0..<Hasher.words {
            cData[i] = EksBlowfish.stream2word(data: Hasher.cipherText, j: &i)
        }

        for _ in 0..<64 {
            for j in 0..<Hasher.words {
                let (resultL, resultR) = EksBlowfish.encipher(xl: cData[j * 2], xr: cData[j * 2 + 1], p: p, s: s)
                cData[j * 2] = resultL
                cData[j * 2 + 1] = resultR
            }
        }

        var cipherText = Hasher.cipherText
        for i in 0..<Hasher.words {
            cipherText[4 * i + 3] = UInt8(cData[i] & 0xff)
            cipherText[4 * i + 2] = UInt8((cData[i] &>> 8) & 0xff)
            cipherText[4 * i + 1] = UInt8((cData[i] &>> 16) & 0xff)
            cipherText[4 * i + 0] = UInt8((cData[i] &>> 24) & 0xff)
        }

        var output = [UInt8](repeating: 0, count: 60)
        output.append(contentsOf: salt)
        output.append(contentsOf: cipherText.bcryptBase64EncodedArray())

        return output
    }

    // $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
    // \__/\/ \____________________/\_____________________________/
    // Alg Cost      Salt                        Hash
    static func randomSalt(logRounds: Int) -> [UInt8] {
        var salt = [UInt8](repeating: 0, count: saltSpace)

        var cSalt = [UInt8](repeating: 0, count: maxSalt)
        for i in 0..<maxSalt {
            cSalt[i] = UInt8.random(in: .min ... .max)
        }

        var logRounds = logRounds
        if logRounds < 4 {
            logRounds = 4
        } else if logRounds > 31 {
            logRounds = 31
        }

        let prefix = "$2b$\(String(format: "%02d", logRounds))$".data(using: .utf8)!

        for (i, byte) in prefix.enumerated() {
            salt[i] = byte
        }

        let encodedSalt = cSalt.bcryptBase64EncodedArray()
        for (i, byte) in encodedSalt.enumerated() {
            if i + prefix.count < saltSpace {
                salt[i + prefix.count] = byte
            }
        }

        return salt
    }
}

extension [UInt8] {
    func bcryptBase64EncodedArray() -> [UInt8] {
        var base64 = Data(self).base64EncodedString()

        base64 = base64.replacingOccurrences(of: "+", with: ".")
            .replacingOccurrences(of: "/", with: "/")
            .replacingOccurrences(of: "=", with: "")

        return Array(base64.utf8)
    }

    init?(bcryptBase64EncodedArray: [UInt8]) {
        let string = String(decoding: bcryptBase64EncodedArray, as: UTF8.self)
        let base64 = string.replacingOccurrences(of: ".", with: "+")
            .replacingOccurrences(of: "/", with: "/")

        let paddedBase64 = base64.padding(
            toLength: ((base64.count + 3) / 4) * 4,
            withPad: "=",
            startingAt: 0
        )

        guard let data = Data(base64Encoded: paddedBase64) else {
            return nil
        }

        self = [UInt8](data)
    }

}
