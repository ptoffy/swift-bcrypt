struct Hasher {
    private static let saltLength = 16
    private static let separator = 0x24  // $

    private let version: BcryptVersion

    /// Encrypts a password using the bcrypt algorithm.
    /// - Parameters:
    ///   - cost: number of rounds to apply the key derivation function, used as log2(cost)
    ///   - password: the password to hash
    /// - Throws:
    /// - Returns:
    public static func hash(cost: Int, password: [UInt8]) throws -> [UInt8] {
        try hash(cost: cost, salt: [UInt8].random(count: saltLength), password: password)
    }

    public static func hash(cost: Int, salt: [UInt8], password: [UInt8]) throws -> [UInt8] {
        guard salt.count == saltLength else {
            throw BcryptError.invalidSaltLength
        }

        let passwordWithNullTerminator = password + [0]

        fatalError("Not implemented")
    }
}

extension [UInt8] {
    static func random(count: Int) -> [UInt8] {
        var array = [UInt8](repeating: 0, count: count)
        // SystemRandomNumberGenerator is automatically seeded, is safe to use in multiple threads,
        // and uses a cryptographically secure algorithm whenever possible.
        var random = SystemRandomNumberGenerator()
        for i in 0..<count {
            array[i] = UInt8.random(in: .min ... .max, using: &random)
        }

        return array
    }
}
