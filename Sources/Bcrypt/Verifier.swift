struct Verifier {
    @inlinable
    public func verify(password: [UInt8], hash goodHash: [UInt8]) throws -> Bool {
        let prefix = goodHash.prefix(7)

        let version = BcryptVersion(identifier: Array(prefix[1...2]))
        let cost = prefix[4...5].reduce(0) { $0 * 10 + Int($1 - 48) }

        let salt = Array(goodHash[7...28])

        let hasher = Hasher(version: version)
        let newHash = try hasher.hash(password: password, cost: cost, salt: salt)

        return newHash == goodHash
    }

}
