struct Verifier {
    private let version: BcryptVersion
    private let hasher: Hasher

    init(version: BcryptVersion) {
        self.version = version
        self.hasher = Hasher(version: version)
    }

    @inlinable
    public func verify(password: [UInt8], hash goodHash: [UInt8]) throws -> Bool {
        let hash = try hasher.hash(password: password, cost: 6, salt: goodHash)
        return hash == goodHash
    }

}
