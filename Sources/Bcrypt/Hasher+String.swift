extension Hasher {
    @inlinable
    public func hash(password: String, cost: Int) throws -> String {
        String(decoding: try hash(password: Array(password.utf8), cost: cost, salt: Hasher.generateRandomSalt()), as: UTF8.self)
    }
}
