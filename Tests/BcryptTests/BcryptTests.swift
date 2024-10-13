import Testing

@testable import Bcrypt

@Test func base64Encode() async throws {
    let b64Encoded = Base64.encode(Array("password".utf8))
    #expect(b64Encoded == "cGFzc3dvcmQ=")
}
