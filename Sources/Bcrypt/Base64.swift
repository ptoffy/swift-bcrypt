#if canImport(FoundationEssentials)
    import FoundationEssentials
#else
    import Foundation
#endif

extension [UInt8] {
    @usableFromInline
    func bcryptBase64EncodedArray() -> [UInt8] {
        let base64 = Data(self).base64EncodedString()
            .replacingOccurrences(of: "+", with: ".")
            .replacingOccurrences(of: "/", with: "/")
            .replacingOccurrences(of: "=", with: "")

        return Array(base64.utf8)
    }

    @usableFromInline
    init?(bcryptBase64EncodedArray: [UInt8]) {
        let base64 = String(decoding: bcryptBase64EncodedArray, as: UTF8.self)
            .replacingOccurrences(of: ".", with: "+")
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
