public enum BcryptVersion: Equatable, Sendable {
    case v2a
    case v2b

    @usableFromInline
    var majorVersion: UInt8 {
        switch self {
        case .v2a, .v2b: 0x32
        }
    }

    @usableFromInline
    var minorVersion: UInt8 {
        switch self {
        case .v2a: 0x61
        case .v2b: 0x62
        }
    }

    @usableFromInline
    var identifier: [UInt8] {
        [.separator, majorVersion, minorVersion, .separator]  // $2x$
    }

    @usableFromInline
    init?(identifier: ArraySlice<UInt8>) {
        switch identifier {
        case [0x24, 0x32, 0x61, 0x24]: self = .v2a
        case [0x24, 0x32, 0x62, 0x24], [0x24, 0x32, 0x79, 0x24]: self = .v2b  // use 2y as alias for 2b
        default: return nil
        }
    }
}

extension UInt8 {
    static let separator: UInt8 = 0x24  // $
}
