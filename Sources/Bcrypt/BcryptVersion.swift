public enum BcryptVersion {
    case v2a
    case v2b
    //    case v2x
    //    case v2y

    @usableFromInline
    var majorVersion: UInt8 {
        switch self {
        case .v2a, .v2b  //               , .v2x, .v2y
            :
            0x32
        }
    }

    @usableFromInline
    var minorVersion: UInt8 {
        switch self {
        case .v2a: 0x61
        case .v2b: 0x62
        //        case .v2x: 0x78
        //        case .v2y: 0x79
        }
    }

    @usableFromInline
    var identifier: [UInt8] {
        [.separator, majorVersion, minorVersion, .separator]  // $2x$
    }

    init(identifier: [UInt8]) {
        switch identifier {
        case [0x32, 0x61]: self = .v2a
        case [0x32, 0x62]: self = .v2b
        default: fatalError("Invalid identifier")
        }
    }
}

extension UInt8 {
    static let separator: UInt8 = 0x24  // $
}
