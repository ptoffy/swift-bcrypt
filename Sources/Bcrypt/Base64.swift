// https://github.com/lemire/fastbase64/blob/master/src/chromiumbase64.c
enum Base64 {
    @inlinable static func encode(_ string: [UInt8]) -> String {
        let inputLength = string.count
        // Every 3 bytes of input is encoded into 4 bytes of output
        let outputLength = (inputLength + 2) / 3 * 4

        return string.withUnsafeBufferPointer { inputBuffer in
            let output = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: outputLength)
            defer { output.deallocate() }

            return e0.withUnsafeBufferPointer { e0Buffer in
                return e1.withUnsafeBufferPointer { e1Buffer in
                    // Set up pointers to the input and output buffers
                    let inputPtr = inputBuffer.baseAddress!
                    let outputPtr = output.baseAddress!
                    let e0Ptr = e0Buffer.baseAddress!
                    let e1Ptr = e1Buffer.baseAddress!

                    // Indices for the input and output buffers
                    var i = 0
                    var j = 0

                    // for i in stride(from: 0, to: inputLength - 2, by: 3)
                    // Process input 3 bytes at a time, producing 4 Base64 output bytes
                    while i < inputLength - 2 {
                        let t1 = inputPtr[i]
                        let t2 = inputPtr[i &+ 1]
                        let t3 = inputPtr[i &+ 2]

                        outputPtr[j] = e0Ptr[Int(t1)]
                        outputPtr[j &+ 1] = e1Ptr[Int(((t1 & 0x03) << 4) | ((t2 >> 4) & 0x0F))]
                        outputPtr[j &+ 2] = e1Ptr[Int(((t2 & 0x0F) << 2) | ((t3 >> 6) & 0x03))]
                        outputPtr[j &+ 3] = e1Ptr[Int(t3)]

                        i &+= 3
                        j &+= 4
                    }

                    // Handle the remaining bytes in the input buffer if the input length is not a multiple of 3.
                    // Also pad the output buffer with '=' characters to make the output length a multiple of 4
                    switch inputLength - i {
                    case 0: break
                    case 1:
                        let t1 = inputPtr[i]
                        outputPtr[j] = e0Ptr[Int(t1)]
                        outputPtr[j &+ 1] = e1Ptr[Int((t1 & 0x03) << 4)]
                        outputPtr[j &+ 2] = 61  // '='
                        outputPtr[j &+ 3] = 61  // '='
                    case 2:
                        let t1 = inputPtr[i]
                        let t2 = inputPtr[i &+ 1]
                        outputPtr[j] = e0Ptr[Int(t1)]
                        outputPtr[j &+ 1] = e1Ptr[Int(((t1 & 0x03) << 4) | ((t2 >> 4) & 0x0F))]
                        outputPtr[j &+ 2] = e1Ptr[Int((t2 & 0x0F) << 2)]
                        outputPtr[j &+ 3] = 61  // '='
                    default: break  // Unreachable as we're handling the previous bytes in groups of 3
                    }

                    // *p = '\0';

                    return String(decoding: output, as: UTF8.self)
                }
            }
        }
    }
}

extension Base64 {
    // https://github.com/lemire/fastbase64/blob/master/src/chromiumbase64.c#L6
    @usableFromInline static let e0: [UInt8] = [
        65, 65, 65, 65, 66, 66, 66, 66, 67, 67,
        67, 67, 68, 68, 68, 68, 69, 69, 69, 69,
        70, 70, 70, 70, 71, 71, 71, 71, 72, 72,
        72, 72, 73, 73, 73, 73, 74, 74, 74, 74,
        75, 75, 75, 75, 76, 76, 76, 76, 77, 77,
        77, 77, 78, 78, 78, 78, 79, 79, 79, 79,
        80, 80, 80, 80, 81, 81, 81, 81, 82, 82,
        82, 82, 83, 83, 83, 83, 84, 84, 84, 84,
        85, 85, 85, 85, 86, 86, 86, 86, 87, 87,
        87, 87, 88, 88, 88, 88, 89, 89, 89, 89,
        90, 90, 90, 90, 97, 97, 97, 97, 98, 98,
        98, 98, 99, 99, 99, 99, 100, 100, 100, 100,
        101, 101, 101, 101, 102, 102, 102, 102, 103, 103,
        103, 103, 104, 104, 104, 104, 105, 105, 105, 105,
        106, 106, 106, 106, 107, 107, 107, 107, 108, 108,
        108, 108, 109, 109, 109, 109, 110, 110, 110, 110,
        111, 111, 111, 111, 112, 112, 112, 112, 113, 113,
        113, 113, 114, 114, 114, 114, 115, 115, 115, 115,
        116, 116, 116, 116, 117, 117, 117, 117, 118, 118,
        118, 118, 119, 119, 119, 119, 120, 120, 120, 120,
        121, 121, 121, 121, 122, 122, 122, 122, 48, 48,
        48, 48, 49, 49, 49, 49, 50, 50, 50, 50,
        51, 51, 51, 51, 52, 52, 52, 52, 53, 53,
        53, 53, 54, 54, 54, 54, 55, 55, 55, 55,
        56, 56, 56, 56, 57, 57, 57, 57, 43, 43,
        43, 43, 47, 47, 47, 47,
    ]

    // https://github.com/lemire/fastbase64/blob/master/src/chromiumbase64.c#L35
    @usableFromInline static let e1: [UInt8] = [
        65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
        75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
        85, 86, 87, 88, 89, 90, 97, 98, 99, 100,
        101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
        111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
        121, 122, 48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 43, 47, 65, 66, 67, 68, 69, 70,
        71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
        81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106,
        107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
        117, 118, 119, 120, 121, 122, 48, 49, 50, 51,
        52, 53, 54, 55, 56, 57, 43, 47, 65, 66,
        67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
        77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
        87, 88, 89, 90, 97, 98, 99, 100, 101, 102,
        103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
        113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        43, 47, 65, 66, 67, 68, 69, 70, 71, 72,
        73, 74, 75, 76, 77, 78, 79, 80, 81, 82,
        83, 84, 85, 86, 87, 88, 89, 90, 97, 98,
        99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
        109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
        119, 120, 121, 122, 48, 49, 50, 51, 52, 53,
        54, 55, 56, 57, 43, 47,
    ]

    @usableFromInline static let e2: [UInt8] = [
        65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
        75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
        85, 86, 87, 88, 89, 90, 97, 98, 99, 100,
        101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
        111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
        121, 122, 48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 43, 47, 65, 66, 67, 68, 69, 70,
        71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
        81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106,
        107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
        117, 118, 119, 120, 121, 122, 48, 49, 50, 51,
        52, 53, 54, 55, 56, 57, 43, 47, 65, 66,
        67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
        77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
        87, 88, 89, 90, 97, 98, 99, 100, 101, 102,
        103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
        113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        43, 47, 65, 66, 67, 68, 69, 70, 71, 72,
        73, 74, 75, 76, 77, 78, 79, 80, 81, 82,
        83, 84, 85, 86, 87, 88, 89, 90, 97, 98,
        99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
        109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
        119, 120, 121, 122, 48, 49, 50, 51, 52, 53,
        54, 55, 56, 57, 43, 47,
    ]

}
