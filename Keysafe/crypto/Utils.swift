import Foundation

enum HexDataError: Swift.Error {
    case invalidLength
    case invalidCharacter
}

extension Data {
    func toHexString() -> String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
    init(hexString: String) throws {
        guard hexString.count % 2 == 0 else {
            throw HexDataError.invalidLength
        }
        
        self.init()
        var index = hexString.startIndex
        
        for _ in 0..<(hexString.count / 2) {
            let nextIndex = hexString.index(index, offsetBy: 2)
            let byteString = hexString[index..<nextIndex]
            
            guard let byte = UInt8(byteString, radix: 16) else {
                throw HexDataError.invalidCharacter
            }
            
            self.append(byte)
            index = nextIndex
        }
    }
}

extension String {
    var bytes: Never {
        fatalError("Do not use `String.bytes` use Data(hexString: String) instead")
    }
}
