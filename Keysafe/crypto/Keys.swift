import Foundation
import BIP32
import secp256k1

enum Error: Swift.Error {
    case failedToGenerateKey
    case hashToCurve(String)
    case unsupportedFormat
    case invalidKey
}

class MasterPrivateKey : ExtendedPrivateKey {
    init(seed: Data) throws {
        let key = try PrivateMasterKeyDerivator().privateKey(seed: seed)
        super.init(key: key)
    }
}

class ExtendedPrivateKey : PrivateKey {
    private let keyForDerivation: ExtendedKeyable
    
    init(key: ExtendedKeyable) {
        self.keyForDerivation = key
        try! super.init(data: keyForDerivation.key)
    }
    func derive(index: UInt32) throws -> ExtendedPrivateKey {
        let childKey = try PrivateChildKeyDerivator().privateKey(privateParentKey: keyForDerivation, index: index)
        return ExtendedPrivateKey(key: childKey)
    }
}

class PrivateKey {
    private let key: secp256k1.Signing.PrivateKey

    init(data: Data) throws {
        try self.key = secp256k1.Signing.PrivateKey(dataRepresentation: data)
    }
    var publicKey: PublicKey {
        PublicKey(key: key.publicKey)
    }
    func multiplyWithMe(pubKey: PublicKey) throws -> PublicKey{
        try PublicKey(key: pubKey.key.multiply(self.key.dataRepresentation.bytes))
        
    }
}

class PublicKey {
    fileprivate let key: secp256k1.Signing.PublicKey
    
    init(key: secp256k1.Signing.PublicKey) {
        self.key = key
    }
    init(data: Data) throws {
        self.key = try secp256k1.Signing.PublicKey(dataRepresentation: data, format: .compressed)
    }
    var dataRepresentation: Data {
        key.dataRepresentation
    }
    func combine(with other: PublicKey) throws -> PublicKey {
        try PublicKey(key: self.key.combine([other.key]))
    }
    func multiply(with other: PrivateKey) throws -> PublicKey {
        try other.multiplyWithMe(pubKey: self)
    }
    func negate() throws -> PublicKey {
        let key = self.key
        guard key.format == .compressed else {
            throw Error.unsupportedFormat
        }
        
        let serialized = key.dataRepresentation
        
        guard let firstByte: UInt8 = switch serialized.first {
        case 0x03: 0x02
        case 0x02: 0x03
        default: throw Error.invalidKey
        } else {
            throw Error.invalidKey
        }
        
        return try PublicKey(key: secp256k1.Signing.PublicKey(
            dataRepresentation: Data([firstByte]) + serialized.dropFirst(),
            format: .compressed
        ))
    }
}
