//
//  CryptoService.swift
//  Keysafe
//
//  Created by pascal on 26/11/2024.
//

import Foundation
import secp256k1

enum Error: Swift.Error {
    case failedToGenerateKey
    case hashToCurve(String)
    case unsupportedFormat
    case invalidKey
}

struct CryptoService {
    private let domainSeparator = Data("Secp256k1_HashToCurve_Cashu_".utf8)
    private let prefix = Data([0x02])
    
    func blindMessage(message: Data, blindingFactor: secp256k1.Signing.PublicKey) throws -> secp256k1.Signing.PublicKey {
        let pointOnCurve = try hashToCurve(message: message)
        
        return try pointOnCurve.combine([blindingFactor])
    }
    
    func unblindMessage(
        blindedKey: secp256k1.Signing.PublicKey,
        blindingFactor: secp256k1.Signing.PrivateKey,
        publicKeyOfMint: secp256k1.Signing.PublicKey)
    throws -> secp256k1.Signing.PublicKey {
        let blindingFactorMulPublicKeyOfMint = try publicKeyOfMint.multiply(blindingFactor.dataRepresentation.bytes)
        return try blindedKey.combine([negatePublicKey(key: blindingFactorMulPublicKeyOfMint)])
    }
    
    func hashToCurve(message: Data) throws -> secp256k1.Signing.PublicKey {
        let hash = Data(SHA256.hash(data: domainSeparator + message))
        var counter: UInt32 = 0
        while counter < UInt32(pow(2.0, 16)) {
            if let key = try? key_from_hash_and_counter(hash, counter) {
                return key
            } else {
                counter += 1
            }
        }
        throw Error.failedToGenerateKey
    }
    
    private func key_from_hash_and_counter(_ hash: Data, _ counter: UInt32) throws -> secp256k1.Signing.PublicKey {
        var counter = counter
        let counterData = withUnsafeBytes(of: &counter) { Data($0) }
        
        let hash = SHA256.hash(data: hash + counterData)
        
        return try secp256k1.Signing.PublicKey(dataRepresentation: prefix + hash, format: .compressed)
    }
    
    private func negatePublicKey(key: secp256k1.Signing.PublicKey) throws -> secp256k1.Signing.PublicKey {
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
        
        return try secp256k1.Signing.PublicKey(
            dataRepresentation: Data([firstByte]) + serialized.dropFirst(),
            format: .compressed
        )
    }
}
