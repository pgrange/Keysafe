import Foundation
import CryptoKit

struct CryptoService {
    private let domainSeparator = Data("Secp256k1_HashToCurve_Cashu_".utf8)
    private let prefix = Data([0x02])
    
    func blindMessage(message: Data, blindingFactor: PublicKey) throws -> PublicKey {
        let pointOnCurve = try hashToCurve(message: message)
        
        return try pointOnCurve.combine(with: blindingFactor)
    }
    
    func unblindMessage(
        blindedKey: PublicKey,
        blindingFactor: PrivateKey,
        publicKeyOfMint: PublicKey)
    throws -> PublicKey {
        return try blindedKey.combine(
            with: publicKeyOfMint.multiply(with: blindingFactor).negate()
        )
    }
    
    func hashToCurve(message: Data) throws -> PublicKey {
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
    
    private func key_from_hash_and_counter(_ hash: Data, _ counter: UInt32) throws -> PublicKey {
        var counter = counter
        let counterData = withUnsafeBytes(of: &counter) { Data($0) }
        
        let hash = SHA256.hash(data: hash + counterData)
        
        return try PublicKey(data: prefix + hash)
    }
}
