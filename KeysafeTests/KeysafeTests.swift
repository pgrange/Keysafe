//
//  KeysafeTests.swift
//  KeysafeTests
//
//  Created by pascal on 25/11/2024.
//

import Testing
import Nimble
@testable import Keysafe

import Foundation
import CryptoKit
import secp256k1

extension Data {
    func toHex() -> String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
}

extension secp256k1.Signing.PublicKey {
    var stringRepresentation:String {
        return String(bytes: self.dataRepresentation)
    }
}

struct KeysafeTests {

    @Test func canProjectMessageOnTheCurve() async throws {
        try assertHashToCurve(
            message: "0000000000000000000000000000000000000000000000000000000000000000",
            expectedPointOnCurve: "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725"
        )
        
        try assertHashToCurve(
            message: "0000000000000000000000000000000000000000000000000000000000000001",
            expectedPointOnCurve: "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf"
        )
        
        try assertHashToCurve(
            message: "0000000000000000000000000000000000000000000000000000000000000002",
            expectedPointOnCurve: "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f"
        )
    }
    
    private func assertHashToCurve(
        message: String,
        expectedPointOnCurve: String
    ) throws {
        let result = try CryptoService().hashToCurve(message: Data(try message.bytes))
        expect(result.stringRepresentation).to(equal(expectedPointOnCurve))
    }
}

enum Error: Swift.Error {
    case failedToGenerateKey
    case hashToCurve(String)
}

class CryptoService {
    private let domainSeparator = Data("Secp256k1_HashToCurve_Cashu_".utf8)

    func hashToCurve(message: Data) throws -> secp256k1.Signing.PublicKey {
        let data = domainSeparator + message
        let hash = Data(SHA256.hash(data: data))
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

        let to_hash = hash + counterData
        let hash = SHA256.hash(data: to_hash)
        let prefix = Data([0x02])
        let combined = prefix + hash
        
        return try secp256k1.Signing.PublicKey(dataRepresentation: combined, format: .compressed)
    }
}
