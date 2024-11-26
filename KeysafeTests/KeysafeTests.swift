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
    
    @Test func canBlindAMessage() async throws {
        try assert_blind_message(
            message: "d341ee4871f1f889041e63cf0d3823c713eea6aff01e80f1719f08f9e5be98f6",
            blindingFactor: "99fce58439fc37412ab3468b73db0569322588f62fb3a49182d67e23d877824a",
            expected: "033b1a9737a40cc3fd9b6af4b723632b76a67a36782596304612a6c2bfb5197e6d"
        )
        try assert_blind_message(
            message: "f1aaf16c2239746f369572c0784d9dd3d032d952c2d992175873fb58fae31a60",
            blindingFactor: "f78476ea7cc9ade20f9e05e58a804cf19533f03ea805ece5fee88c8e2874ba50",
            expected: "029bdf2d716ee366eddf599ba252786c1033f47e230248a4612a5670ab931f1763"
        )
    }
    
    private func assertHashToCurve(
        message: String,
        expectedPointOnCurve: String
    ) throws {
        let result = try CryptoService().hashToCurve(message: Data(try message.bytes))
        expect(result.stringRepresentation).to(equal(expectedPointOnCurve))
    }
    
    private func assert_blind_message(
        message: String,
        blindingFactor: String,
        expected: String
    ) throws {
        let message = Data(try message.bytes)
        let blindingFactor = try secp256k1.Signing.PrivateKey(dataRepresentation: Data(try blindingFactor.bytes))
        
        let result = try CryptoService().blindMessage(message: message, blindingFactor: blindingFactor.publicKey)
        
        expect(result.stringRepresentation).to(equal(expected))
    }
}

enum Error: Swift.Error {
    case failedToGenerateKey
    case hashToCurve(String)
}

struct CryptoService {
    private let domainSeparator = Data("Secp256k1_HashToCurve_Cashu_".utf8)
    
    func blindMessage(message: Data, blindingFactor: secp256k1.Signing.PublicKey) throws -> secp256k1.Signing.PublicKey {
        let pointOnCurve = try hashToCurve(message: message)
        
        return try pointOnCurve.combine([blindingFactor])
    }
    
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
