import Testing
import Nimble
@testable import Keysafe

import Foundation

struct CryptoServiceTests {
    
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
    
    @Test func canUnblindAMessage() async throws {
        try assert_unblind_message(
            blindedMessage: "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            blindingFactor: "0000000000000000000000000000000000000000000000000000000000000001",
            publicKeyOfMint: "020000000000000000000000000000000000000000000000000000000000000001",
            expected: "03c724d7e6a5443b39ac8acf11f40420adc4f99a02e7cc1b57703d9391f6d129cd"
        )
    }
    
    private func assertHashToCurve(
        message: String,
        expectedPointOnCurve: String
    ) throws {
        let result = try CryptoService().hashToCurve(message: Data(try message.bytes))
        expect(String(bytes: result.dataRepresentation)).to(equal(expectedPointOnCurve))
    }
    
    private func assert_blind_message(
        message: String,
        blindingFactor: String,
        expected: String
    ) throws {
        let message = Data(try message.bytes)
        let blindingFactor : PublicKey = try PrivateKey(data: Data(try blindingFactor.bytes)).publicKey
        
        let result = try CryptoService().blindMessage(message: message, blindingFactor: blindingFactor)
        
        expect(String(bytes: result.dataRepresentation)).to(equal(expected))
    }
    
    private func assert_unblind_message(
        blindedMessage: String,
        blindingFactor: String,
        publicKeyOfMint: String,
        expected: String
    ) throws {
        let blindedMessage = try PublicKey(data: Data(try blindedMessage.bytes))
        let blindingFactor = try PrivateKey(data: Data(try blindingFactor.bytes))
        let publicKeyOfMint = try PublicKey(data: Data(try publicKeyOfMint.bytes))
        
        let result = try CryptoService().unblindMessage(
            blindedKey: blindedMessage,
            blindingFactor: blindingFactor,
            publicKeyOfMint: publicKeyOfMint)
        
        expect(String(bytes: result.dataRepresentation)).to(equal(expected))
    }
}
