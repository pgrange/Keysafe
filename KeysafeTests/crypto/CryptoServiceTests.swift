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
        //See nut-00 test vectors https://github.com/cashubtc/nuts/blob/main/tests/00-tests.md
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
    @Test func canBlindAMessageWithSpecificTestVector() async throws {
        //Mnemonic: siren easy crack very net arm lab mountain click change bike answer pipe hurry design
        //Seed: 46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f
        //
        // Derivation path for blinding factor number n:
        // m/1835626100'/1886546294'/0'/4075832'/n/0
        // Derivation path for attestation number number n:
        // m/1835626100'/1886546294'/0'/4075832'/n/1
        // See https://iancoleman.io/bip39/
        var assertionForIndex: [Int: BlindMessageAssertion] = [:]
        assertionForIndex[0] =        BlindMessageAssertion(
            message: "03c031acce93e5869ea61125cf64bcdc1f89cffda8efee94657e9609c27accdf1d",
            blindingFactor: try wifToHex(wifKey: "L1EEg8mBPRGaTou8ru8yMF5sRuKRk7e7aBvSCEpamDbAB8SkLF5z"),
            expected: "03a74728e33ba5b41d561ccf01f1cfa4055d0c0a4491c48eed28efd3936aac03fc")
        assertionForIndex[1] =        BlindMessageAssertion(
            message: "027ef5c12a828f5e32ff3c9b896d6a3311adc6ef63221d77e41171fcb0e9f755d5",
            blindingFactor: try wifToHex(wifKey: "L1rrA8FvjuDUdEbnBHguraH3gMXc61okJBpGzi5NcdV7rJyPGKMG"),
            expected: "029621c1cefbf6ca0b781e2bfe6be4f23773fa8a76ec2b0e90dabcb188b4f22e83")
        assertionForIndex[12043] =        BlindMessageAssertion(
            message: "8f5242d73ce2c5cf7de8b6df8c039dab02a96a97820b60b9c5c13a9d61770db1",
            blindingFactor: try wifToHex(wifKey: "KyMREnFwNjUB5xDLmDZ4Tphxo479hp138tebvGZ56LqaibaLLCU7"),
            expected: "026278c520a535e87147c687ecb67aa989ce7d34e68ffdc11282ca9fa38190e668")
        assertionForIndex[12044] = BlindMessageAssertion(
            message: "f293106dad8fb9bc50adbfe38c52a83e483fbd1d0f8c5181aa8b5431c9ecb73f",
            blindingFactor: try wifToHex(wifKey: "L3jZcF2DGxNppLrTMVS4bZPpfvE9Mf191bsEeLrKs7g5Ukvju4Ln"),
            expected: "020981efe0d09d90523a1e168c6d6960c7a534deb75941c926088b297ec603ce6c")
        assertionForIndex[12045] = BlindMessageAssertion(
            message: "ed9b00913de9d761e0091ac03e183fd56cab2e80d109ca228bd25b5b86148dc2",
            blindingFactor: try wifToHex(wifKey: "L4ShZRt3NyvutdnK4BVBZZA6gybnVBHn92E8dWz23bbshBxhV6g7"),
            expected: "03551efe7c884605e0612f8c77f07bf0e132519f3d9c3a31a25bf914be89f43a94")
        assertionForIndex[12046] = BlindMessageAssertion(
            message: "89a18a2a3c718bc201061f276f2da95c3c3fb0245bdd3b9957f30e7db1daf032",
            blindingFactor: try wifToHex(wifKey: "KxwzJdnTcoBoP6L3UBqMmnb2KDApTNmiSEtkZmtyUw5WPMw9XkUk"),
            expected: "03e2eff8541b4ffea8aaa799b324b51ea797bbc27592a7c74d81c93f7eb019968d")
        assertionForIndex[12047] = BlindMessageAssertion(
            message: "3eb99ea9949f7c14a870eb4c8228dc712173a40baa82b7e99bdda554168a2452",
            blindingFactor: try wifToHex(wifKey: "L5k8tpGtrdtnkwHKmtRVgZu3XXuN2NnugFBHXayTfBKmKnFRrryR"),
            expected: "03070eb3e346ed1ef44f05d7dc9f11b6d8d616211fd2b3d6779a51b16e40aef2d5")
        assertionForIndex[12048] = BlindMessageAssertion(
            message: "0c6557731581444566ed2d2906063a48f7a6df2924eef51ff6cd84ab6f674ba6",
            blindingFactor: try wifToHex(wifKey: "L3eEpr7NZ8mAdWK2QCsPiFvFk6VrGEwyqxSk42WrWz563KWKRBM5"),
            expected: "022881b2fb0aad0f4816b99aa1ed368184939b777ce68c048fed72d4e6e8273db3")
        assertionForIndex[12049] = BlindMessageAssertion(
            message: "1ed20c413cefe9c64243eec4b4ae1652957de1df745f7e1f12105c7e2933bc98",
            blindingFactor: try wifToHex(wifKey: "L2sdXk8wNHV2nn6WPaxKsrmv3JVKAmpTe7nPseFocFaY2rrjwtJj"),
            expected: "025354268520d32a4539c61767510dcb0c93d446dcfdaf75d8b1198af8b2d2e8d1")
        assertionForIndex[12050] = BlindMessageAssertion(
            message: "94404e55ededcb34a3b6e183b813605eb86c5a4e268df81aae173f861dfc4bb6",
            blindingFactor: try wifToHex(wifKey: "KyzCXF1jr5YiqbCiKUsoTkbQ37woChYC3dswQLSVkjbavChJKJr3"),
            expected: "025c4d283f80bef78faa08a5ed67daaf9f7c28cac828ec96594e0fd1d38b22c2a5")
        assertionForIndex[12051] = BlindMessageAssertion(
            message: "769cc04c196bcf46841912e0e6f6361b568d67070686c3444484330cb1eca8fa",
            blindingFactor: try wifToHex(wifKey: "KyqkXiQDwSPY9FwKwTSnLT1ogMH7CGjazz9AhgTD1F4H1emk4EcW"),
            expected: "02cf3893a5fb1b13799d26317f0f48e4fe847d36daa596cd86c3f7e4c6d9ce9cd5")
        assertionForIndex[12052] = BlindMessageAssertion(
            message: "c893998c34ac73782a2b30364988be9c45a613c40df7758b5fd37c99c74df6ba",
            blindingFactor: try wifToHex(wifKey: "L2RYoC9ArKAXjKrNb5EcX2vRmbDU2woS1K2XYKA3umzV5NQmTm2e"),
            expected: "03a4843a10610822ed859ce4b2fc38ea537d2f8726af65a5003bd0945c0a7a96cc")
        
        for (_, assertion) in assertionForIndex {
            try assert_blind_message(
                message: assertion.message,
                blindingFactor: assertion.blindingFactor,
                expected: assertion.expected
            )
        }
    }
    
    struct BlindMessageAssertion {
        let message: String
        let blindingFactor: String
        let expected: String
    }
    
    @Test func canUnblindAMessage() async throws {
        try assert_unblind_message(
            blindedMessage: "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            blindingFactor: "0000000000000000000000000000000000000000000000000000000000000001",
            publicKeyOfMint: "020000000000000000000000000000000000000000000000000000000000000001",
            expected: "03c724d7e6a5443b39ac8acf11f40420adc4f99a02e7cc1b57703d9391f6d129cd"
        )
        //TODO
//        try assert_unblind_message(
//            blindedMessage: "03a74728e33ba5b41d561ccf01f1cfa4055d0c0a4491c48eed28efd3936aac03fc",
//            blindingFactor: try wifToHex(wifKey: "L1EEg8mBPRGaTou8ru8yMF5sRuKRk7e7aBvSCEpamDbAB8SkLF5z"),
//            publicKeyOfMint: "03142715675faf8da1ecc4d51e0b9e539fa0d52fdd96ed60dbe99adb15d6b05ad9",
//            expected: "c031acce93e5869ea61125cf64bcdc1f89cffda8efee94657e9609c27accdf1d"
//        )
    }
    
    private func assertHashToCurve(
        message: String,
        expectedPointOnCurve: String
    ) throws {
        let result = try CryptoService().hashToCurve(message: Data(hexString: message))
        expect(result.dataRepresentation.toHexString()).to(equal(expectedPointOnCurve))
    }
    
    private func assert_blind_message(
        message: String,
        blindingFactor: String,
        expected: String
    ) throws {
        let message = try Data(hexString: message)
        let blindingFactor : PublicKey = try PrivateKey(data: Data(hexString: blindingFactor)).publicKey
        
        let result = try CryptoService().blindMessage(message: message, blindingFactor: blindingFactor)
        
        expect(result.dataRepresentation.toHexString()).to(equal(expected))
    }
    
    private func assert_unblind_message(
        blindedMessage: String,
        blindingFactor: String,
        publicKeyOfMint: String,
        expected: String
    ) throws {
        let blindedMessage  = try PublicKey(data: Data(hexString: blindedMessage))
        let blindingFactor  = try PrivateKey(data: Data(hexString: blindingFactor))
        let publicKeyOfMint = try PublicKey(data: Data(hexString: publicKeyOfMint))
        
        let result = try CryptoService().unblindMessage(
            blindedKey: blindedMessage,
            blindingFactor: blindingFactor,
            publicKeyOfMint: publicKeyOfMint)
        
        expect(result.dataRepresentation.toHexString()).to(equal(expected))
    }
}

import Base58Swift

enum WIFConversionError: Swift.Error {
    case base58DecodeFailed
    case invalidKeyLength
}

func wifToHex(wifKey: String) throws -> String {
    guard let decodedData = Base58.base58CheckDecode(wifKey) else {
        throw WIFConversionError.base58DecodeFailed
    }
    
    var keyData = decodedData.dropFirst() // Remove prefix (0x80)
    
    if keyData.count == 33 && keyData.last == 0x01 { // Compressed key
        keyData = keyData.dropLast() // Remove suffix (0x01)
    }
    
    guard keyData.count == 32 else {
        throw WIFConversionError.invalidKeyLength
    }
    
    return keyData.map { String(format: "%02x", $0) }.joined()
}
