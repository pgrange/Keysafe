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
import secp256k1
import Base58Swift


struct BlindingFactorsRepositoryTests {
    
    //Mnemonic: siren easy crack very net arm lab mountain click change bike answer pipe hurry design
    //Seed: 46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f
    //
    // Derivation path for blinding factor number 12043:
    // m/1835626100'/1886546294'/0'/4075832'/12043/0
    // Private key: KyMREnFwNjUB5xDLmDZ4Tphxo479hp138tebvGZ56LqaibaLLCU7
    //
    // Derivation path for attestation number number 12043:
    // m/1835626100'/1886546294'/0'/4075832'/12043/1
    // Private key: L37Cfks57eSgJ7y5S3n1aNPs1MWc77uFuH6XYqhtomUBzd1dghFh
    private let testSeed = "46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f"
    
    @Test func canGetBlindingFactorForAttestationIndex() async throws {
        let repository = try BlindingFactorsRepository(seed: Data(testSeed.bytes))
        
        let blindingFactor = try repository.getBlindingFactor(attestationIndex: 12043)
        
        let expectedBlindingFactor = try wifToPrivateKey(wif: "KyMREnFwNjUB5xDLmDZ4Tphxo479hp138tebvGZ56LqaibaLLCU7")
        expect(blindingFactor.stringRepresentation).to(equal(expectedBlindingFactor.stringRepresentation))
    }
}

enum WIFError: Swift.Error {
    case invalidWIF
    case invalidChecksum
}

func wifToPrivateKey(wif: String) throws -> secp256k1.Signing.PrivateKey {
    // Décodage Base58Check
    guard let decoded = Base58.base58CheckDecode(wif) else {
        throw WIFError.invalidWIF
    }
    
    // Vérification de la longueur minimale (préfixe + clé + checksum)
    guard decoded.count >= 34 else {
        throw WIFError.invalidWIF
    }
    
    // Extraire le payload et le checksum
    let payload = decoded
    
    // Vérifier le préfixe
    guard payload.first == 0x80 else {
        throw WIFError.invalidWIF
    }
    
    // Vérifier si la clé est compressée (dernier octet == 0x01)
    let isCompressed = payload.count == 34 && payload.last == 0x01
    
    // Extraire la clé privée brute (32 octets)
    let keyData = isCompressed ? payload.dropFirst().dropLast() : payload.dropFirst()
    print(keyData.count)
    guard keyData.count == 32 else {
        throw WIFError.invalidWIF
    }
    
    return try secp256k1.Signing.PrivateKey(dataRepresentation: keyData)
}
