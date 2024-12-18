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


struct AttestationIdsRepositoryTests {
    
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
    
    @Test func canGetAttestationIdForAttestationIndex() async throws {
        let repository = try AttestationIdsRepository(seed: Data(testSeed.bytes))
        
        let attestationId = try repository.getAttestationId(attestationIndex: 12043)
        
        let expectedAttestationId = try wifToPrivateKey(wif: "L37Cfks57eSgJ7y5S3n1aNPs1MWc77uFuH6XYqhtomUBzd1dghFh")
        expect(attestationId.stringRepresentation).to(equal(expectedAttestationId.stringRepresentation))
    }
}
