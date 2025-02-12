import Testing
import Nimble
@testable import Keysafe

import Foundation

struct BlindingFactorsRepositoryTests {
    
    //Mnemonic: siren easy crack very net arm lab mountain click change bike answer pipe hurry design
    //Seed: 46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f
    //
    // Derivation path for blinding factor number 12043:
    // m/1835626100'/1886546294'/0'/4075832'/12043/0
    // Private key: KyMREnFwNjUB5xDLmDZ4Tphxo479hp138tebvGZ56LqaibaLLCU7
    // Public key: 03b64ed09da93b4cd067c8ad29877fda98f594740dcf4c7977f6ad89b3cefc6ec0
    //
    // Derivation path for attestation number number 12043:
    // m/1835626100'/1886546294'/0'/4075832'/12043/1
    // Private key: L37Cfks57eSgJ7y5S3n1aNPs1MWc77uFuH6XYqhtomUBzd1dghFh
    private let testSeed = "46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f"
    
    @Test func canGetBlindingFactorForAttestationIndex() async throws {
        let rootKey = try MasterPrivateKey(seed: Data(hexString: testSeed))
        let repository = BlindingFactorsRepository(rootKey: rootKey)
        
        let blindingFactor: ExtendedPrivateKey = try repository.getBlindingFactor(attestationIndex: 12043)
        
        // We can not expose the private key material of the blinding factor
        // so we assert only on the public key part of the blinding factor
        let expectedPublicKeyForBlindingFactor  = "03b64ed09da93b4cd067c8ad29877fda98f594740dcf4c7977f6ad89b3cefc6ec0"
        expect(blindingFactor.publicKey.dataRepresentation.toHexString()).to(equal(expectedPublicKeyForBlindingFactor))
    }
}
