import Testing
import Nimble
@testable import Keysafe

import Foundation

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
    // Public key: [02]8f5242d73ce2c5cf7de8b6df8c039dab02a96a97820b60b9c5c13a9d61770db1
    private let testSeed = "46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f"
    
    @Test func canGetAttestationIdForAttestationIndex() async throws {
        let rootKey = try MasterPrivateKey(seed: Data(hexString: testSeed))
        let repository = try AttestationIdsRepository(rootKey: rootKey)
        
        try assertAttestationId(
            repository,
            attestationIndex: 12043,
            expectedAttestationId: "8f5242d73ce2c5cf7de8b6df8c039dab02a96a97820b60b9c5c13a9d61770db1"
        )
        try assertAttestationId(
            repository,
            attestationIndex: 0,
            expectedAttestationId: "c031acce93e5869ea61125cf64bcdc1f89cffda8efee94657e9609c27accdf1d"
        )
    }
    
    fileprivate func assertAttestationId(_ repository: AttestationIdsRepository, attestationIndex: UInt32, expectedAttestationId: String) throws {
        let attestationId = try repository.getAttestationId(attestationIndex: attestationIndex)
        
        expect(attestationId.toHexString()).to(equal(expectedAttestationId))
    }
}
