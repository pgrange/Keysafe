import Testing
import Nimble
@testable import Keysafe

import Foundation

struct IdentityRepositoryTests {
    
    //Mnemonic: siren easy crack very net arm lab mountain click change bike answer pipe hurry design
    //Seed: 46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f
    //
    // Derivation path identity key:
    // m/1635087464'/0'/0
    // Private key: L3vWtAq3HZHQGD38Vh2VfHSE88qUWpKRVo2MUr83h1Jz6ks53vvy
    // Public key: 02b8ae339752f1dc85951d103fb5b38d4e44a8c40546b8705c2776bbffa7390205
    
    /*
     Derivation path:
     m / purpose' / account' / index
     
     With:
     * m: the root key
     * purpose: auth / 0x61757468 / 1635087464 (See Bip-43)
     * account: 0
     * index: 0
     */

    private let testSeed = "46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f"
    
    @Test func canGetIdentity() async throws {
        let rootKey = try MasterPrivateKey(seed: Data(hexString: testSeed))
        let repository = IdentityRepository(rootKey: rootKey)
        
        let identity: PrivateKey = try repository.getIdentity()
        
        // We can not expose the private key material of a private key
        // so we assert only on the public key part of the identity
        let expectedPublicKeyForIdentity  = "02b8ae339752f1dc85951d103fb5b38d4e44a8c40546b8705c2776bbffa7390205"
        expect(identity.publicKey.dataRepresentation.toHexString()).to(equal(expectedPublicKeyForIdentity))
    }
}
