import Testing
import Nimble
@testable import Keysafe

import Foundation
import secp256k1
import CryptoKit

struct AttestationServiceTests {
    
    //Mnemonic: siren easy crack very net arm lab mountain click change bike answer pipe hurry design
    //Seed: 46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f
    //
    // Derivation path for blinding factor number 12043:
    // m/1835626100'/1886546294'/0'/4075832'/12043/0
    // Private key: KyMREnFwNjUB5xDLmDZ4Tphxo479hp138tebvGZ56LqaibaLLCU7
    // Public key: [03]b64ed09da93b4cd067c8ad29877fda98f594740dcf4c7977f6ad89b3cefc6ec0
    //
    // Derivation path for attestation number number 12043:
    // m/1835626100'/1886546294'/0'/4075832'/12043/1
    // Private key: L37Cfks57eSgJ7y5S3n1aNPs1MWc77uFuH6XYqhtomUBzd1dghFh
    // Public key: [02]8f5242d73ce2c5cf7de8b6df8c039dab02a96a97820b60b9c5c13a9d61770db1
    //
    //
    
    private let testSeed = "46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f"
    
    @Test func canPrepareAnAttestationRequestWithCorrectIdentity() async throws {
        let rootKey = try MasterPrivateKey(seed: Data(testSeed.bytes))
        let identityRepository = IdentityRepository(rootKey: rootKey)
        let blindingFactorsRepository = BlindingFactorsRepository(rootKey: rootKey)
        let attestationIdsRepository = try AttestationIdsRepository(rootKey: rootKey)
        let cryptoService = CryptoService()
        let attestationService = AttestationService(identityRepository: identityRepository,
                                                    blindingFactorsRepository: blindingFactorsRepository,
                                                    attestationIdsRepository:  attestationIdsRepository,
                                                    cryptoService: cryptoService)
        
        let attestationRequest = try attestationService.prepareAttestationRequest(for: 10, startingAt: 0)
        
        let expectedPublicKey = "02b8ae339752f1dc85951d103fb5b38d4e44a8c40546b8705c2776bbffa7390205"
        expect(attestationRequest.header.publicKey).to(equal(expectedPublicKey))
    }
    
    @Test func canPrepareAnAttestationRequestWithCorrectExpirationTime() async throws {
        let rootKey = try MasterPrivateKey(seed: Data(testSeed.bytes))
        let identityRepository = IdentityRepository(rootKey: rootKey)
        let blindingFactorsRepository = BlindingFactorsRepository(rootKey: rootKey)
        let attestationIdsRepository = try AttestationIdsRepository(rootKey: rootKey)
        let cryptoService = CryptoService()
        let attestationService = AttestationService(identityRepository: identityRepository,
                                                    blindingFactorsRepository: blindingFactorsRepository,
                                                    attestationIdsRepository:  attestationIdsRepository,
                                                    cryptoService: cryptoService)
        
        let attestationRequest = try attestationService.prepareAttestationRequest(for: 10, startingAt: 0, now: Date(timeIntervalSince1970: 10_000))
        
        expect(attestationRequest.header.expiry).to(equal("13600")) //1 hour later
    }
    
    @Test func canPrepareAnAttestationRequestWithCorrectOutputs() async throws {
        let rootKey = try MasterPrivateKey(seed: Data(testSeed.bytes))
        let identityRepository = IdentityRepository(rootKey: rootKey)
        let blindingFactorsRepository = BlindingFactorsRepository(rootKey: rootKey)
        let attestationIdsRepository = try AttestationIdsRepository(rootKey: rootKey)
        let cryptoService = CryptoService()
        let attestationService = AttestationService(identityRepository: identityRepository,
                                                    blindingFactorsRepository: blindingFactorsRepository,
                                                    attestationIdsRepository:  attestationIdsRepository,
                                                    cryptoService: cryptoService)
        
        let attestationRequest = try attestationService.prepareAttestationRequest(for: 10, startingAt: 12043)
        
        expect(attestationRequest.outputs.count).to(equal(10))
        /// See ``CryptoServiceTests.canBlindAMessage``
        expect(attestationRequest.outputs[0]).to(equal("026278c520a535e87147c687ecb67aa989ce7d34e68ffdc11282ca9fa38190e668"))
        expect(attestationRequest.outputs[1]).to(equal("020981efe0d09d90523a1e168c6d6960c7a534deb75941c926088b297ec603ce6c"))
        expect(attestationRequest.outputs[2]).to(equal("03551efe7c884605e0612f8c77f07bf0e132519f3d9c3a31a25bf914be89f43a94"))
        expect(attestationRequest.outputs[3]).to(equal("03e2eff8541b4ffea8aaa799b324b51ea797bbc27592a7c74d81c93f7eb019968d"))
        expect(attestationRequest.outputs[4]).to(equal("03070eb3e346ed1ef44f05d7dc9f11b6d8d616211fd2b3d6779a51b16e40aef2d5"))
        expect(attestationRequest.outputs[5]).to(equal("022881b2fb0aad0f4816b99aa1ed368184939b777ce68c048fed72d4e6e8273db3"))
        expect(attestationRequest.outputs[6]).to(equal("025354268520d32a4539c61767510dcb0c93d446dcfdaf75d8b1198af8b2d2e8d1"))
        expect(attestationRequest.outputs[7]).to(equal("025c4d283f80bef78faa08a5ed67daaf9f7c28cac828ec96594e0fd1d38b22c2a5"))
        expect(attestationRequest.outputs[8]).to(equal("02cf3893a5fb1b13799d26317f0f48e4fe847d36daa596cd86c3f7e4c6d9ce9cd5"))
        expect(attestationRequest.outputs[9]).to(equal("03a4843a10610822ed859ce4b2fc38ea537d2f8726af65a5003bd0945c0a7a96cc"))
    }
    
    @Test func canPrepareAnAttestationRequestWithValidSignature() async throws {
        let rootKey = try MasterPrivateKey(seed: Data(testSeed.bytes))
        let identityRepository = IdentityRepository(rootKey: rootKey)
        let blindingFactorsRepository = BlindingFactorsRepository(rootKey: rootKey)
        let attestationIdsRepository = try AttestationIdsRepository(rootKey: rootKey)
        let cryptoService = CryptoService()
        let attestationService = AttestationService(identityRepository: identityRepository,
                                                    blindingFactorsRepository: blindingFactorsRepository,
                                                    attestationIdsRepository:  attestationIdsRepository,
                                                    cryptoService: cryptoService)
        
        let attestationRequest = try attestationService.prepareAttestationRequest(for: 10,
                                                                                  startingAt: 12043)
        
        let toDigest = attestationRequest.header.uid + attestationRequest.header.expiry + attestationRequest.outputs.joined()
        let digest = Data(SHA256.hash(data: Data(toDigest.utf8)))

        let signature = try secp256k1.Signing.ECDSASignature(dataRepresentation: Data(attestationRequest.signature.bytes))
        
        let publicKey = try secp256k1.Signing.PublicKey(dataRepresentation: identityRepository.getIdentity().publicKey.dataRepresentation,
                                                        format: .compressed)

        expect(publicKey.isValidSignature(signature, for: digest)).to(beTrue())
    }
}
