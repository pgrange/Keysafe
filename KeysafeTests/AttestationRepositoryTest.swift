import Testing
import Nimble
@testable import Keysafe

import Foundation

struct AttestationRepositoryTests {
    
    private let testSeed = "46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f"
    
    @Test func canStoreABlindedAttestationAndReturnItUnblinded() async throws {
        let cryptoService = CryptoService()
        let rootKey = try MasterPrivateKey(seed: Data(testSeed.bytes))
        let blindingFactorsRepository = BlindingFactorsRepository(rootKey: rootKey)
        let attestationIdsRepository = try AttestationIdsRepository(rootKey: rootKey)
        var attestationRepository = InMemoryAttestationRepository(cryptoService: cryptoService, blindingFactorsRepository: blindingFactorsRepository)
        
        let attestationId: Data = try attestationIdsRepository.getAttestationId(attestationIndex: 0)
        expect("c031acce93e5869ea61125cf64bcdc1f89cffda8efee94657e9609c27accdf1d").to(equal(String(bytes: attestationId)))
        
        let blindingFactor = try blindingFactorsRepository.getBlindingFactor(attestationIndex: 0)
        expect("02686a3077dee57aae98f1544898eebd370f9ef17fa4d0226316cc2f8f856033fe").to(equal(String(bytes: blindingFactor.publicKey.dataRepresentation)))
        
        let blindAttestationId: PublicKey = try cryptoService.blindMessage(message: attestationId, blindingFactor: blindingFactor.publicKey)
        expect("020ade5d0494ee5a42b11b619bd1ac49364c3a91a549b58fa6db91f7a2a4bf2439").to(equal(String(bytes: blindAttestationId.dataRepresentation)))
        
        let blindSignedAttestion = try simulateMintSignature(blindAttestationId: blindAttestationId);
        
        
        let unblinAttestationId = try cryptoService.unblindMessage(blindedKey: blindSignedAttestion, blindingFactor: blindingFactor, publicKeyOfMint: PublicKey(data: Data( "03142715675faf8da1ecc4d51e0b9e539fa0d52fdd96ed60dbe99adb15d6b05ad9".bytes)))
        expect(attestationId).to(equal(unblinAttestationId.dataRepresentation))
        
        
//        attestationRepository.push(attestationIndex: 0, attestation: blindSignedAttestion)
//        let attestation = try attestationRepository.pop()
//        
//        expect(attestation).to(equal(String(bytes: attestationId)))
    }
    
    func simulateMintSignature(blindAttestationId: PublicKey) throws -> PublicKey {
        let blindAttestationId = String(bytes: blindAttestationId.dataRepresentation)
        expect(blindAttestationId).to(equal("020ade5d0494ee5a42b11b619bd1ac49364c3a91a549b58fa6db91f7a2a4bf2439"))
        
        return try PublicKey(data: Data( "03d43aa5a3eb0fae292c4e7649806b21fe849f59316ad6dd89209d9e792235b3b5".bytes))
    }
}

struct InMemoryAttestationRepository {
    private var attestations: [(UInt32, String)] = []
    private let cryptoService: CryptoService
    private let blindingFactorsRepository: BlindingFactorsRepository
    
    init(cryptoService: CryptoService, blindingFactorsRepository: BlindingFactorsRepository) {
        self.cryptoService = cryptoService
        self.blindingFactorsRepository = blindingFactorsRepository
    }
    
    mutating func push(attestationIndex: UInt32, attestation: String) {
        attestations.append((attestationIndex, attestation))
    }
        
    mutating func pop() throws -> String {
        let (index, attestation) = attestations.removeFirst()
        
        let blindedKey = try PublicKey(data: Data(try attestation.bytes))
        let blindingFactor = try blindingFactorsRepository.getBlindingFactor(attestationIndex: index)
        let publicKeyOfMint = try PublicKey(data: Data(try "03142715675faf8da1ecc4d51e0b9e539fa0d52fdd96ed60dbe99adb15d6b05ad9".bytes)) //TODO deal with the real public key of mint
        
        return try String(bytes: cryptoService.unblindMessage(blindedKey: blindedKey, blindingFactor: blindingFactor, publicKeyOfMint: publicKeyOfMint).dataRepresentation)
    }
}
