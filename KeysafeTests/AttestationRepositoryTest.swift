import Testing
import Nimble
@testable import Keysafe

import Foundation

struct AttestationRepositoryTests {
    
    private let testSeed = "46f6035476980efb390749d3ad278e6166e2003d8cab716063746d74f9f18148c13caacfe3bf33d5934bbd42848fcd81b9aacbeab19e81482af4108b19c6065f"
    
    @Test func canStoreABlindedAttestationAndReturnItUnblinded() async throws {
        let cryptoService = CryptoService()
        let rootKey = try MasterPrivateKey(seed: Data(hexString: testSeed))
        let blindingFactorsRepository = BlindingFactorsRepository(rootKey: rootKey)
        var attestationRepository = InMemoryAttestationRepository(cryptoService: cryptoService, blindingFactorsRepository: blindingFactorsRepository)
        
        let blindSignedAttestation = try Data(hexString: "03d43aa5a3eb0fae292c4e7649806b21fe849f59316ad6dd89209d9e792235b3b5")
        
        attestationRepository.push(attestationIndex: 0, blindSignedAttestation: blindSignedAttestation)
        let attestation = try attestationRepository.pop()
        
        expect(attestation.toHexString()).to(equal("024aac7d9c17020da7a926f23f32661484663560f8d871800cc51ec9d42d9af177"))
    }
}

struct InMemoryAttestationRepository {
    private var blindSignedAttestations: [(UInt32, Data)] = []
    private let cryptoService: CryptoService
    private let blindingFactorsRepository: BlindingFactorsRepository
    
    init(cryptoService: CryptoService, blindingFactorsRepository: BlindingFactorsRepository) {
        self.cryptoService = cryptoService
        self.blindingFactorsRepository = blindingFactorsRepository
    }
    
    mutating func push(attestationIndex: UInt32, blindSignedAttestation: Data) {
        blindSignedAttestations.append((attestationIndex, blindSignedAttestation))
    }
        
    mutating func pop() throws -> Data {
        let (index, blindSignedAttestation) = blindSignedAttestations.removeFirst()
        
        let blindedKey = try PublicKey(data: blindSignedAttestation)
        let blindingFactor = try blindingFactorsRepository.getBlindingFactor(attestationIndex: index)
        //TODO deal with the real public key of mint
        let publicKeyOfMint = try PublicKey(data: Data(hexString: "03142715675faf8da1ecc4d51e0b9e539fa0d52fdd96ed60dbe99adb15d6b05ad9"))
        
        return try cryptoService.unblindMessage(
            blindedKey: blindedKey,
            blindingFactor: blindingFactor,
            publicKeyOfMint: publicKeyOfMint
        ).dataRepresentation
    }
}
