import Foundation
import CryptoKit

struct AttestationService {
    
    private let identityRepository: IdentityRepository
    private let blindingFactorsRepository: BlindingFactorsRepository
    private let attestationIdsRepository: AttestationIdsRepository
    private let cryptoService: CryptoService
    
    init(identityRepository: IdentityRepository,
         blindingFactorsRepository: BlindingFactorsRepository,
         attestationIdsRepository: AttestationIdsRepository,
         cryptoService: CryptoService) {
        self.identityRepository = identityRepository
        self.blindingFactorsRepository = blindingFactorsRepository
        self.attestationIdsRepository = attestationIdsRepository
        self.cryptoService = cryptoService
    }

    func prepareAttestationRequest(for amount: Int, startingAt firstAttestationIndex: UInt32, now: Date = Date()) throws -> AttestationRequest {
        let identity = try identityRepository.getIdentity()
        let publicKey = identity.publicKey.dataRepresentation.toHexString()
        let oneHour: TimeInterval = 60 * 60
        let uid = try generateSecureRandomUID()
        let expiry = String(Int(now.addingTimeInterval(oneHour).timeIntervalSince1970))
    
        var outputs: [String] = []
        for attestationIndex: UInt32 in firstAttestationIndex..<firstAttestationIndex + UInt32(amount) {
            let blindingFactor = try blindingFactorsRepository.getBlindingFactor(attestationIndex: attestationIndex)
            let attestationId = try attestationIdsRepository.getAttestationId(attestationIndex: attestationIndex)
            let output = try cryptoService.blindMessage(message: Data(try attestationId.bytes), blindingFactor: blindingFactor.publicKey).dataRepresentation.toHexString()
            outputs.append(output)
        }
        
        let digest = SHA256.hash(data: Data((uid + expiry + outputs.joined()).utf8))
        let signature = try identity.sign(digest: Data(digest))
        
        return AttestationRequest(for: amount, publicKey: publicKey, uid: uid, expiry: expiry, outputs: outputs, signature: String(bytes: signature))
    }

    enum SecureRandomError: Swift.Error {
        case generationFailed(status: Int32)
    }

    private func generateSecureRandomUID() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw SecureRandomError.generationFailed(status: status)
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}

struct AttestationRequest {
    let header: AttestationRequestHeader
    let outputs: [String]
    let signature: String
    
    init(for amount: Int, publicKey: String, uid: String, expiry: String, outputs: [String], signature: String) {
        self.header = AttestationRequestHeader(publicKey: publicKey, uid: uid, expiry: expiry)
        self.outputs = outputs
        self.signature = signature
    }
}

struct AttestationRequestHeader {
    let publicKey: String
    let uid: String
    let expiry: String
}
