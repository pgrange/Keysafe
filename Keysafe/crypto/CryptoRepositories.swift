import Foundation

private let BLINDING_FACTOR: UInt32 = 0
private let ATTESTATION_ID: UInt32 = 1

class BlindingFactorsRepository {
    private let repositories: DerivationHelper
    
    init(rootKey: ExtendedPrivateKey) {
        self.repositories = DerivationHelper(rootKey: rootKey)
    }
    
    func getBlindingFactor(attestationIndex: UInt32) throws -> ExtendedPrivateKey {
        return try repositories.derive(attestationIndex: attestationIndex, objectType: BLINDING_FACTOR)
    }
}

class AttestationIdsRepository {
    private let rootKey: ExtendedPrivateKey
    private let repositories: DerivationHelper
    
    init(rootKey: ExtendedPrivateKey) throws {
        self.rootKey = rootKey
        self.repositories = DerivationHelper(rootKey: rootKey)
    }
    
    // See https://github.com/cashubtc/nuts/blob/main/00.md
    // the use of a 64 character hex string generated from 32 random bytes
    // is recommended to prevent fingerprinting
    func getAttestationId(attestationIndex: UInt32) throws -> String {
        let publicKey = try repositories.derive(attestationIndex: attestationIndex, objectType: ATTESTATION_ID).publicKey.dataRepresentation
        let only32BytesOfPublicKey = publicKey.dropFirst()
        return String(bytes: only32BytesOfPublicKey)
    }
}

class IdentityRepository {
    private let rootKey: ExtendedPrivateKey
    
    init(rootKey: ExtendedPrivateKey) {
        self.rootKey = rootKey
    }
    /*
     Derivation path:
     m / purpose' / account' / index
     
     With:
     * m: the root key
     * purpose: auth / 0x61757468 / 1635087464 (See Bip-43)
     * account: 0
     * index: 0
     */
    func getIdentity() throws -> ExtendedPrivateKey {
        let purpose = DerivationHelper.hardened(1635087464)
        let account = DerivationHelper.hardened(0)
        let index: UInt32 = 0
        
        return try rootKey
            .derive(index: purpose)
            .derive(index: account)
            .derive(index: index)
    }
}


private class DerivationHelper {
    private let rootKey: ExtendedPrivateKey
    
    init(rootKey: ExtendedPrivateKey) {
        self.rootKey = rootKey
    }
    
    /*
     Derivation path:
     m / purpose' / coin_type' / account' / unit' / index / object
     
     With:
     * m: the root key
     * purpose: mint / 0x6d696e74 / 1835626100 (See Bip-43)
     * coin_type: priv / 0x70726976 / 1886546294 (See Bip-44 and SLIP-44)
     * account: 0
     * unit: the unit of the attestation, for instance age over 18
     *   >15 / 0x003e3135 / 4075829
     *   >18 / 0x003e3138 / 4075832
     *   >21 / 0x003e3230 / 4076080
     * index: the attestation index
     * object:
     *   blinding factor: 0
     *   attestation id: 1
     */
    func derive(attestationIndex: UInt32, objectType: UInt32) throws -> ExtendedPrivateKey {
        // TODO implement nuts 20 https://github.com/cashubtc/nuts/blob/main/20.md
        let purpose = DerivationHelper.hardened(1835626100)
        let coinType = DerivationHelper.hardened(1886546294)
        let account = DerivationHelper.hardened(0)
        let unit = DerivationHelper.hardened(4075832)
        let index = attestationIndex
        
        return try rootKey
            .derive(index: purpose)
            .derive(index: coinType)
            .derive(index: account)
            .derive(index: unit)
            .derive(index: index)
            .derive(index: objectType)
    }
    
    fileprivate static func hardened(_ index: UInt32) -> UInt32 {
        return 2147483648 + index
    }
}
