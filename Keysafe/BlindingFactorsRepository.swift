//
//  BlindingFactorsRepository.swift
//  Keysafe
//
//  Created by pascal on 18/12/2024.
//

import Foundation
import secp256k1
import BIP32

class BlindingFactorsRepository {
    private let m: ExtendedKeyable
    
    init(seed: Data) throws {
        self.m = try PrivateMasterKeyDerivator().privateKey(seed: seed)
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
     *   attestation number: 1
     */
    func getBlindingFactor(attestationIndex: UInt32) throws -> secp256k1.Signing.PrivateKey {
        let derivator = PrivateChildKeyDerivator()
        let purpose = try derivator.privateKey(privateParentKey: m, index: hardened(1835626100))
        let coinType = try derivator.privateKey(privateParentKey: purpose, index: hardened(1886546294))
        let account = try derivator.privateKey(privateParentKey: coinType, index: hardened(0))
        let unit = try derivator.privateKey(privateParentKey: account, index: hardened(4075832))
        let index = try derivator.privateKey(privateParentKey: unit, index: attestationIndex)
        let blindingFactor = try derivator.privateKey(privateParentKey: index, index: 0)
        return try secp256k1.Signing.PrivateKey(dataRepresentation: blindingFactor.key)
    }
    
    private func hardened(_ index: UInt32) -> UInt32 {
        return 2147483648 + index
    }
}
