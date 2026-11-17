// configuration for running privatedrop's psi with spicy instead of the original psi.
// setting PrivateDrop.Configuration.Contacts.spicy enables it.
// compiled into the privatedrop base framework.

import Foundation

#if canImport(SpicyPSI)
    import SpicyPSI
#endif

public struct SpicyPSISettings: Codable, Equatable {
    // which spicy role the identifiers and the address book play.
    public var roleMapping: SpicyRoleMapping
    // consistency level, cic or wic, matching the identity registration.
    public var level: SpicyLevel
    // authority-signed identity registration.
    public var signedIdentity: Data
    // secret state of the identity registration.
    public var identitySecret: Data
    // the device's own identifiers in registration order.
    public var identifiers: [String]
    // pem certificate of the authority that signs identity registrations.
    public var authorityCertificatePEM: Data
    // party identity for the address-book registration.
    public var deviceID: String
    // largest peer sender set and n_g this device accepts.
    public var maxPeerM: Int
    public var maxPeerNG: Int

    public init(
        roleMapping: SpicyRoleMapping = .identifiersAsSender, level: SpicyLevel = .cic, signedIdentity: Data,
        identitySecret: Data, identifiers: [String], authorityCertificatePEM: Data,
        deviceID: String = "privatedrop-device", maxPeerM: Int = 64, maxPeerNG: Int = 1 << 17
    ) {
        self.roleMapping = roleMapping
        self.level = level
        self.signedIdentity = signedIdentity
        self.identitySecret = identitySecret
        self.identifiers = identifiers
        self.authorityCertificatePEM = authorityCertificatePEM
        self.deviceID = deviceID
        self.maxPeerM = maxPeerM
        self.maxPeerNG = maxPeerNG
    }

    private enum CodingKeys: String, CodingKey {
        case roleMapping, level, signedIdentity, identitySecret, identifiers, authorityCertificatePEM, deviceID, maxPeerM, maxPeerNG
    }

    // a missing level decodes as cic.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        roleMapping = try c.decode(SpicyRoleMapping.self, forKey: .roleMapping)
        level = try c.decodeIfPresent(SpicyLevel.self, forKey: .level) ?? .cic
        signedIdentity = try c.decode(Data.self, forKey: .signedIdentity)
        identitySecret = try c.decode(Data.self, forKey: .identitySecret)
        identifiers = try c.decode([String].self, forKey: .identifiers)
        authorityCertificatePEM = try c.decode(Data.self, forKey: .authorityCertificatePEM)
        deviceID = try c.decodeIfPresent(String.self, forKey: .deviceID) ?? "privatedrop-device"
        maxPeerM = try c.decodeIfPresent(Int.self, forKey: .maxPeerM) ?? 64
        maxPeerNG = try c.decodeIfPresent(Int.self, forKey: .maxPeerNG) ?? 1 << 17
    }
}
