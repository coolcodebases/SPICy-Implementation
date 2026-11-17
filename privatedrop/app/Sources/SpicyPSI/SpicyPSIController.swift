// privatedrop's mutual contact discovery on top of spicy.
// psi runs in both directions over the two http requests /start-psi and /finish-psi.
// start-psi: the server sends a nonce and its receiver registration.
// finish-psi request: the client sends its sender registration and response, its receiver registration and a nonce.
// the server finishes direction 1 and responds for direction 2.
// finish-psi response: the server sends its sender registration and response.
// the client finishes direction 2.
// each session id is a hash of the direction and the nonce chosen by that direction's receiver.
// the server accepts each of its nonces once and only within nonceLifetime.
// the registration over the device's identifiers is signed by an authority and checked by every peer.
// the address-book registration is not signed.

import CryptoKit
import Foundation

// which spicy role each of a device's two sets plays.
public enum SpicyRoleMapping: String, Codable, Sendable, CaseIterable {
    // sender is the own identifiers, receiver is the address book.
    // each device learns which of the peer's identifiers are in its own address book.
    case identifiersAsSender
    // receiver is the own identifiers, sender is the address book.
    // each device learns which of its own identifiers are in the peer's address book.
    case identifiersAsReceiver
}

// verifies an authority-signed blob and returns the signed content.
public protocol SpicyAuthority {
    func verifySigned(_ signed: Data) throws -> Data
}

// a device's precomputed, authority-signed identity registration.
public struct SpicySignedIdentity {
    // authority-signed registration.
    public let signedRegistration: Data
    // secret state from spicy-precompute or exportSecret.
    public let secret: Data

    public init(signedRegistration: Data, secret: Data) {
        self.signedRegistration = signedRegistration
        self.secret = secret
    }
}

// version of the spicy messages carried in the http bodies.
public let spicyWireVersion = 3

// body of the /start-psi response.
public struct SpicyStartPSIResponse: Codable, Equatable {
    public var version: Int
    public var level: SpicyLevel
    public var roleMapping: SpicyRoleMapping
    // server-chosen nonce for direction 1.
    public var nonce: Data
    // server's receiver registration, nil if its receiver set is empty.
    public var receiverRegistration: Data?
}

// body of the /finish-psi request.
public struct SpicyFinishPSIRequest: Codable, Equatable {
    public var version: Int
    public var level: SpicyLevel
    public var roleMapping: SpicyRoleMapping
    // echo of the start-psi nonce.
    public var nonce: Data
    // client's sender registration and response, nil if either side's set is empty.
    public var senderRegistration: Data?
    public var senderResponse: Data?
    // client's receiver registration and nonce for direction 2.
    public var receiverRegistration: Data?
    public var receiverNonce: Data
}

// psi part of the /finish-psi response.
public struct SpicyFinishPSIResponse: Codable, Equatable {
    public var version: Int
    public var senderRegistration: Data?
    public var senderResponse: Data?
}

// per-step measurements for benchmarking.
public struct SpicyPSIMetrics: Codable, Equatable {
    public enum Step: String, Codable { case serverStart, clientStart, serverFinish, serverRespond, clientFinish }
    public var step: Step
    // rust timings of the calls in this step.
    public var rust: Spicy.Timings
    // wall-clock time of the whole step.
    public var total: TimeInterval
    // time spent verifying authority signatures.
    public var authorityVerification: TimeInterval
    // bytes of spicy payload produced and consumed.
    public var bytesOut: Int
    public var bytesIn: Int
    // size of the matched set, where the step produces one.
    public var matches: Int?
}

public final class SpicyPSIController: @unchecked Sendable {

    public enum Error: Swift.Error, Equatable {
        case unsupportedVersion(Int)
        case roleMappingMismatch(local: SpicyRoleMapping, peer: SpicyRoleMapping)
        case levelMismatch(local: SpicyLevel, peer: SpicyLevel)
        case unknownOrExpiredNonce
        case identityRegistrationMismatch
        case identifierCountMismatch(expected: Int, got: Int)
        case incompleteMessage(String)
    }

    public let roleMapping: SpicyRoleMapping
    // consistency level, which peers must share.
    public let level: SpicyLevel
    public let policy: Spicy.Policy
    // mask length n_g taken from the signed identity registration.
    public let nG: Int
    // party identity for the address-book registration.
    public let deviceID: Data
    public var metricsHandler: ((SpicyPSIMetrics) -> Void)?

    private let authority: SpicyAuthority
    private let identifiers: [String]
    private let contacts: [String]
    private let identitySigned: Data
    private let identitySender: SpicySenderHandle?
    private let identityReceiver: SpicyReceiverHandle?

    private let lock = NSLock()
    private var addressBookSender: SpicySenderHandle?
    private var addressBookReceiver: SpicyReceiverHandle?
    private var addressBookPrepared = false
    private let nonces: NonceStore

    // identity is the device's signed registration over identifiers.
    // identifiers are the device's own identifiers in registration order.
    // contacts are the address-book entries, deduplicated in order.
    // deviceID is the party identity used to register the address book.
    // level is the consistency level the identity was registered at.
    public init(
        roleMapping: SpicyRoleMapping,
        level: SpicyLevel = .cic,
        identity: SpicySignedIdentity,
        identifiers: [String],
        contacts: [String],
        authority: SpicyAuthority,
        policy: Spicy.Policy,
        deviceID: Data = Data("privatedrop-device".utf8),
        nonceLifetime: TimeInterval = 300
    ) throws {
        self.roleMapping = roleMapping
        self.level = level
        self.authority = authority
        self.policy = policy
        self.deviceID = deviceID
        self.identifiers = Self.unique(identifiers)
        self.contacts = Self.unique(contacts)
        self.identitySigned = identity.signedRegistration
        self.nonces = NonceStore(lifetime: nonceLifetime)

        // check that the signed registration matches the secret.
        let signedContent = try authority.verifySigned(identity.signedRegistration)
        switch roleMapping {
        case .identifiersAsSender:
            let s = try level.sender(secret: identity.secret)
            guard try s.registration() == signedContent else { throw Error.identityRegistrationMismatch }
            guard s.m == self.identifiers.count else {
                throw Error.identifierCountMismatch(expected: s.m, got: self.identifiers.count)
            }
            identitySender = s
            identityReceiver = nil
            nG = s.nG
        case .identifiersAsReceiver:
            let r = try level.receiver(secret: identity.secret)
            guard try r.registration() == signedContent else { throw Error.identityRegistrationMismatch }
            guard r.n == self.identifiers.count else {
                throw Error.identifierCountMismatch(expected: r.n, got: self.identifiers.count)
            }
            identityReceiver = r
            identitySender = nil
            nG = r.nG
        }
    }

    // registers the address book under the identity's n_g and returns the time it took.
    // it runs on first use or can be called early.
    @discardableResult
    public func prepareAddressBook() throws -> TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        guard !addressBookPrepared else { return 0 }
        let start = Date()
        let items = contacts.map { Data($0.utf8) }
        if !items.isEmpty {
            switch roleMapping {
            case .identifiersAsSender:
                addressBookReceiver = try level.receiver(items: items, id: deviceID, nG: nG)
            case .identifiersAsReceiver:
                addressBookSender = try level.sender(items: items, id: deviceID, nG: nG)
            }
        }
        addressBookPrepared = true
        return -start.timeIntervalSinceNow
    }

    public var isAddressBookPrepared: Bool {
        lock.lock()
        defer { lock.unlock() }
        return addressBookPrepared
    }

    private var sender: SpicySenderHandle? {
        roleMapping == .identifiersAsSender ? identitySender : addressBookSender
    }
    private var receiver: SpicyReceiverHandle? {
        roleMapping == .identifiersAsSender ? addressBookReceiver : identityReceiver
    }
    // items of our receiver role by registration index.
    private var receiverItems: [String] {
        roleMapping == .identifiersAsSender ? contacts : identifiers
    }
    private var senderIsSigned: Bool { roleMapping == .identifiersAsSender }

    // our sender registration as sent on the wire.
    private func senderRegistrationOnWire() throws -> Data? {
        guard let s = sender else { return nil }
        return senderIsSigned ? identitySigned : try s.registration()
    }
    private func receiverRegistrationOnWire() throws -> Data? {
        guard let r = receiver else { return nil }
        return senderIsSigned ? try r.registration() : identitySigned
    }

    // unwraps a peer's sender registration, verifying the signature if signed.
    private func peerSenderRegistration(_ wire: Data) throws -> Data {
        senderIsSigned ? try authority.verifySigned(wire) : wire
    }
    private func peerReceiverRegistration(_ wire: Data) throws -> Data {
        senderIsSigned ? wire : try authority.verifySigned(wire)
    }

    static func sid(direction: UInt8, nonce: Data) -> Data {
        var h = SHA256()
        h.update(data: Data("PrivateDrop/SPICy/sid/v1".utf8))
        h.update(data: Data([direction]))
        h.update(data: nonce)
        return Data(h.finalize())
    }

    private func checkPeer(version: Int, level peerLevel: SpicyLevel? = nil, mapping: SpicyRoleMapping?) throws {
        guard version == spicyWireVersion else { throw Error.unsupportedVersion(version) }
        if let l = peerLevel, l != level { throw Error.levelMismatch(local: level, peer: l) }
        if let m = mapping, m != roleMapping { throw Error.roleMappingMismatch(local: roleMapping, peer: m) }
    }

    // server side, start-psi: issues a nonce and sends our receiver registration.
    public func serverStart() throws -> SpicyStartPSIResponse {
        let start = Date()
        try prepareAddressBook()
        let reg = try receiverRegistrationOnWire()
        let resp = SpicyStartPSIResponse(
            version: spicyWireVersion, level: level, roleMapping: roleMapping, nonce: nonces.issue(),
            receiverRegistration: reg)
        report(.serverStart, Spicy.Timings(), start, 0, out: reg?.count ?? 0, in: 0, matches: nil)
        return resp
    }

    // server side, finish-psi direction 1: returns our matching receiver items.
    // it consumes the nonce, so call it once per request.
    public func serverFinish(_ request: SpicyFinishPSIRequest) throws -> [String] {
        let start = Date()
        try checkPeer(version: request.version, level: request.level, mapping: request.roleMapping)
        guard nonces.consume(request.nonce) else { throw Error.unknownOrExpiredNonce }
        try prepareAddressBook()
        guard let receiver = receiver, let sregWire = request.senderRegistration,
            let response = request.senderResponse
        else {
            report(.serverFinish, Spicy.Timings(), start, 0, out: 0, in: 0, matches: 0)
            return []  // one side's set is empty
        }
        let a = Date()
        let sreg = try peerSenderRegistration(sregWire)
        let auth = -a.timeIntervalSinceNow
        let (idx, t) = try receiver.finish(
            senderRegistration: sreg, response: response,
            sid: Self.sid(direction: 1, nonce: request.nonce), policy: policy)
        let items = receiverItems
        let matches = idx.map { items[$0] }
        report(.serverFinish, t, start, auth, out: 0, in: sregWire.count + response.count, matches: matches.count)
        return matches
    }

    // server side, finish-psi direction 2: responds to the client's receiver registration.
    public func serverRespond(to request: SpicyFinishPSIRequest) throws -> SpicyFinishPSIResponse {
        let start = Date()
        try checkPeer(version: request.version, level: request.level, mapping: request.roleMapping)
        guard let sender = sender, let rregWire = request.receiverRegistration else {
            report(.serverRespond, Spicy.Timings(), start, 0, out: 0, in: 0, matches: nil)
            return SpicyFinishPSIResponse(version: spicyWireVersion, senderRegistration: nil, senderResponse: nil)
        }
        let a = Date()
        let rreg = try peerReceiverRegistration(rregWire)
        let auth = -a.timeIntervalSinceNow
        let (resp, t) = try sender.respond(
            to: rreg, sid: Self.sid(direction: 2, nonce: request.receiverNonce))
        let sreg = try senderRegistrationOnWire()
        report(.serverRespond, t, start, auth, out: resp.count + (sreg?.count ?? 0), in: rregWire.count, matches: nil)
        return SpicyFinishPSIResponse(version: spicyWireVersion, senderRegistration: sreg, senderResponse: resp)
    }

    // client side, after start-psi: runs direction 1 as sender and adds our receiver registration.
    public func clientStart(with start: SpicyStartPSIResponse) throws -> SpicyFinishPSIRequest {
        let begin = Date()
        try checkPeer(version: start.version, level: start.level, mapping: start.roleMapping)
        try prepareAddressBook()
        var senderReg: Data?
        var senderResp: Data?
        var t = Spicy.Timings()
        var auth: TimeInterval = 0
        if let sender = sender, let rregWire = start.receiverRegistration {
            let a = Date()
            let rreg = try peerReceiverRegistration(rregWire)
            auth = -a.timeIntervalSinceNow
            (senderResp, t) = try sender.respond(to: rreg, sid: Self.sid(direction: 1, nonce: start.nonce))
            senderReg = try senderRegistrationOnWire()
        }
        let receiverReg = try receiverRegistrationOnWire()
        let req = SpicyFinishPSIRequest(
            version: spicyWireVersion, level: level, roleMapping: roleMapping, nonce: start.nonce,
            senderRegistration: senderReg, senderResponse: senderResp,
            receiverRegistration: receiverReg, receiverNonce: NonceStore.random())
        let out = (senderReg?.count ?? 0) + (senderResp?.count ?? 0) + (receiverReg?.count ?? 0)
        report(.clientStart, t, begin, auth, out: out, in: start.receiverRegistration?.count ?? 0, matches: nil)
        return req
    }

    // client side, after finish-psi: runs direction 2 as receiver and returns our matching items.
    // request is the request this client sent.
    public func clientFinish(request: SpicyFinishPSIRequest, response: SpicyFinishPSIResponse) throws -> [String] {
        let start = Date()
        try checkPeer(version: response.version, mapping: nil)
        guard let receiver = receiver, let sregWire = response.senderRegistration,
            let resp = response.senderResponse
        else {
            report(.clientFinish, Spicy.Timings(), start, 0, out: 0, in: 0, matches: 0)
            return []
        }
        let a = Date()
        let sreg = try peerSenderRegistration(sregWire)
        let auth = -a.timeIntervalSinceNow
        let (idx, t) = try receiver.finish(
            senderRegistration: sreg, response: resp,
            sid: Self.sid(direction: 2, nonce: request.receiverNonce), policy: policy)
        let items = receiverItems
        let matches = idx.map { items[$0] }
        report(.clientFinish, t, start, auth, out: 0, in: sregWire.count + resp.count, matches: matches.count)
        return matches
    }

    private func report(
        _ step: SpicyPSIMetrics.Step, _ t: Spicy.Timings, _ start: Date, _ auth: TimeInterval,
        out: Int, in bytesIn: Int, matches: Int?
    ) {
        guard let h = metricsHandler else { return }
        h(SpicyPSIMetrics(
            step: step, rust: t, total: -start.timeIntervalSinceNow, authorityVerification: auth,
            bytesOut: out, bytesIn: bytesIn, matches: matches))
    }

    static func unique(_ xs: [String]) -> [String] {
        var seen = Set<String>()
        return xs.filter { seen.insert($0).inserted }
    }
}

// single-use, expiring nonces issued by a server.
final class NonceStore {
    private let lifetime: TimeInterval
    private let capacity: Int
    private var issued: [Data: Date] = [:]
    private let lock = NSLock()

    init(lifetime: TimeInterval, capacity: Int = 4096) {
        self.lifetime = lifetime
        self.capacity = capacity
    }

    static func random() -> Data {
        var b = [UInt8](repeating: 0, count: 32)
        let rc = SecRandomCopyBytes(kSecRandomDefault, b.count, &b)
        precondition(rc == errSecSuccess, "SecRandomCopyBytes failed")
        return Data(b)
    }

    func issue() -> Data {
        let n = Self.random()
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        issued = issued.filter { now.timeIntervalSince($0.value) < lifetime }
        if issued.count >= capacity, let oldest = issued.min(by: { $0.value < $1.value }) {
            issued[oldest.key] = nil
        }
        issued[n] = now
        return n
    }

    func consume(_ n: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let t = issued.removeValue(forKey: n) else { return false }
        return Date().timeIntervalSince(t) < lifetime
    }
}
