// swift wrapper over the c interface of the rust spicy library.
// this is the only file that calls the spicy c functions.
// buffers returned by rust are wrapped in data without copying and freed by rust.
// handles are freed in deinit.
// both parties register with an identity and the same mask length n_g.
// handles may be used from several threads at once.

import CSpicy
import Foundation

public enum Spicy {

    // version string of the linked rust library.
    public static var libraryVersion: String { String(cString: spicy_version()) }

    // recommended mask length n_g for senders of up to maxM and receivers of up to maxN items.
    // both parties of a run must use the same n_g.
    public static func recommendedNG(maxM: Int, maxN: Int) -> Int {
        spicy_recommended_n_g(maxM, maxN)
    }

    public struct Error: Swift.Error, Equatable, CustomStringConvertible {
        public enum Code: Int32, Sendable {
            case invalidArgument = 1
            case invalidInput = 2
            case protocolAbort = 3
            case malformed = 4
            case policy = 5
            case internalError = 6
            case panic = 7
            case unknown = -1
        }

        public let code: Code
        public let message: String

        public init(code: Code, message: String) {
            self.code = code
            self.message = message
        }

        public var description: String { "SPICy error \(code) (\(code.rawValue)): \(message)" }
    }

    // time spent inside rust for one call, plus the elapsed time of the whole swift call.
    // interopOverhead is the time spent outside rust.
    public struct Timings: Equatable, Sendable, Codable {
        public var rustTotal: TimeInterval = 0
        public var rustDecode: TimeInterval = 0
        public var rustVerifyRegistration: TimeInterval = 0
        public var rustPairSetup: TimeInterval = 0
        public var rustIntersection: TimeInterval = 0
        public var rustEncode: TimeInterval = 0
        public var swiftWall: TimeInterval = 0

        public var interopOverhead: TimeInterval { max(0, swiftWall - rustTotal) }

        init(_ t: SpicyTimings, wall: TimeInterval) {
            func s(_ ns: UInt64) -> TimeInterval { TimeInterval(ns) / 1e9 }
            rustTotal = s(t.total_ns)
            rustDecode = s(t.decode_ns)
            rustVerifyRegistration = s(t.verify_registration_ns)
            rustPairSetup = s(t.pair_setup_ns)
            rustIntersection = s(t.intersection_ns)
            rustEncode = s(t.encode_ns)
            swiftWall = wall
        }

        public init() {}
    }

    // upper bounds on the peer's set size and mask length.
    public struct Policy: Equatable, Sendable, Codable {
        public var maxPeerM: Int
        public var maxPeerNG: Int

        public init(maxPeerM: Int, maxPeerNG: Int) {
            self.maxPeerM = maxPeerM
            self.maxPeerNG = maxPeerNG
        }
    }

    // a registered cic sender.
    public final class Sender: SpicySenderHandle, @unchecked Sendable {
        let handle: OpaquePointer

        // registers items for identity id and mask length nG.
        public init(items: [Data], id: Data, nG: Int) throws {
            handle = try register(items, id) { spicy_sender_register($0, $1, $2, nG, $3, $4) }
        }

        // rebuilds a handle from exportSecret output.
        public init(secret: Data) throws {
            handle = try importSecret(secret) { spicy_sender_import($0, $1, $2, $3) }
        }

        deinit { spicy_sender_free(handle) }

        public var m: Int { spicy_sender_m(handle) }
        public var nG: Int { spicy_sender_n_g(handle) }

        // public registration.
        public func registration() throws -> Data {
            try takeBuffer { out, err in spicy_sender_registration(handle, out, err) }
        }

        // secret state for persistence.
        public func exportSecret() throws -> Data {
            try takeBuffer { out, err in spicy_sender_export_secret(handle, out, err) }
        }

        // pair setup and intersection for a receiver registration and session id.
        public func respond(to receiverRegistration: Data, sid: Data) throws -> (response: Data, timings: Timings) {
            try runRespond(receiverRegistration, sid) { spicy_sender_respond(handle, $0, $1, $2, $3, $4, $5, $6) }
        }
    }

    // a registered cic receiver.
    public final class Receiver: SpicyReceiverHandle, @unchecked Sendable {
        let handle: OpaquePointer

        // registers items for identity id and mask length nG.
        public init(items: [Data], id: Data, nG: Int) throws {
            handle = try register(items, id) { spicy_receiver_register($0, $1, $2, nG, $3, $4) }
        }

        // rebuilds a handle from exportSecret output.
        public init(secret: Data) throws {
            handle = try importSecret(secret) { spicy_receiver_import($0, $1, $2, $3) }
        }

        deinit { spicy_receiver_free(handle) }

        // number of registered items.
        public var n: Int { spicy_receiver_n(handle) }
        public var nG: Int { spicy_receiver_n_g(handle) }

        // public registration.
        public func registration() throws -> Data {
            try takeBuffer { out, err in spicy_receiver_registration(handle, out, err) }
        }

        // secret state for persistence.
        public func exportSecret() throws -> Data {
            try takeBuffer { out, err in spicy_receiver_export_secret(handle, out, err) }
        }

        // verifies a sender's registration and response for sid.
        // returns the ascending indices of the intersection in the registered items.
        public func finish(
            senderRegistration: Data, response: Data, sid: Data, policy: Policy
        ) throws -> (indices: [Int], timings: Timings) {
            try runFinish(senderRegistration, response, sid) {
                spicy_receiver_finish(
                    handle, $0, $1, $2, $3, $4, $5, policy.maxPeerM, policy.maxPeerNG, $6, $7, $8)
            }
        }
    }
}

// spicy consistency level run by privatedrop.
public enum SpicyLevel: String, Codable, Sendable, CaseIterable {
    // complete input consistency.
    case cic
    // weak input consistency.
    case wic

    // recommended n_g for this level.
    public func recommendedNG(maxM: Int, maxN: Int) -> Int {
        switch self {
        case .cic: return Spicy.recommendedNG(maxM: maxM, maxN: maxN)
        case .wic: return spicy_wic_recommended_n_g(maxM, maxN)
        }
    }

    public func sender(items: [Data], id: Data, nG: Int) throws -> SpicySenderHandle {
        switch self {
        case .cic: return try Spicy.Sender(items: items, id: id, nG: nG)
        case .wic: return try Spicy.WIC.Sender(items: items, id: id, nG: nG)
        }
    }

    public func sender(secret: Data) throws -> SpicySenderHandle {
        switch self {
        case .cic: return try Spicy.Sender(secret: secret)
        case .wic: return try Spicy.WIC.Sender(secret: secret)
        }
    }

    public func receiver(items: [Data], id: Data, nG: Int) throws -> SpicyReceiverHandle {
        switch self {
        case .cic: return try Spicy.Receiver(items: items, id: id, nG: nG)
        case .wic: return try Spicy.WIC.Receiver(items: items, id: id, nG: nG)
        }
    }

    public func receiver(secret: Data) throws -> SpicyReceiverHandle {
        switch self {
        case .cic: return try Spicy.Receiver(secret: secret)
        case .wic: return try Spicy.WIC.Receiver(secret: secret)
        }
    }
}

// a registered sender of either level.
public protocol SpicySenderHandle: AnyObject, Sendable {
    var m: Int { get }
    var nG: Int { get }
    func registration() throws -> Data
    func exportSecret() throws -> Data
    func respond(to receiverRegistration: Data, sid: Data) throws -> (response: Data, timings: Spicy.Timings)
}

// a registered receiver of either level.
public protocol SpicyReceiverHandle: AnyObject, Sendable {
    var n: Int { get }
    var nG: Int { get }
    func registration() throws -> Data
    func exportSecret() throws -> Data
    func finish(senderRegistration: Data, response: Data, sid: Data, policy: Spicy.Policy) throws
        -> (indices: [Int], timings: Spicy.Timings)
}

extension Spicy {
    // spicy wic, with the same flow, errors and timings as cic.
    public enum WIC {
        // a registered wic sender.
        public final class Sender: SpicySenderHandle, @unchecked Sendable {
            let handle: OpaquePointer

            public init(items: [Data], id: Data, nG: Int) throws {
                handle = try register(items, id) { spicy_wic_sender_register($0, $1, $2, nG, $3, $4) }
            }

            public init(secret: Data) throws {
                handle = try importSecret(secret) { spicy_wic_sender_import($0, $1, $2, $3) }
            }

            deinit { spicy_wic_sender_free(handle) }

            public var m: Int { spicy_wic_sender_m(handle) }
            public var nG: Int { spicy_wic_sender_n_g(handle) }

            public func registration() throws -> Data {
                try takeBuffer { out, err in spicy_wic_sender_registration(handle, out, err) }
            }

            public func exportSecret() throws -> Data {
                try takeBuffer { out, err in spicy_wic_sender_export_secret(handle, out, err) }
            }

            public func respond(to receiverRegistration: Data, sid: Data) throws -> (response: Data, timings: Timings) {
                try runRespond(receiverRegistration, sid) { spicy_wic_sender_respond(handle, $0, $1, $2, $3, $4, $5, $6) }
            }
        }

        // a registered wic receiver.
        public final class Receiver: SpicyReceiverHandle, @unchecked Sendable {
            let handle: OpaquePointer

            public init(items: [Data], id: Data, nG: Int) throws {
                handle = try register(items, id) { spicy_wic_receiver_register($0, $1, $2, nG, $3, $4) }
            }

            public init(secret: Data) throws {
                handle = try importSecret(secret) { spicy_wic_receiver_import($0, $1, $2, $3) }
            }

            deinit { spicy_wic_receiver_free(handle) }

            public var n: Int { spicy_wic_receiver_n(handle) }
            public var nG: Int { spicy_wic_receiver_n_g(handle) }

            public func registration() throws -> Data {
                try takeBuffer { out, err in spicy_wic_receiver_registration(handle, out, err) }
            }

            public func exportSecret() throws -> Data {
                try takeBuffer { out, err in spicy_wic_receiver_export_secret(handle, out, err) }
            }

            public func finish(
                senderRegistration: Data, response: Data, sid: Data, policy: Policy
            ) throws -> (indices: [Int], timings: Timings) {
                try runFinish(senderRegistration, response, sid) {
                    spicy_wic_receiver_finish(
                        handle, $0, $1, $2, $3, $4, $5, policy.maxPeerM, policy.maxPeerNG, $6, $7, $8)
                }
            }
        }
    }
}

// runs a c call with an error buffer and throws on a non-zero status.
private func check(_ call: (UnsafeMutablePointer<SpicyBuffer>) -> Int32) throws {
    var err = SpicyBuffer(ptr: nil, len: 0)
    let rc = call(&err)
    guard rc != SPICY_OK else { return }
    var message = ""
    if let p = err.ptr, err.len > 0 {
        message = String(decoding: UnsafeBufferPointer(start: p, count: err.len), as: UTF8.self)
    }
    spicy_buffer_free(err)
    throw Spicy.Error(code: Spicy.Error.Code(rawValue: rc) ?? .unknown, message: message)
}

// runs a c call that fills an output buffer and returns it as data without copying.
private func takeBuffer(
    _ call: (UnsafeMutablePointer<SpicyBuffer>, UnsafeMutablePointer<SpicyBuffer>) -> Int32
) throws -> Data {
    var out = SpicyBuffer(ptr: nil, len: 0)
    try check { err in call(&out, err) }
    guard let p = out.ptr, out.len > 0 else { return Data() }
    let owned = out
    return Data(
        bytesNoCopy: p, count: out.len,
        deallocator: .custom { _, _ in spicy_buffer_free(owned) })
}

private func unwrap(_ p: OpaquePointer?) throws -> OpaquePointer {
    guard let p = p else {
        throw Spicy.Error(code: .internalError, message: "FFI returned success without a handle")
    }
    return p
}

// packs items as one contiguous buffer plus lengths.
private func withItems<R>(_ items: [Data], _ body: (SpicyItems) throws -> R) rethrows -> R {
    var data = Data(capacity: items.reduce(0) { $0 + $1.count })
    items.forEach { data.append($0) }
    let lengths = items.map { $0.count }
    defer { data.resetBytes(in: 0..<data.count) }  // wipe the packed copy
    return try data.withUnsafeBytes { d in
        try lengths.withUnsafeBufferPointer { l in
            try body(
                SpicyItems(
                    data: d.bindMemory(to: UInt8.self).baseAddress, data_len: d.count,
                    lengths: l.baseAddress, count: l.count))
        }
    }
}

// byte pointer and length of a buffer.
private typealias Bytes = (UnsafePointer<UInt8>?, Int)

private func bytes(_ b: UnsafeRawBufferPointer) -> Bytes {
    (b.bindMemory(to: UInt8.self).baseAddress, b.count)
}

private func seconds(since start: UInt64) -> TimeInterval {
    TimeInterval(DispatchTime.now().uptimeNanoseconds - start) / 1e9
}

// runs a register call on the packed items and id and returns the new handle.
private func register(
    _ items: [Data], _ id: Data,
    _ call: (SpicyItems, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<OpaquePointer?>, UnsafeMutablePointer<SpicyBuffer>)
        -> Int32
) throws -> OpaquePointer {
    var out: OpaquePointer?
    try withItems(items) { raw in
        try id.withUnsafeBytes { i in
            let (p, n) = bytes(i)
            try check { err in call(raw, p, n, &out, err) }
        }
    }
    return try unwrap(out)
}

// runs an import call on secret and returns the new handle.
private func importSecret(
    _ secret: Data,
    _ call: (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<OpaquePointer?>, UnsafeMutablePointer<SpicyBuffer>) -> Int32
) throws -> OpaquePointer {
    var out: OpaquePointer?
    try secret.withUnsafeBytes { b in
        let (p, n) = bytes(b)
        try check { err in call(p, n, &out, err) }
    }
    return try unwrap(out)
}

// runs a respond call and returns the response with its timings.
private func runRespond(
    _ receiverRegistration: Data, _ sid: Data,
    _ call: (
        UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int,
        UnsafeMutablePointer<SpicyBuffer>, UnsafeMutablePointer<SpicyTimings>, UnsafeMutablePointer<SpicyBuffer>
    ) -> Int32
) throws -> (response: Data, timings: Spicy.Timings) {
    let start = DispatchTime.now().uptimeNanoseconds
    var t = SpicyTimings()
    let resp: Data = try receiverRegistration.withUnsafeBytes { rr in
        try sid.withUnsafeBytes { s in
            let (rp, rn) = bytes(rr), (sp, sn) = bytes(s)
            return try takeBuffer { out, err in call(rp, rn, sp, sn, out, &t, err) }
        }
    }
    return (resp, Spicy.Timings(t, wall: seconds(since: start)))
}

// runs a finish call and returns the output indices with their timings.
private func runFinish(
    _ senderRegistration: Data, _ response: Data, _ sid: Data,
    _ call: (
        UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int,
        UnsafeMutablePointer<SpicyIndexList>, UnsafeMutablePointer<SpicyTimings>, UnsafeMutablePointer<SpicyBuffer>
    ) -> Int32
) throws -> (indices: [Int], timings: Spicy.Timings) {
    let start = DispatchTime.now().uptimeNanoseconds
    var t = SpicyTimings()
    var list = SpicyIndexList(ptr: nil, len: 0)
    try senderRegistration.withUnsafeBytes { sr in
        try response.withUnsafeBytes { rp in
            try sid.withUnsafeBytes { s in
                let (a, an) = bytes(sr), (b, bn) = bytes(rp), (c, cn) = bytes(s)
                try check { err in call(a, an, b, bn, c, cn, &list, &t, err) }
            }
        }
    }
    defer { spicy_index_list_free(list) }
    var idx = [Int]()
    if let p = list.ptr, list.len > 0 {
        idx = UnsafeBufferPointer(start: p, count: list.len).map { Int($0) }
    }
    return (idx, Spicy.Timings(t, wall: seconds(since: start)))
}
