// AirDropE2E: runs privatedrop's psi flow with the spicy backend and the signed identity resources.
// usage: AirDropE2E [repetitions] runs in process through the psi controller body api.
// usage: HARNESS_HTTPS=1 AirDropE2E [repetitions] runs a real https server and peer.
// HARNESS_LEVEL=wic selects the wic level, the default is cic.
// for each role mapping and scenario it checks the client's psi status and prints timings and sizes.

import Foundation
import Network

@testable import PrivateDrop_Base

setvbuf(stdout, nil, _IOLBF, 0)
let reps = CommandLine.arguments.count > 1 ? Int(CommandLine.arguments[1]) ?? 3 : 3

let spicyDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
let shared = spicyDir.deletingLastPathComponent().appendingPathComponent("Shared/Resources")
func file(_ url: URL) -> Data { try! Data(contentsOf: url) }
func ids(_ k: Int) -> [String] {
    let plist = try! PropertyListSerialization.propertyList(
        from: file(shared.appendingPathComponent("\(k)_other.plist")), format: nil) as! [String: Any]
    return plist["ids"] as! [String]
}
func randomContacts(_ n: Int, _ tag: String) -> [String] { (0..<n).map { "\(tag)-\($0)@contacts.example" } }

let harnessLevel = SpicyLevel(rawValue: ProcessInfo.processInfo.environment["HARNESS_LEVEL"] ?? "cic") ?? .cic
let useHTTPS = ProcessInfo.processInfo.environment["HARNESS_HTTPS"] != nil
print("SPICy level: \(harnessLevel.rawValue.uppercased())")
let authorityPEM = file(spicyDir.appendingPathComponent("TestAuthority/spicy-test-authority.pem"))
let recordData = file(shared.appendingPathComponent("record.data"))

func configuration(
    role: String, k: Int, contacts: [String], mapping: SpicyRoleMapping
) throws -> PrivateDrop.Configuration {
    let r = mapping == .identifiersAsSender ? "sender" : "receiver"
    let dir = spicyDir.appendingPathComponent("Resources/Identities")
    let tag = harnessLevel == .wic ? "spicy_wic" : "spicy"
    let settings = SpicyPSISettings(
        roleMapping: mapping, level: harnessLevel,
        signedIdentity: file(dir.appendingPathComponent("\(k)_\(tag)_\(r).cms")),
        identitySecret: file(dir.appendingPathComponent("\(k)_\(tag)_\(r)_secret.bin")),
        identifiers: ids(k), authorityCertificatePEM: authorityPEM, deviceID: "harness-\(role)")
    // self-signed tls identities from run-airdrop-harness.sh
    let tls = ProcessInfo.processInfo.environment["HARNESS_TLS_DIR"].map(URL.init(fileURLWithPath:)) ?? shared
    let cert = file(tls.appendingPathComponent(role == "server" ? "ServerCertificate.p12" : "ClientCertificate.p12"))
    // https mode sends no record data, as the harness has no resource bundle to validate it.
    return try PrivateDrop.Configuration(
        recordData: useHTTPS ? nil : recordData, pkcs12: cert, computerName: "Harness-\(role)", modelName: "MacBook 10,3",
        contactsOnly: true, contacts: contacts, supportsPrivateDrop: true, spicyPSI: settings)
}

final class Observer: PeerObserver {
    let done: (Peer) -> Void
    init(done: @escaping (Peer) -> Void) { self.done = done }
    func peerStatusChanged(peer: Peer) {}
    func peerErrorOccurred(error: Peer.PeerError) { print("  peer error: \(error)") }
    func psiStatusChanged(peer: Peer) {
        if peer.psiStatus != .unknown { done(peer) }
    }
}

final class Metrics {
    private let lock = NSLock()
    private(set) var items = [SpicyPSIMetrics]()
    let trace = ProcessInfo.processInfo.environment["HARNESS_TRACE"] != nil
    func add(_ m: SpicyPSIMetrics) {
        if trace { print("    · \(m.step.rawValue): \(String(format: "%.3f", m.total)) s, out \(m.bytesOut) B, in \(m.bytesIn) B, matches \(m.matches.map(String.init) ?? "-")") }
        lock.lock(); items.append(m); lock.unlock()
    }
    func reset() { lock.lock(); items.removeAll(); lock.unlock() }

    // rust time, interop overhead and authority time in seconds, summed over all steps.
    var sums: (rust: TimeInterval, interop: TimeInterval, auth: TimeInterval) {
        let m = items
        return (
            m.reduce(0) { $0 + $1.rust.rustTotal }, m.reduce(0) { $0 + $1.rust.interopOverhead },
            m.reduce(0) { $0 + $1.authorityVerification }
        )
    }
}

func mean(_ xs: [TimeInterval]) -> TimeInterval { xs.reduce(0, +) / Double(max(1, xs.count)) }

struct Scenario {
    let name: String
    let serverContacts: [String]
    let clientContacts: [String]
}

let serverK = 1, clientK = 10
let sIds = ids(serverK), cIds = ids(clientK)
let scenarios = [
    Scenario(name: "mutual contacts",
             serverContacts: randomContacts(60, "s") + [cIds[2], cIds[5]],
             clientContacts: randomContacts(40, "c") + [sIds[0]]),
    Scenario(name: "client not in server's address book",
             serverContacts: randomContacts(60, "s"),
             clientContacts: randomContacts(40, "c") + [sIds[0]]),
    Scenario(name: "server not in client's address book",
             serverContacts: randomContacts(60, "s") + [cIds[2]],
             clientContacts: randomContacts(40, "c")),
]

// what each side should learn, and the client's resulting status.
func expected(_ sc: Scenario, _ mapping: SpicyRoleMapping) -> Peer.PSIStatus {
    let serverLearns: [String]
    let clientLearns: [String]
    switch mapping {
    case .identifiersAsSender:  // each side: peer's ids found in own address book
        serverLearns = sc.serverContacts.filter(cIds.contains)
        clientLearns = sc.clientContacts.filter(sIds.contains)
    case .identifiersAsReceiver:  // each side: own ids found in peer's address book
        serverLearns = sIds.filter(sc.clientContacts.contains)
        clientLearns = cIds.filter(sc.serverContacts.contains)
    }
    if serverLearns.isEmpty { return .notInPeersContacts }
    if clientLearns.isEmpty { return .nonContact }
    return .contact(clientLearns)
}

// one exchange through the psi controller body api with the status mapping of the server routes and peer.
func inProcessExchange(client: PSIController, server: PSIController, recordData: Data?) -> (Peer.PSIStatus, Int) {
    var bytes = 0
    do {
        let startBody = try server.startPSIServerBody()  // GET /start-psi → 200
        let (round, finishBody) = try client.startPSIClientBody(startBody)
        bytes += startBody.count + finishBody.count
        let result: (body: Data, peerContacts: Int, peerIds: Int)
        do {
            result = try server.finishPSIServerBody(finishBody, recordData: recordData)  // POST /finish-psi
        } catch PSIController.Error.noContactMatch {
            return (.notInPeersContacts, bytes)  // server answers 401 → Peer: .notInPeersContacts
        } catch PSIController.Error.verificationFailed {
            return (.notInPeersContacts, bytes)  // also 401
        }
        bytes += result.body.count
        do {
            let r = try client.finishPSIClientBody(round: round, body: result.body)
            guard r.recordData == recordData else { print("  ✘ record data not carried"); return (.unknown, bytes) }
            return (.contact(r.matches), bytes)
        } catch PSIController.Error.noContactMatch {
            return (.nonContact, bytes)
        }
    } catch {
        print("  ✘ unexpected error: \(error)")
        return (.unknown, bytes)
    }
}

var failures = 0
var port = 18_443
let queue = DispatchQueue(label: "driver")

queue.async {
    print("SPICy in PrivateDrop Base (\(useHTTPS ? "HTTPS" : "in-process PSIController body API"), \(Spicy.libraryVersion)); server ids K=\(serverK), client ids K=\(clientK)")
    for mapping in SpicyRoleMapping.allCases {
        for sc in scenarios {
            do {
                let sConf = try configuration(role: "server", k: serverK, contacts: sc.serverContacts, mapping: mapping)
                let cConf = try configuration(role: "client", k: clientK, contacts: sc.clientContacts, mapping: mapping)
                guard let sPSI = PSIController(contactsConfig: sConf.contacts),
                    let cPSI = PSIController(contactsConfig: cConf.contacts)
                else { print("  ✘ PSIController init failed"); failures += 1; continue }
                let metrics = Metrics()
                sPSI.spicy?.metricsHandler = metrics.add
                cPSI.spicy?.metricsHandler = metrics.add
                let t0 = Date()
                try sPSI.precompute()
                try cPSI.precompute()
                let precompute = -t0.timeIntervalSinceNow

                let want = expected(sc, mapping)
                if !useHTTPS {
                    var times = [TimeInterval]()
                    var bytes = 0
                    for _ in 0..<reps {
                        metrics.reset()
                        let start = Date()
                        let (status, b) = inProcessExchange(client: cPSI, server: sPSI, recordData: sConf.contacts.recordData)
                        times.append(-start.timeIntervalSinceNow)
                        bytes = b
                        if status != want {
                            print("  ✘ [\(mapping.rawValue)] \(sc.name): got \(status), expected \(want)")
                            failures += 1
                        }
                    }
                    let (rust, interop, auth) = metrics.sums
                    let swift = metrics.items.reduce(0) { $0 + $1.total }
                    print(String(
                        format: "  ✔ [%@] %@ → %@\n      exchange %.3f s (mean of %d; last: PSI steps %.3f s = Rust %.3f s + FFI %.4f s + authority %.4f s + rest; HTTP bodies %.1f KB); precompute %.2f s",
                        mapping.rawValue, sc.name, "\(want)", mean(times), times.count, swift, rust, interop, auth, Double(bytes) / 1024, precompute))
                    continue
                }
                let server = Server(config: sConf, psiController: sPSI)
                port += 1
                let started = DispatchSemaphore(value: 0)
                try server.startServer(port: port) { _, _ in started.signal() }
                started.wait()
                let client = Client(config: cConf, psiController: cPSI,
                                    contactsChecker: ContactsChecker(ownContactIds: sc.clientContacts))
                var times = [TimeInterval]()
                for _ in 0..<reps {
                    metrics.reset()
                    let finished = DispatchSemaphore(value: 0)
                    var status = Peer.PSIStatus.unknown
                    let observer = Observer { p in status = p.psiStatus; finished.signal() }
                    let peer = Peer(
                        NWEndpoint.hostPort(host: .ipv6(IPv6Address("::1")!), port: NWEndpoint.Port(rawValue: UInt16(server.port))!),
                        supportsPSI: true, observer: observer)
                    peer.contactsChecker = client.contactsChecker
                    let start = Date()
                    try peer.startPSI(using: client)
                    if finished.wait(timeout: .now() + 120) == .timedOut {
                        print("  ✘ timeout"); failures += 1; break
                    }
                    times.append(-start.timeIntervalSinceNow)
                    if status != want {
                        print("  ✘ [\(mapping.rawValue)] \(sc.name): got \(status), expected \(want)")
                        failures += 1
                    }
                    _ = observer  // keeps the observer alive until the exchange ends
                }
                server.stopServer()
                let (rust, interop, auth) = metrics.sums
                let bytes = metrics.items.reduce(0) { $0 + $1.bytesOut }
                print(String(
                    format: "  ✔ [%@] %@ → %@\n      exchange %.3f s (mean of %d; last: Rust %.3f s, interop %.4f s, authority %.4f s, SPICy payload %.1f KB); precompute %.2f s",
                    mapping.rawValue, sc.name, "\(want)", mean(times), times.count, rust, interop, auth, Double(bytes) / 1024, precompute))
            } catch {
                print("  ✘ [\(mapping.rawValue)] \(sc.name): \(error)")
                failures += 1
            }
        }
    }
    print(failures == 0 ? "ALL PASSED" : "\(failures) FAILURE(S)")
    exit(failures == 0 ? 0 : 1)
}
dispatchMain()
