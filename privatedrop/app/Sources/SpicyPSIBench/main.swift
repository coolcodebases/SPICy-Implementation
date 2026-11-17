// spicy-psi-bench: benchmarks privatedrop's psi on spicy through the swift api privatedrop uses.
// usage: swift run -c release spicy-psi-bench [--level cic|wic] [--mapping sender|receiver] [--reps R] [--warmup W] [--csv FILE] M,N ...
// example: swift run -c release spicy-psi-bench --reps 20 1,100 10,1000 20,15000
// both devices have M identifiers and N address-book entries and know one identifier of the other.
// device A is the airdrop sender (https client) and device B the airdrop receiver (https server).
// one run is one complete psi exchange without networking.
// it reports medians with 5th and 95th percentiles per (M, N).
// n_g is the recommended mask length for the sender and receiver set sizes of the mapping.

import Foundation
import SpicyPSI

setvbuf(stdout, nil, _IOLBF, 0)

// benchmark authority that accepts its own prefix instead of a signature.
struct BenchAuthority: SpicyAuthority {
    static let magic = Data("BENCH:".utf8)
    func verifySigned(_ signed: Data) throws -> Data { signed.dropFirst(Self.magic.count) }
}

func peakRSS() -> Double {
    var usage = rusage()
    getrusage(RUSAGE_SELF, &usage)
    return Double(usage.ru_maxrss) / 1_048_576  // bytes to mb
}

var mapping = SpicyRoleMapping.identifiersAsSender
var level = SpicyLevel.cic
var reps = 10
var warmup = 1
var csvPath: String?
var sizes = [(Int, Int)]()
var args = CommandLine.arguments.dropFirst().makeIterator()
while let a = args.next() {
    switch a {
    case "--level": level = SpicyLevel(rawValue: args.next() ?? "") ?? { print("--level must be cic or wic"); exit(2) }()
    case "--mapping": mapping = args.next() == "receiver" ? .identifiersAsReceiver : .identifiersAsSender
    case "--reps": reps = Int(args.next() ?? "") ?? reps
    case "--warmup": warmup = Int(args.next() ?? "") ?? warmup
    case "--csv": csvPath = args.next()
    default:
        let p = a.split(separator: ",").compactMap { Int($0) }
        if p.count == 2 { sizes.append((p[0], p[1])) }
    }
}
if sizes.isEmpty { sizes = [(1, 100), (10, 100), (10, 1000)] }

let threads = ProcessInfo.processInfo.environment["RAYON_NUM_THREADS"] ?? "all (\(ProcessInfo.processInfo.activeProcessorCount))"
print("SPICy PrivateDrop benchmark: \(Spicy.libraryVersion), level \(level.rawValue.uppercased()), mapping \(mapping.rawValue), \(reps) runs (+\(warmup) warm-up), Rust threads \(threads)")

var csv = "level,m,n,n_g,run,psi_client_ms,psi_server_ms,start_handler_ms,finish_handler_ms,total_ms,rust_client_ms,rust_server_ms,pow_verify_ms,bytes_start,bytes_finish_req,bytes_finish_resp,identity_reg_ms,addressbook_reg_ms,online_client_ms,online_server_ms,pair_setup_client_ms,pair_setup_server_ms,verify_reg_client_ms,verify_reg_server_ms,decode_pp_client_ms,decode_pp_server_ms,encode_client_ms,encode_server_ms\n"

func quantile(_ xs: [Double], _ p: Double) -> Double {
    let s = xs.sorted()
    let k = Double(s.count - 1) * p
    let f = Int(k), c = min(f + 1, s.count - 1)
    return s[f] + (s[c] - s[f]) * (k - Double(f))
}
func stat(_ xs: [Double]) -> String {
    String(format: "%8.1f [%7.1f, %8.1f]", quantile(xs, 0.5), quantile(xs, 0.05), quantile(xs, 0.95))
}
func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }
func ms(_ a: UInt64, _ b: UInt64) -> Double { Double(b - a) / 1e6 }

for (m, n) in sizes {
    // set sizes of the sender and receiver roles under the mapping.
    let (senderSize, receiverSize) = mapping == .identifiersAsSender ? (m, n) : (n, m)
    let nG = level.recommendedNG(maxM: senderSize, maxN: receiverSize)
    let aIds = (0..<m).map { "a-id-\($0)@example.org" }
    let bIds = (0..<m).map { "b-id-\($0)@example.org" }
    let aBook = (0..<n - 1).map { "a-contact-\($0)@contacts.example" } + [bIds[0]]
    let bBook = (0..<n - 1).map { "b-contact-\($0)@contacts.example" } + [aIds[0]]

    // identity registration.
    func identity(_ ids: [String], _ id: String) throws -> (SpicySignedIdentity, Double) {
        let t0 = now()
        let items = ids.map { Data($0.utf8) }
        let reg: Data, secret: Data
        if mapping == .identifiersAsSender {
            let p = try level.sender(items: items, id: Data(id.utf8), nG: nG)
            (reg, secret) = (try p.registration(), try p.exportSecret())
        } else {
            let p = try level.receiver(items: items, id: Data(id.utf8), nG: nG)
            (reg, secret) = (try p.registration(), try p.exportSecret())
        }
        return (SpicySignedIdentity(signedRegistration: BenchAuthority.magic + reg, secret: secret), ms(t0, now()))
    }
    do {
        let policy = Spicy.Policy(maxPeerM: senderSize, maxPeerNG: nG)
        let (aIdent, tIdent) = try identity(aIds, "device-a")
        let (bIdent, _) = try identity(bIds, "device-b")
        let a = try SpicyPSIController(roleMapping: mapping, level: level, identity: aIdent, identifiers: aIds, contacts: aBook,
                                       authority: BenchAuthority(), policy: policy, deviceID: Data("device-a".utf8))
        let b = try SpicyPSIController(roleMapping: mapping, level: level, identity: bIdent, identifiers: bIds, contacts: bBook,
                                       authority: BenchAuthority(), policy: policy, deviceID: Data("device-b".utf8))
        let tBook = try a.prepareAddressBook() * 1000
        try b.prepareAddressBook()

        var metrics = [SpicyPSIMetrics]()
        let lock = NSLock()
        a.metricsHandler = { x in lock.lock(); metrics.append(x); lock.unlock() }
        b.metricsHandler = { x in lock.lock(); metrics.append(x); lock.unlock() }
        let enc = PropertyListEncoder()
        enc.outputFormat = .binary
        let dec = PropertyListDecoder()

        var psiA = [Double](), psiB = [Double](), start = [Double](), finish = [Double](), total = [Double]()
        var rustA = [Double](), rustB = [Double](), pow = [Double](), bytes = (0, 0, 0)
        var onA = [Double](), onB = [Double](), psA = [Double](), psB = [Double](), vrA = [Double](), vrB = [Double]()
        var dcA = [Double](), dcB = [Double](), ecA = [Double](), ecB = [Double]()
        for run in 0..<(warmup + reps) {
            metrics.removeAll()
            let t0 = now()
            let startBody = try enc.encode(b.serverStart())  // B: /start-psi
            let t1 = now()
            let req = try a.clientStart(with: try dec.decode(SpicyStartPSIResponse.self, from: startBody))  // A: round 1
            let reqBody = try enc.encode(req)
            let t2 = now()
            let reqMsg = try dec.decode(SpicyFinishPSIRequest.self, from: reqBody)  // B: /finish-psi
            let bLearned = try b.serverFinish(reqMsg)
            let respBody = try enc.encode(try b.serverRespond(to: reqMsg))
            let t3 = now()
            let aLearned = try a.clientFinish(  // A: round 2
                request: req, response: try dec.decode(SpicyFinishPSIResponse.self, from: respBody))
            let t4 = now()
            guard aLearned.count == 1, bLearned.count == 1 else {
                throw NSError(domain: "bench", code: 1, userInfo: [NSLocalizedDescriptionKey: "expected one mutual match, got \(aLearned) / \(bLearned)"])
            }
            guard run >= warmup else { continue }
            // rust time in ms per device, summed over the device's steps.
            let phase = { (steps: [SpicyPSIMetrics.Step], f: (Spicy.Timings) -> TimeInterval) in
                metrics.filter { steps.contains($0.step) }.map { f($0.rust) * 1000 }.reduce(0, +)
            }
            let cSteps: [SpicyPSIMetrics.Step] = [.clientStart, .clientFinish], sSteps: [SpicyPSIMetrics.Step] = [.serverFinish, .serverRespond]
            psiA.append(ms(t1, t2) + ms(t3, t4)); psiB.append(ms(t0, t1) + ms(t2, t3))
            start.append(ms(t0, t1)); finish.append(ms(t2, t3)); total.append(ms(t0, t4))
            rustA.append(phase(cSteps) { $0.rustTotal }); rustB.append(phase(sSteps) { $0.rustTotal })
            pow.append(metrics.map { $0.rust.rustVerifyRegistration * 1000 }.reduce(0, +))
            onA.append(phase(cSteps) { $0.rustIntersection }); onB.append(phase(sSteps) { $0.rustIntersection })
            psA.append(phase(cSteps) { $0.rustPairSetup }); psB.append(phase(sSteps) { $0.rustPairSetup })
            vrA.append(phase(cSteps) { $0.rustVerifyRegistration }); vrB.append(phase(sSteps) { $0.rustVerifyRegistration })
            // decode and encode times.
            dcA.append(phase(cSteps) { $0.rustDecode }); dcB.append(phase(sSteps) { $0.rustDecode })
            ecA.append(phase(cSteps) { $0.rustEncode }); ecB.append(phase(sSteps) { $0.rustEncode })
            bytes = (startBody.count, reqBody.count, respBody.count)
            csv += String(format: "%@,%d,%d,%d,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%d,%d,%d,%.1f,%.1f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
                          level.rawValue, m, n, nG, run - warmup, psiA.last!, psiB.last!, start.last!, finish.last!, total.last!,
                          rustA.last!, rustB.last!, pow.last!, bytes.0, bytes.1, bytes.2, tIdent, tBook,
                          onA.last!, onB.last!, psA.last!, psB.last!, vrA.last!, vrB.last!,
                          dcA.last!, dcB.last!, ecA.last!, ecB.last!)
        }
        let kb = { (x: Int) in String(format: "%.1f", Double(x) / 1024) }
        print("""

            == m = \(m) identifiers, n = \(n) contacts (n_g = \(nG)), median [p5, p95] ms over \(reps) runs
              psi(A, client)   \(stat(psiA))   rust \(String(format: "%.1f", quantile(rustA, 0.5)))
              psi(B, server)   \(stat(psiB))   rust \(String(format: "%.1f", quantile(rustB, 0.5)))
                /start-psi     \(stat(start))
                /finish-psi    \(stat(finish))
              online (∩ phase) A \(stat(onA))   B \(stat(onB))
              pair setup       A \(stat(psA))   B \(stat(psB))   (+ registration check A \(String(format: "%.1f", quantile(vrA, 0.5))), B \(String(format: "%.1f", quantile(vrB, 0.5))))
              decode + pp      A \(stat(dcA))   B \(stat(dcB))
              total (no net)   \(stat(total))   (π_pow verification, both directions: \(String(format: "%.1f", quantile(pow, 0.5))))
              bytes            start \(kb(bytes.0)) KB, finish request \(kb(bytes.1)) KB, finish response \(kb(bytes.2)) KB (total \(kb(bytes.0 + bytes.1 + bytes.2)) KB)
              precompute       identity registration \(String(format: "%.0f", tIdent)) ms, address-book registration \(String(format: "%.0f", tBook)) ms
              peak RSS         \(String(format: "%.0f", peakRSS())) MB
            """)
    } catch {
        print("\n== m = \(m), n = \(n): ✘ \(error)")
    }
    if let p = csvPath { try? csv.write(toFile: p, atomically: true, encoding: .utf8) }
}
