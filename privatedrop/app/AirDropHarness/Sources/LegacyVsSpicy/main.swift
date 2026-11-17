// LegacyVsSpicy: runs privatedrop's original psi and spicy on identical inputs, one direction each.
// usage: LegacyVsSpicy [ids,contacts ...]
// the default sizes are 1,100 10,100 20,100 10,1000.
// it compares outputs with the plain set intersection and prints timings and message sizes.
// legacy: the verifier holds the identifiers and the prover the address book.
// spicy a: the receiver holds the identifiers and the sender the address book.
// spicy b: the sender holds the identifiers and the receiver the address book.
// signatures are not included, and precomputation is reported separately from online work.

import Foundation
import PSI
import SpicyPSI

setvbuf(stdout, nil, _IOLBF, 0)

func time<T>(_ f: () throws -> T) rethrows -> (T, TimeInterval) {
    let s = Date()
    let r = try f()
    return (r, -s.timeIntervalSinceNow)
}
func kb(_ n: Int) -> String { String(format: "%.1f KB", Double(n) / 1024) }
func ms(_ t: TimeInterval) -> String { String(format: "%.1f ms", t * 1000) }

var sizes: [(Int, Int)] = CommandLine.arguments.dropFirst().compactMap {
    let p = $0.split(separator: ",").compactMap { Int($0) }
    return p.count == 2 ? (p[0], p[1]) : nil
}
if sizes.isEmpty { sizes = [(1, 100), (10, 100), (20, 100), (10, 1000)] }

PSI.initialize(config: .init(useECPointCompression: true))
let policy = Spicy.Policy(maxPeerM: 100_000, maxPeerNG: 1 << 22)
var failures = 0

for (nIds, nContacts) in sizes {
    // identical inputs for all implementations
    let ids = (0..<nIds).map { "id-\($0)@owner.example" }
    let hits = Set(ids.enumerated().filter { $0.offset % 3 == 0 }.map(\.element))  // every third id is a contact
    var contacts = (0..<nContacts - hits.count).map { "contact-\($0)@book.example" }
    contacts.insert(contentsOf: hits.sorted(), at: contacts.count / 2)
    let reference = ids.filter { contacts.contains($0) }  // in the identifier holder's order
    print("\n== \(nIds) identifiers × \(nContacts) contacts, |∩| = \(reference.count)")

    // legacy privatedrop psi
    do {
        let verifier = try Verifier(ids: ids)
        let prover = try Prover(contacts: contacts)
        let (y, tY) = time { verifier.generateYFromIds() }  // precomputable
        let (u, tU) = time { prover.generateUForVerifier() }  // precomputable
        let ((z, pok), tProve) = time { () -> ([Data], (pokAs: [Data], pokZ: Data)) in
            let z = prover.generateZValuesForVerifier(from: y)
            return (z, prover.generatePoKForVerifier(from: y, z: z))
        }
        let (out, tVerify) = try time { () -> [String] in
            try verifier.verify(z: z, pokZ: pok.pokZ, pokAs: pok.pokAs)
            return verifier.intersect(with: u)
        }
        let ok = out == reference
        if !ok { failures += 1 }
        let bytesToProver = y.reduce(0) { $0 + $1.count }
        let bytesToVerifier = (z + pok.pokAs + u).reduce(0) { $0 + $1.count } + pok.pokZ.count
        print("  legacy   \(ok ? "✔" : "✘ MISMATCH \(out)")  precompute Y \(ms(tY)), U \(ms(tU)) | online: prover \(ms(tProve)), verifier \(ms(tVerify)) | ↑ \(kb(bytesToProver)) ↓ \(kb(bytesToVerifier))")
    } catch {
        failures += 1
        print("  legacy   ✘ \(error)")
    }

    // spicy, mapping a
    if nContacts <= 200 {
        do {
            let nG = Spicy.recommendedNG(maxM: nContacts, maxN: nIds)
            let (receiver, tR) = try time { try Spicy.Receiver(items: ids.map { Data($0.utf8) }, id: Data("r".utf8), nG: nG) }
            let (sender, tS) = try time { try Spicy.Sender(items: contacts.map { Data($0.utf8) }, id: Data("s".utf8), nG: nG) }
            let sid = Data("compare".utf8)
            let rreg = try receiver.registration(), sreg = try sender.registration()
            let (resp, ts) = try sender.respond(to: rreg, sid: sid)
            let (idx, tr) = try receiver.finish(senderRegistration: sreg, response: resp, sid: sid, policy: policy)
            let out = idx.map { ids[$0] }
            let ok = out == reference
            if !ok { failures += 1 }
            print("  SPICy A  \(ok ? "✔" : "✘ MISMATCH \(out)")  precompute reg_R \(ms(tR)), reg_S \(ms(tS)) | online: sender \(ms(ts.rustTotal)) (+\(ms(ts.interopOverhead)) FFI), receiver \(ms(tr.rustTotal)) (+\(ms(tr.interopOverhead)) FFI; π_pow \(ms(tr.rustVerifyRegistration))) | ↑ \(kb(rreg.count)) ↓ \(kb(sreg.count + resp.count))")
        } catch {
            failures += 1
            print("  SPICy A  ✘ \(error)")
        }
    } else {
        print("  SPICy A  skipped (Sender = \(nContacts)-entry address book: pair-setup proofs take ~minutes)")
    }

    // spicy, mapping b
    do {
        let nG = Spicy.recommendedNG(maxM: nIds, maxN: nContacts)
        let (sender, tS) = try time { try Spicy.Sender(items: ids.map { Data($0.utf8) }, id: Data("s".utf8), nG: nG) }
        let (receiver, tR) = try time { try Spicy.Receiver(items: contacts.map { Data($0.utf8) }, id: Data("r".utf8), nG: nG) }
        let sid = Data("compare".utf8)
        let rreg = try receiver.registration(), sreg = try sender.registration()
        let (resp, ts) = try sender.respond(to: rreg, sid: sid)
        let (idx, tr) = try receiver.finish(senderRegistration: sreg, response: resp, sid: sid, policy: policy)
        let out = Set(idx.map { contacts[$0] })
        let ok = out == Set(reference)
        if !ok { failures += 1 }
        print("  SPICy B  \(ok ? "✔" : "✘ MISMATCH \(out)")  precompute reg_S \(ms(tS)) (n_g \(nG)), reg_R \(ms(tR)) | online: sender \(ms(ts.rustTotal)) (+\(ms(ts.interopOverhead)) FFI), receiver \(ms(tr.rustTotal)) (+\(ms(tr.interopOverhead)) FFI; π_pow \(ms(tr.rustVerifyRegistration))) | ↑ \(kb(rreg.count)) ↓ \(kb(sreg.count + resp.count))")
    } catch {
        failures += 1
        print("  SPICy B  ✘ \(error)")
    }
}
print(failures == 0 ? "\nALL OUTPUTS MATCH THE REFERENCE" : "\n\(failures) FAILURE(S)")
exit(failures == 0 ? 0 : 1)
