// psi entry points on http bodies, used by peer (client) and serverroutes (server).
// they dispatch to the original relic psi or to spicy.
// compiled into the privatedrop base framework.

import Foundation
import NIO

#if canImport(SpicyPSI)
    import SpicyPSI
#endif

// what the client keeps between /start-psi and /finish-psi.
enum PSIClientRound {
    case legacy(PSIFinisRequest)
    case spicy(SpicyFinishPSIRequest)

    // number of own values sent in round 1, for the test delegate.
    var sentValues: Int {
        switch self {
        case .legacy(let r): return r.prover.z.count
        case .spicy: return 0
        }
    }
}

// /finish-psi response body when spicy is used.
struct SpicyPSIFinishEnvelope: Codable {
    var psi: SpicyFinishPSIResponse
    var ReceiverRecordData: Data?
}

extension PSIController {

    var usesSpicy: Bool { spicy != nil }

    // runs psi work, on a background queue for spicy and inline for the original psi.
    // reply runs its closure on the channel's event loop.
    func perform(on eventLoop: EventLoop, _ work: @escaping (_ reply: @escaping (@escaping () -> Void) -> Void) -> Void) {
        let reply: (@escaping () -> Void) -> Void = { send in
            if eventLoop.inEventLoop { send() } else { eventLoop.execute(send) }
        }
        if usesSpicy {
            DispatchQueue.global(qos: .userInitiated).async { work(reply) }
        } else {
            work(reply)
        }
    }

    // precomputes what does not depend on the peer.
    func precompute() throws {
        if let spicy = spicy {
            try spicy.prepareAddressBook()
        } else {
            _ = prover.generateU()
        }
    }

    // server side, /start-psi response body.
    func startPSIServerBody() throws -> Data {
        if let spicy = spicy {
            return try PropertyListEncoder().encode(spicy.serverStart())
        }
        return try PropertyListEncoder().encode(startPSIServer())
    }

    // server side, /finish-psi: verifies the client's round, intersects and answers with our round.
    // throws noContactMatch if the intersection is empty and verificationFailed if verification fails.
    func finishPSIServerBody(_ body: Data, recordData: Data?) throws -> (body: Data, peerContacts: Int, peerIds: Int) {
        guard let spicy = spicy else {
            let finishRequest = try PropertyListDecoder().decode(PSIFinisRequest.self, from: body)
            let proverResponse = try finishPSIServer(with: finishRequest)
            let resp = PSIFinishResponse(proverResponse: proverResponse, ReceiverRecordData: recordData)
            return (try PropertyListEncoder().encode(resp), finishRequest.prover.u.count, proverResponse.z.count)
        }
        let request: SpicyFinishPSIRequest
        do {
            request = try PropertyListDecoder().decode(SpicyFinishPSIRequest.self, from: body)
        } catch {
            throw Error.malformedMessage
        }
        PrivateDrop.testDelegate?.startVerifying()
        let matches = try mapSpicyErrors { try spicy.serverFinish(request) }
        PrivateDrop.testDelegate?.intersected()
        guard !matches.isEmpty else { throw Error.noContactMatch }
        self.isContactOffPeer = true
        PrivateDrop.testDelegate?.startCalculatingZ()
        let resp = try mapSpicyErrors { try spicy.serverRespond(to: request) }
        PrivateDrop.testDelegate?.calculatedPOK()
        let envelope = SpicyPSIFinishEnvelope(psi: resp, ReceiverRecordData: recordData)
        return (try PropertyListEncoder().encode(envelope), 0, 0)
    }

    // client side, after /start-psi: our round-1 messages and the /finish-psi request body.
    func startPSIClientBody(_ body: Data) throws -> (round: PSIClientRound, body: Data) {
        if let spicy = spicy {
            let start = try PropertyListDecoder().decode(SpicyStartPSIResponse.self, from: body)
            let req = try mapSpicyErrors { try spicy.clientStart(with: start) }
            return (.spicy(req), try PropertyListEncoder().encode(req))
        }
        let verifierResponse = try PropertyListDecoder().decode(PSIVerifierResponse.self, from: body)
        let req = try startPSIClient(with: verifierResponse)
        return (.legacy(req), try PropertyListEncoder().encode(req))
    }

    // client side, after /finish-psi: verifies the server's round and intersects.
    // throws noContactMatch if the intersection is empty.
    func finishPSIClientBody(round: PSIClientRound, body: Data) throws
        -> (matches: [String], recordData: Data?, peerContacts: Int)
    {
        switch round {
        case .legacy:
            let finishResponse = try PropertyListDecoder().decode(PSIFinishResponse.self, from: body)
            let matches = try finishPSIClient(with: finishResponse.proverResponse)
            return (matches, finishResponse.ReceiverRecordData, finishResponse.proverResponse.u.count)
        case .spicy(let request):
            guard let spicy = spicy else { throw Error.stateError }
            let envelope = try PropertyListDecoder().decode(SpicyPSIFinishEnvelope.self, from: body)
            PrivateDrop.testDelegate?.startVerifying()
            let matches = try mapSpicyErrors { try spicy.clientFinish(request: request, response: envelope.psi) }
            PrivateDrop.testDelegate?.intersected()
            guard !matches.isEmpty else { throw Error.noContactMatch }
            self.isContactOffPeer = true
            return (matches, envelope.ReceiverRecordData, 0)
        }
    }

    // maps spicy, flow and authority errors to psi controller errors.
    private func mapSpicyErrors<T>(_ f: () throws -> T) throws -> T {
        do {
            return try f()
        } catch let e as Spicy.Error {
            Log.error(system: .client, message: "SPICy: %@", String(describing: e))
            switch e.code {
            case .invalidArgument, .internalError, .panic, .unknown: throw Error.stateError
            default: throw Error.verificationFailed
            }
        } catch let e as SpicyPSIController.Error {
            Log.error(system: .client, message: "SPICy flow: %@", String(describing: e))
            throw Error.verificationFailed
        } catch {
            // other errors come from the authority
            Log.error(system: .client, message: "SPICy authority: %@", String(describing: error))
            throw Error.verificationFailed
        }
    }
}
