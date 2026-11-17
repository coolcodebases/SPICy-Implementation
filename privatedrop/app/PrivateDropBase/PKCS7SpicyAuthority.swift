// verifies authority-signed spicy identity registrations with privatedrop's pkcs7 verifier.
// compiled into the privatedrop base framework.

import Foundation
import OpenSSL

#if canImport(SpicyPSI)
    import SpicyPSI
#endif

struct PKCS7SpicyAuthority: SpicyAuthority {
    // file with the authority certificate.
    let certificateURL: URL

    init(certificatePEM: Data) throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("privatedrop-spicy-authority-\(certificatePEM.hashValue).pem")
        try certificatePEM.write(to: url, options: .atomic)
        self.certificateURL = url
    }

    func verifySigned(_ signed: Data) throws -> Data {
        try PKCS7Verifier(pkcs7: signed).verify(with: certificateURL, verifyChain: true)
    }
}
