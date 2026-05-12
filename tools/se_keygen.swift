import Foundation
import CryptoKit

let keyFile: URL
if CommandLine.arguments.count > 1 {
    keyFile = URL(fileURLWithPath: CommandLine.arguments[1])
} else {
    keyFile = URL(fileURLWithPath: "artifacts/se_key.dat")
}

do {
    let key: SecureEnclave.P256.Signing.PrivateKey

    if let stored = try? Data(contentsOf: keyFile) {
        key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored)
    } else {
        key = try SecureEnclave.P256.Signing.PrivateKey()
        try key.dataRepresentation.write(to: keyFile)
    }

    let pubHex = key.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined()
    let dataHex = key.dataRepresentation.map { String(format: "%02x", $0) }.joined()
    print(pubHex)
    print(dataHex)
} catch {
    fputs("se_keygen: \(error)\n", stderr)
    exit(1)
}
