import Foundation
import CryptoKit

@_cdecl("se_bridge_sign_challenge")
public func seBridgeSignChallenge(
    _ keyDataPtr: UnsafePointer<UInt8>,
    _ keyDataLen: Int,
    _ challengePtr: UnsafePointer<UInt8>,
    _ challengeLen: Int,
    _ sigOut: UnsafeMutablePointer<UInt8>,
    _ sigOutLen: UnsafeMutablePointer<Int>,
    _ pubkeyOut: UnsafeMutablePointer<UInt8>,
    _ pubkeyOutLen: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        let keyData = Data(bytes: keyDataPtr, count: keyDataLen)
        let challenge = Data(bytes: challengePtr, count: challengeLen)

        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData)
        let signature = try key.signature(for: challenge)
        let sigBytes = signature.derRepresentation
        let pubBytes = key.publicKey.x963Representation

        guard sigBytes.count <= sigOutLen.pointee,
              pubBytes.count <= pubkeyOutLen.pointee else {
            return -1
        }

        sigBytes.copyBytes(to: sigOut, count: sigBytes.count)
        sigOutLen.pointee = sigBytes.count

        pubBytes.copyBytes(to: pubkeyOut, count: pubBytes.count)
        pubkeyOutLen.pointee = pubBytes.count

        return 0
    } catch {
        return -1
    }
}

@_cdecl("se_bridge_create_key")
public func seBridgeCreateKey(
    _ keyDataOut: UnsafeMutablePointer<UInt8>,
    _ keyDataOutLen: UnsafeMutablePointer<Int>,
    _ pubkeyOut: UnsafeMutablePointer<UInt8>,
    _ pubkeyOutLen: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        let keyDataBytes = key.dataRepresentation
        let pubBytes = key.publicKey.x963Representation

        guard keyDataBytes.count <= keyDataOutLen.pointee,
              pubBytes.count <= pubkeyOutLen.pointee else {
            return -1
        }

        keyDataBytes.copyBytes(to: keyDataOut, count: keyDataBytes.count)
        keyDataOutLen.pointee = keyDataBytes.count

        pubBytes.copyBytes(to: pubkeyOut, count: pubBytes.count)
        pubkeyOutLen.pointee = pubBytes.count

        return 0
    } catch {
        return -1
    }
}
