import Fluent
import Vapor
import SwiftCBOR

func routes(_ app: Application) throws {
    app.get { req in
        return req.view.render("index", ["title": "Hello Vapor!"])
    }
    
    app.get("makeCredential") { req -> MakeCredentialResponse in
        let username = try req.query.get(String.self, at: "username")
        let userID = UUID()
        let challenge = [UInt8].random(count: 32).base64
        let encodedChallenge = challenge.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        req.logger.debug("Challenge is \(encodedChallenge)")
        req.session.data["challenge"] = encodedChallenge
        req.session.data["username"] = username
        req.session.data["userID"] = userID.uuidString
        return MakeCredentialResponse(userID: userID.uuidString.base64String(), challenge: challenge)
    }
    
    // step 2 for registration
    app.post("makeCredential") { req -> HTTPStatus in
        guard let challenge = req.session.data["challenge"] else {
            throw Abort(.unauthorized)
        }
        let registerData = try req.content.decode(RegisterData.self)
        guard let clientObjectData = Data(base64Encoded: registerData.response.clientDataJSON) else {
            throw Abort(.badRequest)
        }
        let clientObject = try JSONDecoder().decode(ClientDataObject.self, from: clientObjectData)
        guard challenge == clientObject.challenge else {
            throw Abort(.unauthorized)
        }
        guard clientObject.type == "webauthn.create" else {
            throw Abort(.badRequest)
        }
        guard let origin = Environment.get("ORIGIN") else {
            throw Abort(.internalServerError)
        }
        guard origin == clientObject.origin else {
            throw Abort(.unauthorized)
        }
        var base64AttestationString = registerData.response.attestationObject.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while base64AttestationString.count % 4 != 0 {
            base64AttestationString = base64AttestationString.appending("=")
        }
        guard let attestationData = Data(base64Encoded: base64AttestationString) else {
            throw Abort(.badRequest)
        }
        guard let decodedAttestationObject = try CBOR.decode([UInt8](attestationData)) else {
            throw Abort(.badRequest)
        }
        req.logger.debug("Got COBR decoded data: \(decodedAttestationObject)")
        
        // Ignore format/statement for now
        guard let authData = decodedAttestationObject["authData"] else {
            throw Abort(.badRequest)
        }
        switch authData {
        case .byteString(let array):
            let idLengthBytes = array[53..<55]
            let idLengthData = Data(idLengthBytes)
            let idLength: UInt16 = idLengthData.toInteger(endian: .big)
            let credentialIDEndIndex = Int(idLength) + 55
            
            let credentialID = array[55..<credentialIDEndIndex]
            let publicKeyBytes = array[credentialIDEndIndex...]
            guard let publicKeyObject = try CBOR.decode(Array(publicKeyBytes)) else {
                throw Abort(.badRequest)
            }
            req.logger.debug("Credential ID is \(credentialID)")
            req.logger.debug("Public Key Object is \(publicKeyObject)")
        default:
            throw Abort(.badRequest)
        }

        return .ok
    }
    
    // step 1 for authentication
    app.get("authentication_initialize") { req -> HTTPStatus in
        return .notImplemented
    }
    
    // step 2 for authentication
    app.post("authentication_finalize") { req -> HTTPStatus in
        return .notImplemented
    }
    
    func parseAttestationObject(_ bytes: [UInt8]) throws {
        let minAuthDataLength = 37
        let minAttestedAuthLength = 55
        let maxCredentialIDLength = 1023
        
        guard bytes.count >= minAuthDataLength else {
            throw WebAuthnError.authDataTooShort
        }
        
        let rpIDHashData = bytes[..<32]
        let flags = AuthenticatorFlags(bytes[32])
        let counter: UInt32 = Data(bytes[33..<37]).toInteger(endian: .big)
        
        var remainingCount = bytes.count - minAuthDataLength
        
        if flags.attestedCredentialData {
            guard bytes.count > minAttestedAuthLength else {
                throw WebAuthnError.attestedCredentialDataMissing
            }
//            validError := a.unmarshalAttestedData(rawAuthData)
//            if validError != nil {
//                return validError
//            }
//            attDataLen := len(a.AttData.AAGUID) + 2 + len(a.AttData.CredentialID) + len(a.AttData.CredentialPublicKey)
//            remaining = remaining - attDataLen
        } else {
            if !flags.extensionDataIncluded && bytes.count != minAuthDataLength {
                throw WebAuthnError.attestedCredentialFlagNotSet
            }
        }
        
        if flags.extensionDataIncluded {
            guard remainingCount != 0 else {
                throw WebAuthnError.extensionDataMissing
            }
            let extensionData = bytes[(bytes.count - remainingCount)...]
            remainingCount -= extensionData.count
        }
        
        guard remainingCount == 0 else {
            throw WebAuthnError.leftOverBytes
        }
    }
}

enum WebAuthnError: Error {
    case authDataTooShort
    case extensionDataMissing
    case leftOverBytes
    case attestedCredentialFlagNotSet
    case attestedCredentialDataMissing
}

struct AuthenticatorFlags {
    
    /**
     Taken from https://w3c.github.io/webauthn/#sctn-authenticator-data
     Bit 0: User Present Result
     Bit 1: Reserved for future use
     Bit 2: User Verified Result
     Bits 3-5: Reserved for future use
     Bit 6: Attested credential data included
     Bit 7: Extension data include
     */
    
    enum Bit: UInt8 {
        case userPresent = 0
        case userVerified = 2
        case attestedCredentialDataIncluded = 6
        case extensionDataIncluded = 7
    }
    
    let userPresent: Bool
    let userVerified: Bool
    let attestedCredentialData: Bool
    let extensionDataIncluded: Bool
    
    init(_ byte: UInt8) {
        userPresent = Self.isFlagSet(on: byte, at: .userPresent)
        userVerified = Self.isFlagSet(on: byte, at: .userVerified)
        attestedCredentialData = Self.isFlagSet(on: byte, at: .attestedCredentialDataIncluded)
        extensionDataIncluded = Self.isFlagSet(on: byte, at: .extensionDataIncluded)
    }
    
    static func isFlagSet(on byte: UInt8, at position: Bit) -> Bool {
        (byte & (1 << position.rawValue)) != 0
    }
}

struct MakeCredentialResponse: Content {
    let userID: String
    let challenge: String
}

struct RegisterData: Content {
    let id: String
    let rawID: String
    let type: String
    let response: RegisterCredentialsResponse
    
    enum CodingKeys: String, CodingKey {
        case id
        case rawID = "rawId"
        case type
        case response
    }
}

struct RegisterCredentialsResponse: Content {
    let attestationObject: String
    let clientDataJSON: String
}

struct ClientDataObject: Content {
    let challenge: String
    let origin: String
    let type: String
}

public enum Endian {
    case big, little
}

protocol IntegerTransform: Sequence where Element: FixedWidthInteger {
    func toInteger<I: FixedWidthInteger>(endian: Endian) -> I
}

extension IntegerTransform {
    func toInteger<I: FixedWidthInteger>(endian: Endian) -> I {
        let f = { (accum: I, next: Element) in accum &<< next.bitWidth | I(next) }
        return endian == .big ? reduce(0, f) : reversed().reduce(0, f)
    }
}

extension Data: IntegerTransform {}
extension Array: IntegerTransform where Element: FixedWidthInteger {}
