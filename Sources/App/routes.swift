import Fluent
import Vapor
import SwiftCBOR
import Crypto

func routes(_ app: Application) throws {
    app.get { req in
        return req.view.render("index", ["title": "Log In"])
    }
    
    let authSessionRoutes = app.grouped(User.sessionAuthenticator())
    
    let protected = authSessionRoutes.grouped(User.redirectMiddleware(path: "/"))
    
    protected.get("private") { req -> View in
        let user = try req.auth.require(User.self)
        return try await req.view.render("private", ["username": user.username, "title": "Private Area"])
    }
    
    protected.post("logout") { req -> Response in
        req.session.destroy()
        return req.redirect(to: "/")
    }
    
    authSessionRoutes.get("makeCredential") { req -> MakeCredentialResponse in
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
    authSessionRoutes.post("makeCredential") { req -> HTTPStatus in
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
        guard let authData = decodedAttestationObject["authData"], case let .byteString(authDataBytes) = authData else {
            throw Abort(.badRequest)
        }
        guard let credentialsData = try parseAttestationObject(authDataBytes, logger: req.logger) else {
            throw Abort(.badRequest)
        }
        guard let publicKeyObject = try CBOR.decode(credentialsData.publicKey) else {
            throw Abort(.badRequest)
        }
        // This is now in COSE format
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        guard let keyTypeRaw = publicKeyObject[.unsignedInt(1)], case let .unsignedInt(keyType) = keyTypeRaw else {
            throw Abort(.badRequest)
        }
        guard let algorithmRaw = publicKeyObject[.unsignedInt(3)], case let .negativeInt(algorithmNegative) = algorithmRaw else {
            throw Abort(.badRequest)
        }
        // https://github.com/unrelentingtech/SwiftCBOR#swiftcbor
        // Negative integers are decoded as NegativeInt(UInt), where the actual number is -1 - i
        let algorithm: Int = -1 - Int(algorithmNegative)
        
        // Curve is key -1 - or -0 for SwiftCBOR
        // X Coordinate is key -2, or NegativeInt 1 for SwiftCBOR
        // Y Coordinate is key -3, or NegativeInt 2 for SwiftCBOR
        
        guard let curveRaw = publicKeyObject[.negativeInt(0)], case let .unsignedInt(curve) = curveRaw else {
            throw Abort(.badRequest)
        }
        guard let xCoordRaw = publicKeyObject[.negativeInt(1)], case let .byteString(xCoordinateBytes) = xCoordRaw else {
            throw Abort(.badRequest)
        }
        guard let yCoordRaw = publicKeyObject[.negativeInt(2)], case let .byteString(yCoordinateBytes) = yCoordRaw else {
            throw Abort(.badRequest)
        }
        
        req.logger.debug("Key type was \(keyType)")
        req.logger.debug("Algorithm was \(algorithm)")
        req.logger.debug("Curve was \(curve)")
        
        let key = try P256.Signing.PublicKey(rawRepresentation: xCoordinateBytes + yCoordinateBytes)
        req.logger.debug("Key is \(key.pemRepresentation)")
        
        guard let username = req.session.data["username"], let userIDString = req.session.data["userID"], let userID = UUID(uuidString: userIDString) else {
            throw Abort(.badRequest)
        }
        
        let user = User(id: userID, username: username)
        try await user.save(on: req.db)
        
        let credentialID = Data(credentialsData.credentialID).base64EncodedString()
        let credential = WebAuthnCredential(id: credentialID, publicKey: key.pemRepresentation, userID: userID)
        try await credential.save(on: req.db)
        
        req.auth.login(user)
        
        return .ok
    }
    
    // step 1 for authentication
    authSessionRoutes.get("authentication_initialize") { req -> HTTPStatus in
        return .notImplemented
    }
    
    // step 2 for authentication
    authSessionRoutes.post("authentication_finalize") { req -> HTTPStatus in
        return .notImplemented
    }
    
    func parseAttestedData(_ data: [UInt8], logger: Logger) throws -> AttestedCredentialData {
        // We've parsed the first 37 bytes so far, the next bytes now should be the attested credential data
        // See https://w3c.github.io/webauthn/#sctn-attested-credential-data
        let aaguidLength = 16
        let aaguid = data[37..<(37 + aaguidLength)] // To byte at index 52
        
        let idLengthBytes = data[53..<55] // Length is 2 bytes
        let idLengthData = Data(idLengthBytes)
        let idLength: UInt16 = idLengthData.toInteger(endian: .big)
        let credentialIDEndIndex = Int(idLength) + 55
        
        let credentialID = data[55..<credentialIDEndIndex]
        let publicKeyBytes = data[credentialIDEndIndex...]
        
        return AttestedCredentialData(aaguid: Array(aaguid), credentialID: Array(credentialID), publicKey: Array(publicKeyBytes))
    }
    
    func parseAttestationObject(_ bytes: [UInt8], logger: Logger) throws -> AttestedCredentialData? {
        let minAuthDataLength = 37
        let minAttestedAuthLength = 55
        let maxCredentialIDLength = 1023
        // What to do when we don't have this
        var credentialsData: AttestedCredentialData? = nil
        
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
            let attestedCredentialData = try parseAttestedData(bytes, logger: logger)
            // 2 is the bytes storing the size of the credential ID
            let credentialDataLength = attestedCredentialData.aaguid.count + 2 + attestedCredentialData.credentialID.count + attestedCredentialData.publicKey.count
            remainingCount -= credentialDataLength
            credentialsData = attestedCredentialData
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
        return credentialsData
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

struct AttestedCredentialData {
    let aaguid: [UInt8]
    let credentialID: [UInt8]
    let publicKey: [UInt8]
}
