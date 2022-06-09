import Fluent
import Vapor

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
