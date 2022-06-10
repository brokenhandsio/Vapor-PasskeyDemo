import Fluent
import Vapor
import WebAuthn

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
        let registerData = try req.content.decode(RegisterWebAuthnCredentialData.self)
        
        guard let origin = Environment.get("ORIGIN") else {
            throw Abort(.internalServerError)
        }
        
        let credential = try WebAuthn.parseRegisterCredentials(registerData, challengeProvided: challenge, origin: origin, logger: req.logger)
        
        guard let username = req.session.data["username"], let userIDString = req.session.data["userID"], let userID = UUID(uuidString: userIDString) else {
            throw Abort(.badRequest)
        }
        
        let user = User(id: userID, username: username)
        try await user.save(on: req.db)
        
        let credential = WebAuthnCredential(id: credential.credentialID, publicKey: credential.publicKey.pemRepresentation, userID: userID)
        try await credential.save(on: req.db)
        
        req.auth.login(user)
        
        return .ok
    }
    
    // step 1 for authentication
    authSessionRoutes.get("authenticate") { req -> StartAuthenticateResponse in
        let username = try req.query.get(String.self, at: "username")
        guard let user = try await User.query(on: req.db).filter(\.$username == username).first() else {
            throw Abort(.unauthorized)
        }
        let challenge = [UInt8].random(count: 32).base64
        let encodedChallenge = challenge.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        req.logger.debug("Authenticate Challenge is \(encodedChallenge)")
        req.session.data["challenge"] = encodedChallenge
        req.session.data["userID"] = try user.requireID().uuidString
        let credentials = try await user.$credentials.get(on: req.db).map {
            // We need to convert the IDs to base64 encoded from base64 URL encoded
            var id = $0.id!.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            while id.count % 4 != 0 {
                id = id.appending("=")
            }
            return WebAuthnCredential(id: id, publicKey: $0.publicKey, userID: $0.$user.id)
        }
        return StartAuthenticateResponse(challenge: challenge, credentials: credentials)
    }
    
    // step 2 for authentication
    authSessionRoutes.post("authenticate") { req -> HTTPStatus in
        guard let challenge = req.session.data["challenge"], let userIDString = req.session.data["userID"], let userID = UUID(uuidString: userIDString) else {
            throw Abort(.unauthorized)
        }
        let data = try req.content.decode(AssertionCredential.self)
        guard let credential = try await WebAuthnCredential.query(on: req.db).filter(\.$id == data.id).with(\.$user).first(), credential.$user.id == userID else {
            throw Abort(.unauthorized)
        }
        let publicKey = try P256.Signing.PublicKey(pemRepresentation: credential.publicKey)
        try WebAuthn.validateAssertion(data, challengeProvided: challenge, publicKey: publicKey, logger: req.logger)
        req.auth.login(credential.user)
        return .ok
    }
}

extension RegisterWebAuthnCredentialData: Content {}
extension AssertionCredential: Content {}
