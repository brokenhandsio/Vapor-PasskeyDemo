import Fluent
import Vapor
import WebAuthn

func routes(_ app: Application) throws {
    app.get { req in
        return req.view.render("index", ["title": "Log In"])
    }

    app.get(".well-known", "apple-app-site-association") { req -> Response in
        let appIdentifier = "YWLW23LT6G.io.brokenhands.demos.auth.Shiny"
        let responseString =
            """
            {
                "applinks": {
                    "details": [
                        {
                            "appIDs": [
                                "\(appIdentifier)"
                            ],
                            "components": [
                            ]
                        }
                    ]
                },
                "webcredentials": {
                    "apps": [
                        "\(appIdentifier)"
                    ]
                }
            }
            """
        let response = try await responseString.encodeResponse(for: req)
        response.headers.contentType = HTTPMediaType(type: "application", subType: "json")
        return response
    }

    let authSessionRoutes = app.grouped(User.sessionAuthenticator())

    let protected = authSessionRoutes.grouped(User.redirectMiddleware(path: "/"))

    protected.get("private") { req -> View in
        let user = try req.auth.require(User.self)
        return try await req.view.render("private", ["username": user.username, "title": "Private Area"])
    }

    protected.post("logout") { req -> Response in
        req.session.destroy()
        req.auth.logout(User.self)
        return req.redirect(to: "/")
    }

    authSessionRoutes.get("signup", use: { req -> Response in
        let username = try req.query.get(String.self, at: "username")
        guard try await User.query(on: req.db).filter(\.$username == username).first() == nil else {
            throw Abort(.conflict, reason: "Username already taken.")
        }
        let user = User(username: username)
        try await user.create(on: req.db)
        req.auth.login(user)
        return req.redirect(to: "makeCredential")
    })

    // step 1 for registration
    authSessionRoutes.get("makeCredential") { (req: Request) -> PublicKeyCredentialCreationOptions in
        // In order to create a credential we need to know who the user is
        let user = try req.auth.require(User.self)

        // We can then create the options for the client to create a new credential
        let options = req.webAuthn.beginRegistration(user: user.webAuthnUser)

        // We need to temporarily store the challenge somewhere safe
        let registrationSessionID = UUID().uuidString
        req.session.data["registrationSessionID"] = registrationSessionID
        try await req.cache.set(registrationSessionID, to: options.challenge)

        // Return the options to the client
        return options
    }

    authSessionRoutes.delete("makeCredential") { req -> HTTPStatus in
        let user = try req.auth.require(User.self)
        try await user.delete(on: req.db)
        return .noContent
    }

    // step 2 for registration
    authSessionRoutes.post("makeCredential") { req -> HTTPStatus in
        // Obtain the user we're registering a credential for
        let user = try req.auth.require(User.self)

        // Obtain the challenge we stored on the server for this session
        guard let registrationSessionID = req.session.data["registrationSessionID"],
            let challenge = try await req.cache.get(registrationSessionID, as: [UInt8].self) else {
            throw Abort(.badRequest, reason: "Missing registration session ID")
        }

        // Delete the challenge from the server to prevent attackers from reusing it
        try await req.cache.delete(registrationSessionID)

        // Verify the credential the client sent us
        let credential = try await req.webAuthn.finishRegistration(
            challenge: challenge,
            credentialCreationData: req.content.decode(RegistrationCredential.self),
            confirmCredentialIDNotRegisteredYet: { credentialID in
                let existingCredential = try await WebAuthnCredential.query(on: req.db)
                    .filter(\.$id == credentialID)
                    .first()
                return existingCredential == nil
            }
        )

        // If the credential was verified, save it to the database
        try await WebAuthnCredential(from: credential, userID: user.requireID()).save(on: req.db)

        return .ok
    }

    // step 1 for authentication
    authSessionRoutes.get("authenticate") { req -> PublicKeyCredentialRequestOptions in
        let options = try req.webAuthn.beginAuthentication()

        let authSessionID = UUID().uuidString
        req.session.data["authSessionID"] = authSessionID
        try await req.cache.set(authSessionID, to: options.challenge)

        return options
    }

    // step 2 for authentication
    authSessionRoutes.post("authenticate") { req -> HTTPStatus in
        // Obtain the challenge we stored on the server for this session
        guard let authSessionID = req.session.data["authSessionID"],
            let challenge = try await req.cache.get(authSessionID, as: [UInt8].self) else {
            throw Abort(.badRequest, reason: "Missing auth session ID")
        }

        // Delete the challenge from the server to prevent attackers from reusing it
        try await req.cache.delete(authSessionID)

        // Decode the credential the client sent us
        let authenticationCredential = try req.content.decode(AuthenticationCredential.self)

        // find the credential the stranger claims to possess
        guard let credential = try await WebAuthnCredential.query(on: req.db)
            .filter(\.$id == authenticationCredential.id.urlDecoded.asString())
            .with(\.$user)
            .first() else {
            throw Abort(.unauthorized)
        }

        // if we found a credential, use the stored public key to verify the challenge
        let verifiedAuthentication = try req.webAuthn.finishAuthentication(
            credential: authenticationCredential,
            expectedChallenge: challenge,
            credentialPublicKey: [UInt8](URLEncodedBase64(credential.publicKey).urlDecoded.decoded!),
            credentialCurrentSignCount: credential.currentSignCount
        )

        // if we successfully verified the user, update the sign count
        credential.currentSignCount = verifiedAuthentication.newSignCount
        try await credential.save(on: req.db)

        // finally authenticate the user
        req.auth.login(credential.user)
        return .ok
    }
}

extension PublicKeyCredentialCreationOptions: AsyncResponseEncodable {
    public func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        return try Response(status: .ok, headers: headers, body: .init(data: JSONEncoder().encode(self)))
    }
}

extension PublicKeyCredentialRequestOptions: AsyncResponseEncodable {
    public func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        return try Response(status: .ok, headers: headers, body: .init(data: JSONEncoder().encode(self)))
    }
}
