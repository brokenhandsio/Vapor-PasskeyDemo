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

    authSessionRoutes.get("makeCredential") { req -> PublicKeyCredentialCreationOptions in
        let user = try req.auth.require(User.self)
        let options = try req.webAuthn.beginRegistration(user: user, attestation: .none)
        req.session.data["challenge"] = options.challenge.asString()
        return options
    }

    authSessionRoutes.delete("makeCredential") { req -> HTTPStatus in
        let user = try req.auth.require(User.self)
        try await user.delete(on: req.db)
        return .noContent
    }

    // step 2 for registration
    authSessionRoutes.post("makeCredential") { req -> HTTPStatus in
        let user = try req.auth.require(User.self)
        guard let challenge = req.session.data["challenge"] else { throw Abort(.unauthorized) }

        let credential = try await req.webAuthn.finishRegistration(
            challenge: EncodedBase64(challenge),
            credentialCreationData: req.content.decode(RegistrationCredential.self),
            confirmCredentialIDNotRegisteredYet: { credentialID in
                let existingCredential = try await WebAuthnCredential.query(on: req.db)
                    .filter(\.$id == credentialID)
                    .first()
                return existingCredential == nil
            }
        )

        try await WebAuthnCredential(from: credential, userID: user.requireID()).save(on: req.db)

        return .ok
    }

    // step 1 for authentication
    authSessionRoutes.get("authenticate") { req -> PublicKeyCredentialRequestOptions in
        // if the user specified a username, we'll fetch a list of saved credentials for that user
        var allowCredentials: [PublicKeyCredentialDescriptor]?
        if let username = req.query[String.self, at: "username"] {
            guard let user = try await User.query(on: req.db).filter(\.$username == username).first() else {
                throw Abort(.badRequest, reason: "User does not exist")
            }

            let credentials = try await user.$credentials.get(on: req.db)
            allowCredentials = credentials.map {
                let idData = [UInt8](URLEncodedBase64($0.id!).urlDecoded.decoded!)
                return PublicKeyCredentialDescriptor(type: "public-key", id: idData)
            }
            guard allowCredentials!.count > 0 else {
                throw Abort(.badRequest, reason: "User has no registered credentials")
            }
        }

        let options = try req.webAuthn.beginAuthentication(allowCredentials: allowCredentials)
        req.session.data["challenge"] = options.challenge.asString()

        return options
    }

    // step 2 for authentication
    authSessionRoutes.post("authenticate") { req -> HTTPStatus in
        guard let challenge = req.session.data["challenge"] else { throw Abort(.unauthorized) }
        let authenticationCredential = try req.content.decode(AuthenticationCredential.self)

        // find the credential the stranger claims to possess
        guard let credential = try await WebAuthnCredential.query(on: req.db)
            .filter(\.$id == authenticationCredential.id.asString())
            .with(\.$user)
            .first() else {
            throw Abort(.unauthorized)
        }

        // if we found a credential, use the stored public key to verify the challenge
        let verifiedAuthentication = try req.webAuthn.finishAuthentication(
            credential: authenticationCredential,
            expectedChallenge: EncodedBase64(challenge).urlEncoded,
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

extension RegistrationCredential: Content {}
extension AuthenticationCredential: Content {}
extension PublicKeyCredentialCreationOptions: Content {}
extension PublicKeyCredentialRequestOptions: Content {}