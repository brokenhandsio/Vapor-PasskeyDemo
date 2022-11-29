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

    authSessionRoutes.get("makeCredential") { req -> PublicKeyCredentialCreationOptions in
        let username = try req.query.get(String.self, at: "username")

        let user = User(username: username)
        try await user.save(on: req.db)

        let (options, sessionData) = try req.webAuthn.beginRegistration(user: user)

        req.logger.debug("Challenge is \(options.challenge)")

        req.session.data["challenge"] = sessionData.challenge
        req.session.data["userID"] = sessionData.userID

        return options
    }

    // step 2 for registration
    authSessionRoutes.post("makeCredential") { req -> HTTPStatus in
        guard let challenge = req.session.data["challenge"] else {
            throw Abort(.unauthorized)
        }
        let registerData = try req.content.decode(RegistrationResponse.self)

        guard let origin = Environment.get("ORIGIN") else {
            throw Abort(.internalServerError)
        }

        let credential = try req.webAuthn.parseRegisterCredentials(registerData, challengeProvided: challenge, origin: origin, logger: req.logger)

        guard let userIDString = req.session.data["userID"],
            let userID = UUID(uuidString: userIDString),
            let user = try await User.find(userID, on: req.db) else {
            throw Abort(.badRequest)
        }

        let webAuthnCredential = WebAuthnCredential(id: credential.credentialID, publicKey: credential.publicKey.pemRepresentation, userID: userID)
        try await webAuthnCredential.save(on: req.db)

        req.auth.login(user)

        return .ok
    }

    // step 1 for authentication
    authSessionRoutes.get("authenticate") { req -> StartAuthenticateResponse in
        let username = try req.query.get(String.self, at: "username")
        guard let user = try await User.query(on: req.db).filter(\.$username == username).first() else {
            throw Abort(.unauthorized)
        }
        let challenge = try req.webAuthn.generateChallengeString()
        let encodedChallenge = challenge.base64URLEncodedString()
        req.logger.debug("Authenticate Challenge is \(encodedChallenge)")
        req.session.data["challenge"] = encodedChallenge
        req.session.data["userID"] = try user.requireID().uuidString
        let credentials = try await user.$credentials.get(on: req.db).map { credential -> WebAuthnCredential in
            // We need to convert the IDs to base64 encoded from base64 URL encoded
            var id = String.base64(fromBase64URLEncoded: credential.id!)
            while id.count % 4 != 0 {
                id = id.appending("=")
            }
            return WebAuthnCredential(id: id, publicKey: credential.publicKey, userID: credential.$user.id)
        }
        return StartAuthenticateResponse(challenge: challenge.base64String(), credentials: credentials)
    }

    // step 2 for authentication
    authSessionRoutes.post("authenticate") { req -> HTTPStatus in
        guard let challenge = req.session.data["challenge"], let userIDString = req.session.data["userID"], let userID = UUID(uuidString: userIDString) else {
            throw Abort(.unauthorized)
        }
        let data = try req.content.decode(AuthenticationResponse.self)
        guard let credential = try await WebAuthnCredential.query(on: req.db).filter(\.$id == data.id).with(\.$user).first(), credential.$user.id == userID else {
            throw Abort(.unauthorized)
        }
        let publicKey = try P256.Signing.PublicKey(pemRepresentation: credential.publicKey)
        try req.webAuthn.verifyAuthenticationResponse(
            data,
            expectedChallenge: challenge,
            publicKey: publicKey,
            logger: req.logger
        )
        req.auth.login(credential.user)
        return .ok
    }
}

extension RegistrationResponse: Content {}
extension AuthenticationResponse: Content {}
extension PublicKeyCredentialCreationOptions: Content {}