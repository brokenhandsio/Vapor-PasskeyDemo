import Vapor

struct StartAuthenticateResponse: Content {
    let challenge: String
    let credentials: [WebAuthnCredential]
}
