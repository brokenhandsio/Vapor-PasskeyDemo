import Vapor

struct MakeCredentialResponse: Content {
    let userID: String
    let challenge: String
}
