import Fluent
import Vapor
import WebAuthn

final class User: Model, Content {
    static let schema: String = "users"

    @ID
    var id: UUID?

    @Field(key: "username")
    var username: String

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Children(for: \.$user)
    var credentials: [WebAuthnCredential]

    init() {}

    init(id: UUID? = nil, username: String) {
        self.id = id
        self.username = username
    }
}

extension User {
    var webAuthnUser: PublicKeyCredentialUserEntity {
        PublicKeyCredentialUserEntity(id: [UInt8](id!.uuidString.utf8), name: username, displayName: username)
    }
}

extension User: ModelSessionAuthenticatable {}
