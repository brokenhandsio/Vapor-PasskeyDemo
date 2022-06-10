import Fluent
import Vapor

final class WebAuthnCredential: Model, Content {
    static let schema = "webauth_credentals"
    
    @ID(custom: "id", generatedBy: .user)
    var id: String?
    
    @Field(key: "public_key")
    var publicKey: String
    
    @Parent(key: "user_id")
    var user: User
    
    init() {}
    
    init(id: String, publicKey: String, userID: UUID) {
        self.id = id
        self.publicKey = publicKey
        self.$user.id = userID
    }
}
