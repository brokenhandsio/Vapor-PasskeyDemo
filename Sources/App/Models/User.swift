import Fluent
import Vapor

final class User: Model, Content {
    static let schema: String = "users"
    
    @ID
    var id: UUID?
    
    @Field(key: "username")
    var username: String
    
    init() {}
    
    init(username: String) {
        self.username = username
    }
}
