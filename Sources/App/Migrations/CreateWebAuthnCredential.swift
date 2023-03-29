import Fluent

struct CreateWebAuthnCredential: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("webauth_credentals")
            .field("id", .string, .identifier(auto: false))
            .field("public_key", .string, .required)
            .field("current_sign_count", .uint32, .required)
            .field("user_id", .uuid, .required, .references("users", "id"))
            .unique(on: "id")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("webauth_credentals").delete()
    }
}
