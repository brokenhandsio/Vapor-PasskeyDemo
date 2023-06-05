import Fluent
import FluentSQLiteDriver
import Leaf
import Vapor
import WebAuthn

// configures your application
public func configure(_ app: Application) throws {
    // uncomment to serve files from /Public folder
    app.middleware.use(FileMiddleware(publicDirectory: app.directory.publicDirectory))
    app.middleware.use(app.sessions.middleware)

    app.databases.use(.sqlite(.file(Environment.get("SQLITE_DATABASE_PATH") ?? "db.sqlite")), as: .sqlite)

    app.migrations.add(CreateUser())
    app.migrations.add(CreateWebAuthnCredential())

    app.views.use(.leaf)
    app.webAuthn = WebAuthnManager(
        config: WebAuthnConfig(
            relyingPartyDisplayName: Environment.get("RP_DISPLAY_NAME") ?? "Vapor Passkey Demo",
            relyingPartyID: Environment.get("RP_ID") ?? "localhost",
            relyingPartyOrigin: Environment.get("RP_ORIGIN") ?? "http://localhost:8080"
        )
    )

    // register routes
    try routes(app)

    try app.autoMigrate().wait()
}
