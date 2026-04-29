import App
import Logging
import NIOCore
import NIOPosix
import Vapor

var env = try Environment.detect()
try LoggingSystem.bootstrap(from: &env)
let app = try await Application.make(env)

do {
    try await configure(app)
} catch {
    app.logger.report(error: error)
    try? await app.asyncShutdown()
    throw error
}

try await app.execute()
try await app.asyncShutdown()
