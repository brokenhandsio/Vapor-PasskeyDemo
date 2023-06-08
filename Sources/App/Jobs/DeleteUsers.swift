import Vapor
import Queues
import Fluent

struct DeleteUsersJob: AsyncScheduledJob {
    func run(context: QueueContext) async throws {
        let dateTwoHoursAgo = Date().addingTimeInterval(-3600 * 2)
        let users = try await User.query(on: context.application.db)
            .filter(\.$createdAt < dateTwoHoursAgo)
            .all()
        try await users.delete(on: context.application.db)
        context.logger.info("Deleted \(users.count) users")
    }
}
