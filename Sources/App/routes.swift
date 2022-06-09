import Fluent
import Vapor

func routes(_ app: Application) throws {
    app.get { req in
        return req.view.render("index", ["title": "Hello Vapor!"])
    }
    
    app.get("makeCredential") { req -> MakeCredentialResponse in
        let username = try req.query.get(String.self, at: "username")
        let userID = UUID()
        let challenge = [UInt8].random(count: 32).base64
        req.session.data["challenge"] = challenge
        req.session.data["username"] = username
        req.session.data["userID"] = userID.uuidString
        return MakeCredentialResponse(userID: userID.uuidString.base64String(), challenge: challenge)
    }
    
    // step 2 for registration
    app.post("registration_finalize") { req -> HTTPStatus in
        return .notImplemented
    }

    // step 1 for authentication
    app.get("authentication_initialize") { req -> HTTPStatus in
        return .notImplemented
    }
    
    // step 2 for authentication
    app.post("authentication_finalize") { req -> HTTPStatus in
        return .notImplemented
    }
}

struct MakeCredentialResponse: Content {
    let userID: String
    let challenge: String
}
