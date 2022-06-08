import Fluent
import Vapor

func routes(_ app: Application) throws {
    app.get { req in
        return req.view.render("index", ["title": "Hello Vapor!"])
    }
    
    // step 1 for registration
    app.get("registration_initialize") { req -> HTTPStatus in
        return .notImplemented
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
