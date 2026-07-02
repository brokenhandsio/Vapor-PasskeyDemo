import Testing
@testable import App
import VaporTesting

@Suite(.serialized)
struct AppTests {

    private func sessionCookie(from response: TestingHTTPResponse) -> String {
        response.headers.first(name: "Set-Cookie")
            .flatMap { $0.split(separator: ";").first.map(String.init) }
            ?? ""
    }

    // MARK: - Public routes

    @Test func index() async throws {
        try await withApp(configure: configure) { app in
            try await app.testing().test(.GET, "/") { res async in
                #expect(res.status == .ok)
            }
        }
    }

    @Test func appleAppSiteAssociation() async throws {
        try await withApp(configure: configure) { app in
            try await app.testing().test(.GET, "/.well-known/apple-app-site-association") { res async in
                #expect(res.status == .ok)
                #expect(res.headers.contentType?.type == "application")
                #expect(res.headers.contentType?.subType == "json")
            }
        }
    }

    // MARK: - Auth-protected routes

    @Test func privateRedirectsWhenUnauthenticated() async throws {
        try await withApp(configure: configure) { app in
            try await app.testing().test(.GET, "/private") { res async in
                #expect(res.status == .seeOther)
                #expect(res.headers.first(name: "Location") == "/")
            }
        }
    }

    @Test func makeCredentialRequiresAuth() async throws {
        try await withApp(configure: configure) { app in
            try await app.testing().test(.GET, "/makeCredential") { res async in
                #expect(res.status == .unauthorized)
            }
        }
    }

    // MARK: - Signup

    @Test func signupCreatesUserAndRedirects() async throws {
        try await withApp(configure: configure) { app in
            try await app.testing().test(.GET, "/signup?username=\(UUID().uuidString)") { res async in
                #expect(res.status == .seeOther)
                #expect(res.headers.first(name: "Location") == "makeCredential")
            }
        }
    }

    @Test func signupRejectsDuplicateUsername() async throws {
        try await withApp(configure: configure) { app in
            let tester = try app.testing()
            let username = UUID().uuidString

            try await tester.test(.GET, "/signup?username=\(username)") { res async in
                #expect(res.status == .seeOther)
            }
            try await tester.test(.GET, "/signup?username=\(username)") { res async in
                #expect(res.status == .conflict)
            }
        }
    }

    // MARK: - Registration flow

    @Test func makeCredentialReturnsOptionsWhenAuthenticated() async throws {
        try await withApp(configure: configure) { app in
            let tester = try app.testing()
            let signupRes = try await tester.sendRequest(.GET, "/signup?username=\(UUID().uuidString)")
            let cookie = sessionCookie(from: signupRes)

            try await tester.test(.GET, "/makeCredential", beforeRequest: { req in
                req.headers.add(name: "Cookie", value: cookie)
            }, afterResponse: { res async in
                #expect(res.status == .ok)
                #expect(res.headers.contentType?.type == "application")
                #expect(res.headers.contentType?.subType == "json")
            })
        }
    }

    // MARK: - Authentication

    @Test func beginAuthenticationReturnsChallenge() async throws {
        try await withApp(configure: configure) { app in
            try await app.testing().test(.GET, "/authenticate") { res async in
                #expect(res.status == .ok)
                #expect(res.headers.contentType?.type == "application")
                #expect(res.headers.contentType?.subType == "json")
                #expect(res.body.string.contains("\"challenge\""))
            }
        }
    }

    // MARK: - Logout

    @Test func logoutDestroysSession() async throws {
        try await withApp(configure: configure) { app in
            let tester = try app.testing()
            let signupRes = try await tester.sendRequest(.GET, "/signup?username=\(UUID().uuidString)")
            let cookie = sessionCookie(from: signupRes)

            // Confirm the session is active
            try await tester.test(.GET, "/makeCredential", beforeRequest: { req in
                req.headers.add(name: "Cookie", value: cookie)
            }, afterResponse: { res async in
                #expect(res.status == .ok)
            })

            // Log out
            try await tester.test(.POST, "/logout", beforeRequest: { req in
                req.headers.add(name: "Cookie", value: cookie)
            }, afterResponse: { res async in
                #expect(res.status == .seeOther)
                #expect(res.headers.first(name: "Location") == "/")
            })

            // The old session cookie should no longer authenticate
            try await tester.test(.GET, "/makeCredential", beforeRequest: { req in
                req.headers.add(name: "Cookie", value: cookie)
            }, afterResponse: { res async in
                #expect(res.status == .unauthorized)
            })
        }
    }
}
