import Vapor
struct DecisionRequest: Content {
    let domain: String
    let password: String
    let hasPasskey: Bool
    let isBound: Bool
}
struct DecisionResponse: Content {
    let action: String
    let domain: String
    let note: String
}

struct HealthResponse: Content {
    let status: String
    let service: String
}

// SwiftPM uses main.swift as the executable entry point.
var environment = try Environment.detect()
try LoggingSystem.bootstrap(from: &environment)

let app = try await Application.make(environment)

// Render networking configuration
app.http.server.configuration.hostname = "0.0.0.0"
app.http.server.configuration.port =
    Environment.get("PORT").flatMap(Int.init) ?? 8080

app.get { _ async -> HealthResponse in
    HealthResponse(
        status: "ok",
        service: "OpenAI Identity & Passkey Authentication Engine"
    )
}

app.get("health") { _ async -> HealthResponse in
    HealthResponse(status: "ok", service: "sign-trigger-swift")
}

app.post("auth", "decision") {
    request async throws -> DecisionResponse in

    let input = try request.content.decode(DecisionRequest.self)

    guard !input.domain.trimmingCharacters(
        in: .whitespacesAndNewlines
    ).isEmpty else {
        throw Abort(.badRequest, reason: "domain must not be empty")
    }

    let action = IdentitySystem().signInTrigger(
        domain: input.domain,
        password: input.password,
        hasPasskey: input.hasPasskey,
        isBound: input.isBound
    )

    return DecisionResponse(
        action: action,
        domain: input.domain,
        note: "Prototype decision only. No real WebAuthn verification or OIDC exchange is performed."
    )
}

do {
    try await app.execute()
} catch {
    app.logger.report(error: error)
    try? await app.asyncShutdown()
    throw error
}

try await app.asyncShutdown()
