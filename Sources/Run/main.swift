import Vapor
import Fluent
import FluentPostgresDriver

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
app.http.server.configuration.hostname = "0.0.0.0"
app.http.server.configuration.port = Environment.get("PORT").flatMap(Int.init) ?? 8080

// Persistent authentication routes are enabled only with a configured PostgreSQL URL.
// If the database is configured but unavailable, startup fails rather than silently
// falling back to process-local storage.
if let databaseURL = Environment.get("DATABASE_URL") {
    app.databases.use(.postgres(url: databaseURL), as: .psql)
    app.migrations.add(CreateAuthPlatformTables())
    try await app.autoMigrate()
}

registerProductionAuthRoutes(app)

app.get { _ async -> HealthResponse in
    HealthResponse(status: "ok", service: "AuthPlatform API")
}

app.get("health") { _ async -> HealthResponse in
    HealthResponse(status: "ok", service: "AuthPlatform API liveness")
}

app.get("ready") { _ async -> HealthResponse in
    let ready = Environment.get("DATABASE_URL") != nil
        && Environment.get("WORKOS_CLIENT_ID") != nil
        && Environment.get("WORKOS_REDIRECT_URI_IOS") != nil
        && Environment.get("AUTHPLATFORM_PUBLIC_BASE_URL") != nil
        && Environment.get("AUTHPLATFORM_DEVICE_VERIFICATION_URL") != nil
        && Environment.get("AUTHPLATFORM_OAUTH_CLIENT_ID") != nil
    return HealthResponse(status: ready ? "ready" : "not_ready", service: "AuthPlatform API readiness")
}

// Legacy prototype decision endpoint retained for compatibility.
// It does not authenticate users or perform WebAuthn/OIDC verification.
app.post("auth", "decision") { request async throws -> DecisionResponse in
    let input = try request.content.decode(DecisionRequest.self)
    guard !input.domain.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
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
        note: "Prototype decision only. Use /v1/auth/exchange and authenticated AuthPlatform endpoints for the production identity flow."
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
