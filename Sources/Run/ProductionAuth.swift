import Foundation
import Vapor
import Fluent
import FluentPostgresDriver
import JWTKit
import Crypto
import SQLKit
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Configuration and cryptographic helpers

enum AuthConfig {
    static var workOSClientID: String? { Environment.get("WORKOS_CLIENT_ID") }
    static var iosRedirectURI: String? { Environment.get("WORKOS_REDIRECT_URI_IOS") }
    static var webRedirectURI: String? {
        Environment.get("WORKOS_REDIRECT_URI_WEB")
            ?? publicBaseURL.map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/device/callback" }
    }
    static var publicBaseURL: String? { Environment.get("AUTHPLATFORM_PUBLIC_BASE_URL") }
    static var deviceVerificationURL: String? { Environment.get("AUTHPLATFORM_DEVICE_VERIFICATION_URL") }
    static var telegramSecret: String? { Environment.get("TELEGRAM_BOT_SHARED_SECRET") }
    static var oauthClientID: String? { Environment.get("AUTHPLATFORM_OAUTH_CLIENT_ID") }
    static var allowedScopes: Set<String> {
        Set((Environment.get("AUTHPLATFORM_ALLOWED_SCOPES") ?? "devices:read devices:write").split(separator: " ").map(String.init))
    }
}

enum SecureValues {
    static func random(_ count: Int = 32) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    static func hash(_ value: String) -> String {
        SecureValues.base64URL(Data(SHA256.hash(data: Data(value.utf8))))
    }

    static func userCode() -> String {
        let alphabet = Array("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")
        var generator = SystemRandomNumberGenerator()
        return String((0..<8).map { _ in alphabet.randomElement(using: &generator)! })
    }

    static func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
        let a = Array(lhs.utf8), b = Array(rhs.utf8)
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for index in a.indices { difference |= a[index] ^ b[index] }
        return difference == 0
    }
}

// MARK: - WorkOS AuthKit JWT verification

private struct WorkOSDiscovery: Decodable {
    let issuer: String
    let jwks_uri: URL
}

private enum JWTExpectedAudience: Codable {
    case one(String)
    case many([String])

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(String.self) { self = .one(value) }
        else { self = .many(try container.decode([String].self)) }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .one(let value): try container.encode(value)
        case .many(let values): try container.encode(values)
        }
    }

    func contains(_ value: String) -> Bool {
        switch self {
        case .one(let item): return item == value
        case .many(let items): return items.contains(value)
        }
    }
}

private struct WorkOSClaims: JWTPayload {
    let iss: String
    let sub: String
    let aud: JWTExpectedAudience
    let exp: Double
    let nbf: Double?

    func verify(using algorithm: some JWTAlgorithm) throws {
        guard !sub.isEmpty, exp > Date().timeIntervalSince1970 else {
            throw Abort(.unauthorized, reason: "Invalid or expired WorkOS session")
        }
        if let nbf, nbf > Date().timeIntervalSince1970 {
            throw Abort(.unauthorized, reason: "WorkOS session is not active yet")
        }
    }
}

actor WorkOSJWTVerifier {
    static let shared = WorkOSJWTVerifier()
    private var keys: JWTKeyCollection?
    private var issuer: String?
    private var expiresAt = Date.distantPast

    func subject(from token: String, clientID: String) async throws -> String {
        if keys == nil || Date() >= expiresAt {
            let discoveryURL = URL(string: "https://api.workos.com/user_management/\(clientID)/.well-known/openid-configuration")!
            let (discoveryData, _) = try await URLSession.shared.data(from: discoveryURL)
            let discovery = try JSONDecoder().decode(WorkOSDiscovery.self, from: discoveryData)
            let (jwksData, _) = try await URLSession.shared.data(from: discovery.jwks_uri)
            guard let jwks = String(data: jwksData, encoding: .utf8) else {
                throw Abort(.serviceUnavailable, reason: "WorkOS signing keys could not be decoded")
            }
            keys = try await JWTKeyCollection().add(jwksJSON: jwks)
            issuer = discovery.issuer
            expiresAt = Date().addingTimeInterval(300)
        }

        // Reject unsigned and symmetric tokens before consulting the JWKS.
        let segments = token.split(separator: ".")
        guard segments.count == 3,
              let headerData = Data(base64URL: String(segments[0])),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              let algorithm = header["alg"] as? String,
              ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"].contains(algorithm) else {
            throw Abort(.unauthorized, reason: "Unsupported WorkOS token")
        }

        guard let keys else { throw Abort(.serviceUnavailable) }
        let claims = try await keys.verify(token, as: WorkOSClaims.self)
        guard claims.iss == issuer, claims.aud.contains(clientID),
              claims.exp > Date().timeIntervalSince1970 else {
            throw Abort(.unauthorized, reason: "WorkOS issuer, audience, or expiry validation failed")
        }
        return claims.sub
    }
}

private extension Data {
    init?(base64URL value: String) {
        var normalized = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while normalized.count % 4 != 0 { normalized.append("=") }
        self.init(base64Encoded: normalized)
    }
}

// MARK: - Persistent models

final class AuthUser: Model {
    static let schema = "auth_users"
    @ID(key: .id) var id: UUID?
    @OptionalField(key: "workos_subject") var workosSubject: String?
    @Field(key: "created_at") var createdAt: Date
    init() {}
    init(workosSubject: String) { self.workosSubject = workosSubject; self.createdAt = Date() }
    init(telegramOnly: Bool) { self.workosSubject = nil; self.createdAt = Date() }
}

final class RegisteredDevice: Model, Content {
    static let schema = "registered_devices"
    @ID(key: .id) var id: UUID?
    @Field(key: "user_id") var userID: UUID
    @Field(key: "public_key") var publicKey: String
    @Field(key: "key_thumbprint") var keyThumbprint: String
    @Field(key: "label") var label: String
    @Field(key: "platform") var platform: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    init() {}
    init(userID: UUID, publicKey: String, thumbprint: String, label: String, platform: String) {
        self.userID = userID; self.publicKey = publicKey; self.keyThumbprint = thumbprint
        self.label = label; self.platform = platform; self.createdAt = Date()
    }
}

final class DeviceChallenge: Model {
    static let schema = "device_challenges"
    @ID(key: .id) var id: UUID?
    @Field(key: "user_id") var userID: UUID
    @Field(key: "challenge_hash") var challengeHash: String
    @Field(key: "public_key") var publicKey: String
    @Field(key: "label") var label: String
    @Field(key: "platform") var platform: String
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "consumed_at") var consumedAt: Date?
    init() {}
    init(userID: UUID, challenge: String, publicKey: String, label: String, platform: String) {
        self.userID = userID; self.challengeHash = SecureValues.hash(challenge)
        self.publicKey = publicKey; self.label = label; self.platform = platform
        self.expiresAt = Date().addingTimeInterval(300)
    }
}

final class DeviceGrant: Model {
    static let schema = "oauth_device_grants"
    @ID(key: .id) var id: UUID?
    @Field(key: "client_id") var clientID: String
    @Field(key: "device_code_hash") var deviceCodeHash: String
    @Field(key: "user_code_hash") var userCodeHash: String
    @Field(key: "scopes") var scopes: String
    @Field(key: "status") var status: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "poll_interval") var pollInterval: Int
    @OptionalField(key: "last_polled_at") var lastPolledAt: Date?
    @OptionalField(key: "user_id") var userID: UUID?
    @OptionalField(key: "consumed_at") var consumedAt: Date?
    init() {}
    init(clientID: String, deviceCode: String, userCode: String, scopes: [String]) {
        self.clientID = clientID; self.deviceCodeHash = SecureValues.hash(deviceCode)
        self.userCodeHash = SecureValues.hash(userCode); self.scopes = scopes.joined(separator: " ")
        self.status = "pending"; self.expiresAt = Date().addingTimeInterval(600); self.pollInterval = 5
    }
}

final class OAuthAccessToken: Model {
    static let schema = "oauth_access_tokens"
    @ID(key: .id) var id: UUID?
    @Field(key: "authorization_id") var authorizationID: UUID
    @Field(key: "user_id") var userID: UUID
    @Field(key: "token_hash") var tokenHash: String
    @Field(key: "expires_at") var expiresAt: Date
    init() {}
    init(authorizationID: UUID, userID: UUID, token: String) {
        self.authorizationID = authorizationID; self.userID = userID
        self.tokenHash = SecureValues.hash(token); self.expiresAt = Date().addingTimeInterval(3600)
    }
}

final class TelegramLinkChallenge: Model {
    static let schema = "telegram_link_challenges"
    @ID(key: .id) var id: UUID?
    @Field(key: "telegram_user_id") var telegramUserID: String
    @Field(key: "code_hash") var codeHash: String
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "claimed_at") var claimedAt: Date?
    init() {}
    init(telegramUserID: String, code: String) {
        self.telegramUserID = telegramUserID; self.codeHash = SecureValues.hash(code)
        self.expiresAt = Date().addingTimeInterval(600)
    }
}

final class TelegramLink: Model {
    static let schema = "telegram_links"
    @ID(key: .id) var id: UUID?
    @Field(key: "telegram_user_id") var telegramUserID: String
    @Field(key: "user_id") var userID: UUID
    @Field(key: "linked_at") var linkedAt: Date
    init() {}
    init(telegramUserID: String, userID: UUID) {
        self.telegramUserID = telegramUserID; self.userID = userID; self.linkedAt = Date()
    }
}

// MARK: - Database migration

struct CreateAuthPlatformTables: AsyncMigration {
    func prepare(on db: Database) async throws {
        try await db.schema("auth_users").id()
            .field("workos_subject", .string).field("created_at", .datetime, .required)
            .unique(on: "workos_subject").create()
        try await db.schema("registered_devices").id()
            .field("user_id", .uuid, .required).field("public_key", .string, .required)
            .field("key_thumbprint", .string, .required).field("label", .string, .required)
            .field("platform", .string, .required).field("created_at", .datetime, .required)
            .field("revoked_at", .datetime).unique(on: "key_thumbprint").create()
        try await db.schema("device_challenges").id()
            .field("user_id", .uuid, .required).field("challenge_hash", .string, .required)
            .field("public_key", .string, .required).field("label", .string, .required)
            .field("platform", .string, .required).field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime).unique(on: "challenge_hash").create()
        try await db.schema("oauth_device_grants").id()
            .field("client_id", .string, .required).field("device_code_hash", .string, .required)
            .field("user_code_hash", .string, .required).field("scopes", .string, .required)
            .field("status", .string, .required).field("expires_at", .datetime, .required)
            .field("poll_interval", .int, .required).field("last_polled_at", .datetime)
            .field("user_id", .uuid).field("consumed_at", .datetime)
            .unique(on: "device_code_hash").unique(on: "user_code_hash").create()
        try await db.schema("oauth_access_tokens").id()
            .field("authorization_id", .uuid, .required).field("user_id", .uuid, .required)
            .field("token_hash", .string, .required).field("expires_at", .datetime, .required)
            .unique(on: "authorization_id").unique(on: "token_hash").create()
        try await db.schema("telegram_link_challenges").id()
            .field("telegram_user_id", .string, .required).field("code_hash", .string, .required)
            .field("expires_at", .datetime, .required).field("claimed_at", .datetime)
            .unique(on: "code_hash").create()
        try await db.schema("telegram_links").id()
            .field("telegram_user_id", .string, .required).field("user_id", .uuid, .required)
            .field("linked_at", .datetime, .required).unique(on: "telegram_user_id").create()
    }

    func revert(on db: Database) async throws {
        for table in ["telegram_links", "telegram_link_challenges", "oauth_access_tokens",
                      "oauth_device_grants", "device_challenges", "registered_devices", "auth_users"] {
            try await db.schema(table).delete()
        }
    }
}


// Existing installations created workos_subject as NOT NULL. This additive migration
// makes the provider-specific subject optional without dropping existing WorkOS data.
struct MakeWorkOSSubjectNullable: AsyncMigration {
    func prepare(on db: Database) async throws {
        guard let sql = db as? any SQLDatabase else {
            throw Abort(.serviceUnavailable, reason: "SQL database is required for identity migration")
        }
        try await sql.raw("ALTER TABLE auth_users ALTER COLUMN workos_subject DROP NOT NULL").run()
    }

    func revert(on db: Database) async throws {
        guard let sql = db as? any SQLDatabase else {
            throw Abort(.serviceUnavailable, reason: "SQL database is required for identity migration")
        }
        try await sql.raw("UPDATE auth_users SET workos_subject = 'legacy:' || id::text WHERE workos_subject IS NULL").run()
        try await sql.raw("ALTER TABLE auth_users ALTER COLUMN workos_subject SET NOT NULL").run()
    }
}

// MARK: - Request and response contracts

private struct AuthExchangeRequest: Content { let code: String; let codeVerifier: String; let redirectURI: String }
private struct WorkOSAuthResponse: Content { let access_token: String; let refresh_token: String?; let expires_in: Int?; let token_type: String? }
private struct AuthExchangeResponse: Content { let accessToken: String; let refreshToken: String?; let expiresIn: Int?; let userID: UUID }
private struct ChallengeRequest: Content { let publicKey: String; let label: String; let platform: String }
private struct ChallengeResponse: Content { let challengeID: UUID; let challenge: String; let expiresIn: Int }
private struct BindRequest: Content { let challengeID: UUID; let challenge: String; let signature: String }
private struct DeviceListResponse: Content { let devices: [RegisteredDevice] }
private struct DeviceAuthorizationRequest: Content { let client_id: String; let scope: String? }
private struct DeviceAuthorizationResponse: Content {
    let device_code: String; let user_code: String; let verification_uri: String
    let verification_uri_complete: String; let expires_in: Int; let interval: Int
}
private struct DeviceApprovalRequest: Content { let user_code: String; let approve: Bool }
private struct TokenRequest: Content { let grant_type: String; let device_code: String; let client_id: String }
private struct OAuthTokenResponse: Content { let access_token: String; let token_type: String; let expires_in: Int; let scope: String }
private struct OAuthErrorResponse: Content { let error: String; let error_description: String }
private struct OAuthRevokeRequest: Content { let token: String; let client_id: String }
private struct AuthorizationServerMetadata: Content {
    let issuer: String
    let device_authorization_endpoint: String
    let token_endpoint: String
    let revocation_endpoint: String
    let grant_types_supported: [String]
    let response_types_supported: [String]
    let token_endpoint_auth_methods_supported: [String]
}
private struct TelegramChallengeRequest: Content { let telegram_user_id: String }
private struct TelegramChallengeResponse: Content { let code: String; let expires_in: Int }
private struct TelegramClaimRequest: Content { let code: String }
private struct TelegramDeviceSummary: Content {
    let id: UUID
    let label: String
    let platform: String
    let createdAt: Date
}
private struct TelegramDevicesResponse: Content { let devices: [TelegramDeviceSummary] }
private struct TelegramStatusResponse: Content { let status: String; let service: String }
private struct TelegramDeviceApprovalRequest: Content {
    let telegram_user_id: String
    let user_code: String
    let approve: Bool
}
private struct TelegramDeviceApprovalPreview: Content {
    let client_id: String
    let scopes: String
    let expires_at: Date
}


private func requireDatabase() throws {
    guard Environment.get("DATABASE_URL") != nil else {
        throw Abort(.serviceUnavailable, reason: "Persistent database is not configured")
    }
}

private func currentUser(_ req: Request) async throws -> AuthUser {
    try requireDatabase()
    let cookieHeader = req.headers.first(name: "Cookie") ?? ""
    let cookieToken = cookieHeader.split(separator: ";").compactMap { part -> String? in
        let pair = part.trimmingCharacters(in: .whitespaces).split(separator: "=", maxSplits: 1)
        return pair.count == 2 && pair[0] == "authplatform_session" ? String(pair[1]) : nil
    }.first
    guard let token = req.headers.bearerAuthorization?.token ?? cookieToken else {
        throw Abort(.unauthorized, reason: "A bearer token or browser session is required")
    }

    // WorkOS JWTs are accepted when WorkOS is configured. Telegram and device
    // sessions are opaque AuthPlatform tokens and must remain usable without it.
    if let clientID = AuthConfig.workOSClientID,
       let subject = try? await WorkOSJWTVerifier.shared.subject(from: token, clientID: clientID) {
        if let existing = try await AuthUser.query(on: req.db)
            .filter(\.$workosSubject == subject).first() {
            return existing
        }
        let user = AuthUser(workosSubject: subject)
        try await user.save(on: req.db)
        return user
    }

    let tokenHash = SecureValues.hash(token)
    guard let stored = try await OAuthAccessToken.query(on: req.db)
        .filter(\.$tokenHash == tokenHash).first(),
          stored.expiresAt > Date(),
          let user = try await AuthUser.find(stored.userID, on: req.db) else {
        throw Abort(.unauthorized, reason: "Invalid or expired bearer token")
    }
    return user
}

private func requireBrowserOrigin(_ req: Request) throws {
    let cookies = req.headers.first(name: "Cookie") ?? ""
    guard cookies.contains("authplatform_session=") else { return }
    guard let rawOrigin = req.headers.first(name: "Origin"),
          let origin = URL(string: rawOrigin),
          let expected = AuthConfig.publicBaseURL.flatMap { URL(string: $0) },
          origin.scheme == "https", origin.host == expected.host,
          origin.port == expected.port else {
        throw Abort(.forbidden, reason: "Browser approval origin validation failed")
    }
}

private func requireTelegramService(_ req: Request) throws {
    guard let expected = AuthConfig.telegramSecret,
          let supplied = req.headers.first(name: "X-AuthPlatform-Telegram-Secret"),
          SecureValues.constantTimeEqual(expected, supplied) else {
        throw Abort(.unauthorized, reason: "Telegram service authentication failed")
    }
}

private func oauthError(_ error: String, _ description: String, status: HTTPResponseStatus = .badRequest) -> Response {
    let response = Response(status: status)
    try? response.content.encode(OAuthErrorResponse(error: error, error_description: description))
    return response
}

// MARK: - Route registration

func registerProductionAuthRoutes(_ app: Application) {
    app.post("v1", "auth", "exchange") { req async throws -> AuthExchangeResponse in
        try requireDatabase()
        guard let clientID = AuthConfig.workOSClientID,
              let expectedRedirect = AuthConfig.iosRedirectURI else {
            throw Abort(.serviceUnavailable, reason: "WorkOS client and iOS redirect URI are not configured")
        }
        let input = try req.content.decode(AuthExchangeRequest.self)
        guard input.redirectURI == expectedRedirect else {
            throw Abort(.badRequest, reason: "redirect_uri does not match the registered iOS callback")
        }

        var request = URLRequest(url: URL(string: "https://api.workos.com/user_management/authenticate")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "client_id": clientID, "grant_type": "authorization_code",
            "code": input.code, "code_verifier": input.codeVerifier
        ])
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw Abort(.unauthorized, reason: "WorkOS rejected the authorization code exchange")
        }
        let tokens = try JSONDecoder().decode(WorkOSAuthResponse.self, from: data)
        let subject = try await WorkOSJWTVerifier.shared.subject(from: tokens.access_token, clientID: clientID)
        let user: AuthUser
        if let found = try await AuthUser.query(on: req.db).filter(\.$workosSubject == subject).first() {
            user = found
        } else {
            user = AuthUser(workosSubject: subject)
            try await user.save(on: req.db)
        }
        return AuthExchangeResponse(accessToken: tokens.access_token, refreshToken: tokens.refresh_token,
                                     expiresIn: tokens.expires_in, userID: user.id!)
    }

    app.post("v1", "devices", "challenges") { req async throws -> ChallengeResponse in
        let user = try await currentUser(req)
        let input = try req.content.decode(ChallengeRequest.self)
        guard let keyData = Data(base64Encoded: input.publicKey), keyData.count == 65,
              !input.label.isEmpty, !input.platform.isEmpty else {
            throw Abort(.badRequest, reason: "A valid uncompressed P-256 public key, label, and platform are required")
        }
        let nonce = SecureValues.base64URL(SecureValues.random())
        let challenge = DeviceChallenge(userID: user.id!, challenge: nonce,
                                        publicKey: input.publicKey, label: input.label, platform: input.platform)
        try await challenge.save(on: req.db)
        return ChallengeResponse(challengeID: challenge.id!, challenge: nonce, expiresIn: 300)
    }

    app.post("v1", "devices", "bind") { req async throws -> RegisteredDevice in
        let user = try await currentUser(req)
        let input = try req.content.decode(BindRequest.self)
        guard let challenge = try await DeviceChallenge.find(input.challengeID, on: req.db),
              challenge.userID == user.id, challenge.consumedAt == nil,
              challenge.expiresAt > Date(), SecureValues.hash(input.challenge) == challenge.challengeHash,
              let publicKeyData = Data(base64Encoded: challenge.publicKey),
              let signatureData = Data(base64Encoded: input.signature) else {
            throw Abort(.unauthorized, reason: "Challenge is invalid, expired, consumed, or not owned by this account")
        }
        let canonical = "AuthPlatform-Device-Bind-v1|\(user.id!.uuidString)|\(input.challengeID.uuidString)|\(input.challenge)"
        do {
            let key = try P256.Signing.PublicKey(rawRepresentation: publicKeyData)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
            guard key.isValidSignature(signature, for: Data(canonical.utf8)) else {
                throw Abort(.unauthorized, reason: "Device proof-of-possession signature is invalid")
            }
        } catch let abort as Abort { throw abort }
        catch { throw Abort(.unauthorized, reason: "Device public key or signature is malformed") }

        challenge.consumedAt = Date()
        try await challenge.save(on: req.db)
        let thumbprint = SecureValues.base64URL(Data(SHA256.hash(data: publicKeyData)))
        if try await RegisteredDevice.query(on: req.db).filter(\.$keyThumbprint == thumbprint).first() != nil {
            throw Abort(.conflict, reason: "This device key is already registered")
        }
        let device = RegisteredDevice(userID: user.id!, publicKey: challenge.publicKey,
                                      thumbprint: thumbprint, label: challenge.label, platform: challenge.platform)
        try await device.save(on: req.db)
        return device
    }

    app.get("v1", "devices") { req async throws -> DeviceListResponse in
        let user = try await currentUser(req)
        let devices = try await RegisteredDevice.query(on: req.db)
            .filter(\.$userID == user.id!).filter(\.$revokedAt == nil).all()
        return DeviceListResponse(devices: devices)
    }

    app.delete("v1", "devices", ":deviceID") { req async throws -> HTTPStatus in
        let user = try await currentUser(req)
        guard let raw = req.parameters.get("deviceID"), let id = UUID(uuidString: raw),
              let device = try await RegisteredDevice.find(id, on: req.db), device.userID == user.id else {
            throw Abort(.notFound)
        }
        device.revokedAt = Date()
        try await device.save(on: req.db)
        return .noContent
    }

    app.get(".well-known", "oauth-authorization-server") { req async throws -> AuthorizationServerMetadata in
        guard let baseURL = AuthConfig.publicBaseURL else { throw Abort(.serviceUnavailable) }
        let issuer = baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return AuthorizationServerMetadata(
            issuer: issuer,
            device_authorization_endpoint: issuer + "/oauth/device_authorization",
            token_endpoint: issuer + "/oauth/token",
            revocation_endpoint: issuer + "/oauth/revoke",
            grant_types_supported: ["urn:ietf:params:oauth:grant-type:device_code"],
            response_types_supported: [],
            token_endpoint_auth_methods_supported: ["none"]
        )
    }

    // Browser device-approval flow: WorkOS AuthKit authorization-code + PKCE.
    app.get("device", "login") { req async throws -> Response in
        guard let clientID = AuthConfig.workOSClientID,
              let redirectURI = AuthConfig.webRedirectURI,
              let authorizeBase = URL(string: "https://api.workos.com/user_management/authorize") else {
            throw Abort(.serviceUnavailable, reason: "WorkOS browser redirect configuration is incomplete")
        }
        let state = SecureValues.base64URL(SecureValues.random(32))
        let verifier = SecureValues.base64URL(SecureValues.random(48))
        let challenge = SecureValues.base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
        var components = URLComponents(url: authorizeBase, resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "provider", value: "authkit"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256")
        ]
        let response = Response(status: .seeOther)
        response.headers.replaceOrAdd(name: "Location", value: components.url!.absoluteString)
        response.headers.add(name: "Set-Cookie", value: "authplatform_oauth_state=\(state); Path=/device; Max-Age=600; Secure; HttpOnly; SameSite=Lax")
        response.headers.add(name: "Set-Cookie", value: "authplatform_oauth_verifier=\(verifier); Path=/device; Max-Age=600; Secure; HttpOnly; SameSite=Lax")
        return response
    }

    app.get("device", "callback") { req async throws -> Response in
        try requireDatabase()
        guard let clientID = AuthConfig.workOSClientID,
              let redirectURI = AuthConfig.webRedirectURI,
              let code = req.query[String.self, at: "code"],
              let returnedState = req.query[String.self, at: "state"] else {
            throw Abort(.badRequest, reason: "WorkOS callback is missing required parameters")
        }
        var cookies: [String: String] = [:]
        for item in (req.headers.first(name: "Cookie") ?? "").split(separator: ";") {
            let pair = item.trimmingCharacters(in: .whitespaces).split(separator: "=", maxSplits: 1)
            if pair.count == 2, cookies[String(pair[0])] == nil {
                cookies[String(pair[0])] = String(pair[1])
            }
        }
        guard let expectedState = cookies["authplatform_oauth_state"],
              SecureValues.constantTimeEqual(expectedState, returnedState),
              let verifier = cookies["authplatform_oauth_verifier"] else {
            throw Abort(.unauthorized, reason: "Browser sign-in state validation failed")
        }
        var exchange = URLRequest(url: URL(string: "https://api.workos.com/user_management/authenticate")!)
        exchange.httpMethod = "POST"
        exchange.setValue("application/json", forHTTPHeaderField: "Content-Type")
        exchange.httpBody = try JSONSerialization.data(withJSONObject: [
            "client_id": clientID, "grant_type": "authorization_code",
            "code": code, "code_verifier": verifier, "redirect_uri": redirectURI
        ])
        let (data, upstreamResponse) = try await URLSession.shared.data(for: exchange)
        guard (upstreamResponse as? HTTPURLResponse)?.statusCode == 200 else {
            throw Abort(.unauthorized, reason: "WorkOS browser authorization exchange failed")
        }
        let tokens = try JSONDecoder().decode(WorkOSAuthResponse.self, from: data)
        let subject = try await WorkOSJWTVerifier.shared.subject(from: tokens.access_token, clientID: clientID)
        let user: AuthUser
        if let existing = try await AuthUser.query(on: req.db).filter(\.$workosSubject == subject).first() {
            user = existing
        } else {
            user = AuthUser(workosSubject: subject)
            try await user.save(on: req.db)
        }
        let session = SecureValues.base64URL(SecureValues.random(40))
        try await OAuthAccessToken(authorizationID: UUID(), userID: user.id!, token: session).save(on: req.db)
        let response = Response(status: .seeOther)
        response.headers.replaceOrAdd(name: "Location", value: "/device")
        response.headers.add(name: "Set-Cookie", value: "authplatform_session=\(session); Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax")
        response.headers.add(name: "Set-Cookie", value: "authplatform_oauth_state=; Path=/device; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
        response.headers.add(name: "Set-Cookie", value: "authplatform_oauth_verifier=; Path=/device; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
        return response
    }

    app.get("device", "preview") { req async throws -> TelegramDeviceApprovalPreview in
        _ = try await currentUser(req)
        guard let rawCode = req.query[String.self, at: "user_code"] else {
            throw Abort(.badRequest, reason: "Device user code is required")
        }
        let code = rawCode.uppercased().filter { $0.isLetter || $0.isNumber }
        guard code.count == 8,
              let grant = try await DeviceGrant.query(on: req.db)
                .filter(\.$userCodeHash == SecureValues.hash(code)).first(),
              grant.status == "pending", grant.expiresAt > Date() else {
            throw Abort(.notFound, reason: "Device request is invalid, expired, or already handled")
        }
        return TelegramDeviceApprovalPreview(client_id: grant.clientID, scopes: grant.scopes, expires_at: grant.expiresAt)
    }

    app.get("device") { req async throws -> Response in
        guard req.headers.first(name: "Cookie")?.contains("authplatform_session=") == true else {
            let response = Response(status: .seeOther)
            response.headers.replaceOrAdd(name: "Location", value: "/device/login")
            return response
        }
        _ = try await currentUser(req)
        let html = """
        <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Approve device · AuthPlatform</title><style>
        body{font:16px system-ui;background:#f5f7fb;color:#172033;margin:0;display:grid;min-height:100vh;place-items:center}
        main{background:white;width:min(92vw,440px);padding:32px;border-radius:18px;box-shadow:0 12px 40px #18233a18}
        h1{font-size:25px;margin:0 0 8px}p{color:#536078;line-height:1.5}
        input{box-sizing:border-box;width:100%;padding:14px;border:1px solid #cbd3e1;border-radius:9px;font:inherit;letter-spacing:3px;text-transform:uppercase}
        button{padding:12px 18px;border:0;border-radius:9px;font:600 15px system-ui;cursor:pointer;margin:12px 8px 0 0}
        .yes{background:#165dca;color:white}.no{background:#e9edf4;color:#243047}#result{min-height:24px}
        </style></head><body><main><h1>Approve a device</h1>
        <p>Enter the eight-character code shown on the device you are trying to connect. Only approve a request you initiated.</p>
        <form id="approval"><label for="code">Device code</label><p><input id="code" name="user_code" minlength="8" maxlength="8" autocomplete="one-time-code" required></p><p id="details" role="status">Enter your code to review the device and requested permissions.</p>
        <button class="yes" type="submit" data-approve="true">Approve device</button><button class="no" type="submit" data-approve="false">Deny</button></form>
        <p id="result" role="status"></p><p><a href="/device/logout">Sign out</a></p></main>
        <script>
        const form=document.querySelector('#approval'),result=document.querySelector('#result'),details=document.querySelector('#details'),codeInput=document.querySelector('#code');
        let previewReady=false;
        codeInput.addEventListener('change',async()=>{previewReady=false;details.textContent='Checking request…';const code=codeInput.value.trim().toUpperCase();
        try{const r=await fetch('/device/preview?user_code='+encodeURIComponent(code),{credentials:'same-origin'});if(!r.ok)throw new Error('not found');
        const data=await r.json();details.textContent='Client: '+data.client_id+' | Scopes: '+(data.scopes||'(none)')+' | Expires: '+data.expires_at;previewReady=true;
        }catch(_){details.textContent='No valid pending request found for this code.';}});
        form.addEventListener('submit',async e=>{e.preventDefault();if(!previewReady){result.textContent='Review a valid request before deciding.';return;}const approve=e.submitter.dataset.approve==='true';
        result.textContent='Submitting…';try{const r=await fetch('/device/approve',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_code:form.user_code.value,approve})});
        result.textContent=r.ok?(approve?'Device approved. You can return to your device.':'Request denied.'):'This code is invalid, expired, or already handled.';previewReady=false;}catch(_){result.textContent='Unable to contact AuthPlatform. Try again.';}});
        </script></body></html>
        """
        let response = Response(status: .ok)
        response.headers.replaceOrAdd(name: "Content-Type", value: "text/html; charset=utf-8")
        response.headers.replaceOrAdd(name: "Cache-Control", value: "no-store")
        response.headers.replaceOrAdd(name: "X-Content-Type-Options", value: "nosniff")
        response.headers.replaceOrAdd(name: "Referrer-Policy", value: "no-referrer")
        response.body = .init(string: html)
        return response
    }

    app.get("device", "logout") { req async throws -> Response in
        try requireDatabase()
        let cookieHeader = req.headers.first(name: "Cookie") ?? ""
        if let session = cookieHeader.split(separator: ";").compactMap({ part -> String? in
            let pair = part.trimmingCharacters(in: .whitespaces).split(separator: "=", maxSplits: 1)
            return pair.count == 2 && pair[0] == "authplatform_session" ? String(pair[1]) : nil
        }).first,
           let stored = try await OAuthAccessToken.query(on: req.db)
            .filter(\.$tokenHash == SecureValues.hash(session)).first() {
            try await stored.delete(on: req.db)
        }
        let response = Response(status: .seeOther)
        response.headers.replaceOrAdd(name: "Location", value: "/device/login")
        response.headers.add(name: "Set-Cookie", value: "authplatform_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
        return response
    }

    app.post("oauth", "device_authorization") { req async throws -> DeviceAuthorizationResponse in
        try requireDatabase()
        guard let registeredClient = AuthConfig.oauthClientID else {
            throw Abort(.serviceUnavailable, reason: "No OAuth device client is registered")
        }
        let input = try req.content.decode(DeviceAuthorizationRequest.self)
        guard input.client_id == registeredClient else { throw Abort(.unauthorized, reason: "Unknown OAuth client") }
        let scopes = (input.scope ?? "").split(separator: " ").map(String.init)
        guard scopes.allSatisfy({ AuthConfig.allowedScopes.contains($0) }) else {
            throw Abort(.badRequest, reason: "One or more requested scopes are not allowed")
        }
        guard let baseURL = AuthConfig.deviceVerificationURL,
              AuthConfig.publicBaseURL != nil,
              URL(string: baseURL)?.scheme == "https" else {
            throw Abort(.serviceUnavailable, reason: "HTTPS device verification URL and public API base URL are required")
        }
        let deviceCode = SecureValues.base64URL(SecureValues.random(40))
        var code = SecureValues.userCode()
        while try await DeviceGrant.query(on: req.db).filter(\.$userCodeHash == SecureValues.hash(code)).first() != nil {
            code = SecureValues.userCode()
        }
        let grant = DeviceGrant(clientID: registeredClient, deviceCode: deviceCode, userCode: code, scopes: scopes)
        try await grant.save(on: req.db)
        let verify = baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return DeviceAuthorizationResponse(device_code: deviceCode, user_code: code,
            verification_uri: verify, verification_uri_complete: verify + "?user_code=" + code,
            expires_in: 600, interval: 5)
    }

    app.post("device", "approve") { req async throws -> HTTPStatus in
        try requireBrowserOrigin(req)
        let user = try await currentUser(req)
        let input = try req.content.decode(DeviceApprovalRequest.self)
        let code = input.user_code.uppercased().filter { $0.isLetter || $0.isNumber }
        guard code.count == 8 else { throw Abort(.badRequest, reason: "Invalid device user code") }

        // PostgreSQL executes this conditional UPDATE atomically. Concurrent requests
        // cannot both transition the same pending grant.
        var query = DeviceGrant.query(on: req.db)
            .filter(\.$userCodeHash == SecureValues.hash(code))
            .filter(\.$status == "pending")
            .filter(\.$expiresAt > Date())
        query.set(\.$status, to: input.approve ? "approved" : "denied")
        query.set(\.$userID, to: input.approve ? user.id : nil)
        try await query.update()
        guard let resultingGrant = try await DeviceGrant.query(on: req.db)
            .filter(\.$userCodeHash == SecureValues.hash(code)).first(),
              resultingGrant.status == (input.approve ? "approved" : "denied"),
              resultingGrant.userID == (input.approve ? user.id : nil) else {
            throw Abort(.conflict, reason: "Device request was already handled by another approval attempt")
        }
        return .noContent
    }

    app.post("oauth", "token") { req async throws -> Response in
        try requireDatabase()
        let input = try req.content.decode(TokenRequest.self)
        guard input.grant_type == "urn:ietf:params:oauth:grant-type:device_code",
              input.client_id == AuthConfig.oauthClientID,
              let grant = try await DeviceGrant.query(on: req.db)
                .filter(\.$deviceCodeHash == SecureValues.hash(input.device_code)).first() else {
            return oauthError("invalid_grant", "Device authorization is invalid.")
        }
        guard grant.expiresAt > Date() else { return oauthError("expired_token", "The device code has expired.") }
        if grant.status == "denied" { return oauthError("access_denied", "The user denied the request.") }
        if grant.status == "pending" {
            if let last = grant.lastPolledAt, Date().timeIntervalSince(last) < Double(grant.pollInterval) {
                grant.pollInterval += 5
                grant.lastPolledAt = Date()
                try await grant.save(on: req.db)
                return oauthError("slow_down", "Increase the polling interval.", status: .badRequest)
            }
            grant.lastPolledAt = Date()
            try await grant.save(on: req.db)
            return oauthError("authorization_pending", "The user has not approved the request.")
        }
        guard grant.status == "approved", grant.consumedAt == nil, let userID = grant.userID,
              let grantID = grant.id else {
            return oauthError("invalid_grant", "This authorization has already been consumed.")
        }
        let accessToken = SecureValues.base64URL(SecureValues.random(40))
        let token = OAuthAccessToken(authorizationID: grantID, userID: userID, token: accessToken)
        do { try await token.save(on: req.db) }
        catch { return oauthError("invalid_grant", "This authorization has already issued a token.") }
        grant.consumedAt = Date()
        try await grant.save(on: req.db)
        let response = Response(status: .ok)
        try response.content.encode(OAuthTokenResponse(access_token: accessToken, token_type: "Bearer",
            expires_in: 3600, scope: grant.scopes))
        return response
    }

    app.post("oauth", "revoke") { req async throws -> HTTPStatus in
        try requireDatabase()
        let input = try req.content.decode(OAuthRevokeRequest.self)
        guard input.client_id == AuthConfig.oauthClientID else { throw Abort(.unauthorized) }
        if let stored = try await OAuthAccessToken.query(on: req.db)
            .filter(\.$tokenHash == SecureValues.hash(input.token)).first() {
            try await stored.delete(on: req.db)
        }
        return .noContent
    }

    // Telegram service endpoints. Telegram identity is only linked after an authenticated
    // AuthKit user claims a short-lived code initiated by the bot.
    app.post("v1", "telegram", "link-challenges") { req async throws -> TelegramChallengeResponse in
        try requireDatabase(); try requireTelegramService(req)
        let input = try req.content.decode(TelegramChallengeRequest.self)
        guard !input.telegram_user_id.isEmpty, input.telegram_user_id.count <= 64 else {
            throw Abort(.badRequest, reason: "Invalid Telegram user ID")
        }
        let code = SecureValues.userCode()
        let challenge = TelegramLinkChallenge(telegramUserID: input.telegram_user_id, code: code)
        try await challenge.save(on: req.db)
        return TelegramChallengeResponse(code: code, expires_in: 600)
    }

    app.post("v1", "telegram", "link") { req async throws -> HTTPStatus in
        let user = try await currentUser(req)
        let input = try req.content.decode(TelegramClaimRequest.self)
        let code = input.code.uppercased().filter { $0.isLetter || $0.isNumber }
        guard let challenge = try await TelegramLinkChallenge.query(on: req.db)
            .filter(\.$codeHash == SecureValues.hash(code)).first(),
              challenge.claimedAt == nil, challenge.expiresAt > Date() else {
            throw Abort(.badRequest, reason: "Telegram link code is invalid or expired")
        }
        if let existing = try await TelegramLink.query(on: req.db)
            .filter(\.$telegramUserID == challenge.telegramUserID).first(), existing.userID != user.id {
            throw Abort(.conflict, reason: "This Telegram account is already linked to another AuthPlatform account")
        }
        if let oidcIdentity = try await TelegramOIDCIdentity.query(on: req.db)
            .filter(\.$telegramSubject == challenge.telegramUserID).first(),
           oidcIdentity.userID != user.id {
            throw Abort(.conflict, reason: "Telegram sign-in is already associated with another AuthPlatform account; automatic account merging is disabled")
        }
        let link = TelegramLink(telegramUserID: challenge.telegramUserID, userID: user.id!)
        try await link.save(on: req.db)
        challenge.claimedAt = Date()
        try await challenge.save(on: req.db)
        return .noContent
    }

    app.get("v1", "telegram", "devices") { req async throws -> TelegramDevicesResponse in
        try requireDatabase(); try requireTelegramService(req)
        guard let telegramID = req.query[String.self, at: "telegram_user_id"],
              let link = try await TelegramLink.query(on: req.db).filter(\.$telegramUserID == telegramID).first() else {
            throw Abort(.notFound, reason: "Telegram account is not linked")
        }
        let devices = try await RegisteredDevice.query(on: req.db)
            .filter(\.$userID == link.userID).filter(\.$revokedAt == nil).all()
        return TelegramDevicesResponse(devices: devices.compactMap { device in
            guard let id = device.id else { return nil }
            return TelegramDeviceSummary(id: id, label: device.label, platform: device.platform, createdAt: device.createdAt)
        })
    }


    // The Telegram bot is an explicit secondary approval channel for device grants.
    // The service secret authenticates the bot; the linked Telegram account identifies
    // the user. A preview is required before the user sends /confirm.
    app.get("v1", "telegram", "device-authorizations") { req async throws -> TelegramDeviceApprovalPreview in
        try requireDatabase(); try requireTelegramService(req)
        guard let telegramID = req.query[String.self, at: "telegram_user_id"],
              let rawCode = req.query[String.self, at: "user_code"],
              let link = try await TelegramLink.query(on: req.db)
                .filter(\.$telegramUserID == telegramID).first() else {
            throw Abort(.notFound, reason: "Telegram account is not linked")
        }
        let code = rawCode.uppercased().filter { $0.isLetter || $0.isNumber }
        guard let grant = try await DeviceGrant.query(on: req.db)
            .filter(\.$userCodeHash == SecureValues.hash(code)).first(),
              grant.status == "pending", grant.expiresAt > Date() else {
            throw Abort(.notFound, reason: "Device request is invalid, expired, or already handled")
        }
        _ = link
        return TelegramDeviceApprovalPreview(client_id: grant.clientID, scopes: grant.scopes, expires_at: grant.expiresAt)
    }

    app.post("v1", "telegram", "device-approval") { req async throws -> HTTPStatus in
        try requireDatabase(); try requireTelegramService(req)
        let input = try req.content.decode(TelegramDeviceApprovalRequest.self)
        guard !input.telegram_user_id.isEmpty, input.telegram_user_id.count <= 64 else {
            throw Abort(.badRequest, reason: "Invalid Telegram user ID")
        }
        guard let link = try await TelegramLink.query(on: req.db)
            .filter(\.$telegramUserID == input.telegram_user_id).first() else {
            throw Abort(.notFound, reason: "Telegram account is not linked")
        }
        let code = input.user_code.uppercased().filter { $0.isLetter || $0.isNumber }
        guard code.count == 8 else { throw Abort(.badRequest, reason: "Invalid device user code") }

        // The authenticated service identity resolves to a linked account; the atomic
        // conditional UPDATE makes approval/denial single-use under concurrent requests.
        var query = DeviceGrant.query(on: req.db)
            .filter(\.$userCodeHash == SecureValues.hash(code))
            .filter(\.$status == "pending")
            .filter(\.$expiresAt > Date())
        query.set(\.$status, to: input.approve ? "approved" : "denied")
        query.set(\.$userID, to: input.approve ? link.userID : nil)
        try await query.update()
        guard let resultingGrant = try await DeviceGrant.query(on: req.db)
            .filter(\.$userCodeHash == SecureValues.hash(code)).first(),
              resultingGrant.status == (input.approve ? "approved" : "denied"),
              resultingGrant.userID == (input.approve ? link.userID : nil) else {
            throw Abort(.conflict, reason: "Device request was already handled by another approval attempt")
        }
        return .noContent
    }

    app.get("v1", "telegram", "status") { req async throws -> TelegramStatusResponse in
        try requireTelegramService(req)
        return TelegramStatusResponse(status: Environment.get("DATABASE_URL") == nil ? "not_ready" : "ready",
                                      service: "AuthPlatform")
    }
}
