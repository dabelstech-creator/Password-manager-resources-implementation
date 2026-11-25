import Foundation
import Vapor
import Fluent
import FluentPostgresDriver
import JWTKit
import Crypto
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Configuration and cryptographic helpers

enum AuthConfig {
    static var workOSClientID: String? { Environment.get("WORKOS_CLIENT_ID") }
    static var iosRedirectURI: String? { Environment.get("WORKOS_REDIRECT_URI_IOS") }
    static var publicBaseURL: String? { Environment.get("AUTHPLATFORM_PUBLIC_BASE_URL") }
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
    @Field(key: "workos_subject") var workosSubject: String
    @Field(key: "created_at") var createdAt: Date
    init() {}
    init(workosSubject: String) { self.workosSubject = workosSubject; self.createdAt = Date() }
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
            .field("workos_subject", .string, .required).field("created_at", .datetime, .required)
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

private func requireDatabase() throws {
    guard Environment.get("DATABASE_URL") != nil else {
        throw Abort(.serviceUnavailable, reason: "Persistent database is not configured")
    }
}

private func currentUser(_ req: Request) async throws -> AuthUser {
    try requireDatabase()
    guard let clientID = AuthConfig.workOSClientID,
          let token = req.headers.bearerAuthorization?.token else {
        throw Abort(.unauthorized, reason: "A WorkOS AuthKit bearer token is required")
    }

    let subject: String
    do {
        subject = try await WorkOSJWTVerifier.shared.subject(from: token, clientID: clientID)
    } catch {
        // AuthPlatform-issued opaque device tokens are also accepted for API access.
        let tokenHash = SecureValues.hash(token)
        guard let stored = try await OAuthAccessToken.query(on: req.db)
            .filter(\.$tokenHash == tokenHash).first(),
              stored.expiresAt > Date(),
              let user = try await AuthUser.find(stored.userID, on: req.db) else {
            throw Abort(.unauthorized, reason: "Invalid or expired bearer token")
        }
        return user
    }

    if let existing = try await AuthUser.query(on: req.db).filter(\.$workosSubject == subject).first() {
        return existing
    }
    let user = AuthUser(workosSubject: subject)
    try await user.save(on: req.db)
    return user
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
        guard let baseURL = AuthConfig.publicBaseURL else {
            throw Abort(.serviceUnavailable, reason: "AuthPlatform public base URL is not configured")
        }
        let deviceCode = SecureValues.base64URL(SecureValues.random(40))
        var code = SecureValues.userCode()
        while try await DeviceGrant.query(on: req.db).filter(\.$userCodeHash == SecureValues.hash(code)).first() != nil {
            code = SecureValues.userCode()
        }
        let grant = DeviceGrant(clientID: registeredClient, deviceCode: deviceCode, userCode: code, scopes: scopes)
        try await grant.save(on: req.db)
        let verify = baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/device"
        return DeviceAuthorizationResponse(device_code: deviceCode, user_code: code,
            verification_uri: verify, verification_uri_complete: verify + "?user_code=" + code,
            expires_in: 600, interval: 5)
    }

    app.post("device", "approve") { req async throws -> HTTPStatus in
        let user = try await currentUser(req)
        let input = try req.content.decode(DeviceApprovalRequest.self)
        let code = input.user_code.uppercased().filter { $0.isLetter || $0.isNumber }
        guard let grant = try await DeviceGrant.query(on: req.db)
            .filter(\.$userCodeHash == SecureValues.hash(code)).first(),
              grant.expiresAt > Date(), grant.status == "pending" else {
            throw Abort(.badRequest, reason: "User code is invalid, expired, or already used")
        }
        grant.status = input.approve ? "approved" : "denied"
        grant.userID = input.approve ? user.id : nil
        try await grant.save(on: req.db)
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
            .filter(\\.$tokenHash == SecureValues.hash(input.token)).first() {
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

    app.get("v1", "telegram", "status") { req async throws -> TelegramStatusResponse in
        try requireTelegramService(req)
        return TelegramStatusResponse(status: Environment.get("DATABASE_URL") == nil ? "not_ready" : "ready",
                                      service: "AuthPlatform")
    }
}
