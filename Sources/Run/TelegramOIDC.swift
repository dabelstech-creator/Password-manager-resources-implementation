import Foundation
import Vapor
import Fluent
import JWTKit
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// Telegram's native and web login clients issue OIDC ID tokens. AuthPlatform
// validates those tokens itself; a client-supplied Telegram profile is never trusted.
enum TelegramLoginConfiguration {
    static var clientID: String? { Environment.get("TELEGRAM_LOGIN_CLIENT_ID") }
    static let issuer = "https://oauth.telegram.org"
    static let jwksURL = URL(string: "https://oauth.telegram.org/.well-known/jwks.json")!
}

private enum TelegramAudience: Codable {
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

private struct TelegramIDTokenClaims: JWTPayload {
    let iss: String
    let sub: String
    let aud: TelegramAudience
    let exp: Double
    let iat: Double
    let nbf: Double?

    func verify(using algorithm: some JWTAlgorithm) throws {
        let now = Date().timeIntervalSince1970
        guard !sub.isEmpty, sub.count <= 128, exp > now,
              iat <= now + 60,
              nbf.map({ $0 <= now }) ?? true else {
            throw Abort(.unauthorized, reason: "Telegram ID token is expired or not yet valid")
        }
    }
}

actor TelegramOIDCVerifier {
    static let shared = TelegramOIDCVerifier()
    private var keys: JWTKeyCollection?
    private var expiresAt = Date.distantPast

    func subject(from token: String, clientID: String) async throws -> String {
        if keys == nil || Date() >= expiresAt {
            let (data, response) = try await URLSession.shared.data(from: TelegramLoginConfiguration.jwksURL)
            guard (response as? HTTPURLResponse)?.statusCode == 200,
                  let jwks = String(data: data, encoding: .utf8) else {
                throw Abort(.serviceUnavailable, reason: "Telegram signing keys are unavailable")
            }
            keys = try await JWTKeyCollection().add(jwksJSON: jwks)
            expiresAt = Date().addingTimeInterval(300)
        }

        let segments = token.split(separator: ".")
        guard segments.count == 3,
              let headerData = telegramBase64URLDecode(String(segments[0])),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              let algorithm = header["alg"] as? String,
              ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"].contains(algorithm) else {
            throw Abort(.unauthorized, reason: "Unsupported Telegram ID token")
        }

        guard let keys else { throw Abort(.serviceUnavailable) }
        let claims = try await keys.verify(token, as: TelegramIDTokenClaims.self)
        guard claims.iss == TelegramLoginConfiguration.issuer,
              claims.aud.contains(clientID),
              claims.exp > Date().timeIntervalSince1970 else {
            throw Abort(.unauthorized, reason: "Telegram token issuer, audience, or expiry validation failed")
        }
        return claims.sub
    }
}

// Separate provider identity table makes the Telegram subject unique and auditable.
// The existing auth_users.workos_subject column is non-nullable in deployed schemas;
// until a dedicated nullable-column migration is applied, Telegram-created users use
// a reserved, namespaced internal subject. Never expose this value as a WorkOS subject.
final class TelegramOIDCIdentity: Model {
    static let schema = "telegram_oidc_identities"
    @ID(key: .id) var id: UUID?
    @Field(key: "telegram_subject") var telegramSubject: String
    @Field(key: "user_id") var userID: UUID
    @Field(key: "issuer") var issuer: String
    @Field(key: "created_at") var createdAt: Date
    init() {}
    init(subject: String, userID: UUID) {
        self.telegramSubject = subject
        self.userID = userID
        self.issuer = TelegramLoginConfiguration.issuer
        self.createdAt = Date()
    }
}

struct CreateTelegramOIDCIdentities: AsyncMigration {
    func prepare(on db: Database) async throws {
        try await db.schema(TelegramOIDCIdentity.schema).id()
            .field("telegram_subject", .string, .required)
            .field("user_id", .uuid, .required)
            .field("issuer", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "telegram_subject")
            .create()
    }

    func revert(on db: Database) async throws {
        try await db.schema(TelegramOIDCIdentity.schema).delete()
    }
}

private struct TelegramIDTokenRequest: Content { let id_token: String }
private struct TelegramLoginResponse: Content {
    let accessToken: String
    let tokenType: String
    let expiresIn: Int
    let userID: UUID
}

func registerTelegramOIDCRoutes(_ app: Application) {
    app.post("v1", "auth", "telegram") { req async throws -> TelegramLoginResponse in
        try requireTelegramOIDCDatabase()
        guard let clientID = TelegramLoginConfiguration.clientID, !clientID.isEmpty else {
            throw Abort(.serviceUnavailable, reason: "TELEGRAM_LOGIN_CLIENT_ID is not configured")
        }
        let input = try req.content.decode(TelegramIDTokenRequest.self)
        guard input.id_token.count <= 16_384 else {
            throw Abort(.badRequest, reason: "Telegram ID token is too large")
        }
        let telegramSubject = try await TelegramOIDCVerifier.shared.subject(
            from: input.id_token, clientID: clientID
        )

        let user: AuthUser
        if let identity = try await TelegramOIDCIdentity.query(on: req.db)
            .filter(\.$telegramSubject == telegramSubject).first(),
           let existing = try await AuthUser.find(identity.userID, on: req.db) {
            user = existing
        } else {
            let internalSubject = "telegram-oidc:" + telegramSubject
            if let existing = try await AuthUser.query(on: req.db)
                .filter(\.$workosSubject == internalSubject).first() {
                user = existing
            } else {
                user = AuthUser(workosSubject: internalSubject)
                try await user.save(on: req.db)
            }
            let identity = TelegramOIDCIdentity(subject: telegramSubject, userID: user.id!)
            try await identity.save(on: req.db)
        }

        // Opaque AuthPlatform token; only its SHA-256 hash is persisted.
        let accessToken = SecureValues.base64URL(SecureValues.random(40))
        let session = OAuthAccessToken(authorizationID: UUID(), userID: user.id!, token: accessToken)
        try await session.save(on: req.db)
        return TelegramLoginResponse(
            accessToken: accessToken, tokenType: "Bearer", expiresIn: 3600, userID: user.id!
        )
    }
}

private func requireTelegramOIDCDatabase() throws {
    guard Environment.get("DATABASE_URL") != nil else {
        throw Abort(.serviceUnavailable, reason: "Persistent database is not configured")
    }
}


private func telegramBase64URLDecode(_ value: String) -> Data? {
    var normalized = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while normalized.count % 4 != 0 { normalized.append("=") }
    return Data(base64Encoded: normalized)
}
