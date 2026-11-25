package com.dabelstech.authplatform.telegramlogin

import app.univera.telegramlogin.TelegramLogin
import app.univera.telegramlogin.TelegramLoginResult
import app.univera.telegramlogin.TelegramAuthContext

/**
 * Configure once from the host application after supplying the client ID and
 * the platform-specific HTTPS redirect URI registered with @BotFather.
 */
fun configureTelegramAuth(clientId: String, redirectUri: String) {
    require(clientId.isNotBlank()) { "Telegram OIDC client ID is required" }
    require(redirectUri.startsWith("https://")) { "A verified HTTPS redirect URI is required" }
    TelegramLogin.configure(
        clientId = clientId,
        redirectUri = redirectUri,
        scopes = listOf("openid")
    )
}

/** Returns only a Telegram-signed ID token. The host must exchange it with AuthPlatform. */
suspend fun loginWithTelegram(context: TelegramAuthContext): Result<String> =
    when (val result = TelegramLogin.login(context)) {
        is TelegramLoginResult.Success -> Result.success(result.idToken)
        is TelegramLoginResult.Failure -> Result.failure(result.error)
    }

/** Call this from the platform deep-link / Universal-Link callback. */
fun handleTelegramRedirect(url: String) {
    require(url.isNotBlank()) { "Telegram callback URL is required" }
    TelegramLogin.handle(url)
}
