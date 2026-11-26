# AuthPlatform Telegram Login KMP module

This isolated Kotlin Multiplatform module integrates the community `kmp-telegram-login` SDK for Android and iOS. It is intentionally separate from the Swift/Vapor backend package.

## Toolchain

- Kotlin 2.4.0+
- Android minSdk 23+
- iOS 15+
- Maven Central artifact: `app.univera.telegramlogin:telegram-login:0.3.0`

The module is a client integration layer, not an identity authority. AuthPlatform must validate every returned ID token using Telegram JWKS before issuing its own session.

## Configure

Register the actual Android package + Play app-signing SHA-256 and iOS bundle ID + Apple Team ID with @BotFather under Bot Settings → Login Widget. BotFather issues distinct redirect hosts for Android and iOS. Supply the exact registered redirect URI to `configureTelegramAuth` at app startup:

- Android: `https://app{androidAppId}-login.tg.dev/tglogin`
- iOS: `https://app{iosAppId}-login.tg.dev`

These are templates, not valid deployment values. Do not substitute the WorkOS callback URL. Do not place the bot API token or OAuth client secret in the app.

## Host app callback wiring

The repository currently has no Android application module, iOS app target, package ID, bundle ID, or signing configuration. The host apps must add the callbacks below after their identifiers are registered.

Android:
- Add an exported callback activity with `singleTask` launch mode and an `autoVerify=true` HTTPS App Link intent filter for the exact BotFather host and `/tglogin` path.
- Declare the `tg` scheme query in `<queries>`.
- In `onNewIntent`, call `handleTelegramRedirect(intent.dataString)`.
- Construct `TelegramAuthContext(applicationContext)` and call `loginWithTelegram(context)`.

iOS:
- Add the exact BotFather host to Associated Domains as `applinks:<ios-host>`.
- Add `tg` to `LSApplicationQueriesSchemes`.
- In SwiftUI `onOpenURL`, forward `url.absoluteString` to the Kotlin callback handler exported by the shared framework.
- Use the SDK's iOS auth context and await `loginWithTelegram`.

After receiving the ID token:
1. POST `{ "id_token": token }` to `/v1/auth/telegram` over HTTPS.
2. Keep the returned AuthPlatform access token in OS-protected storage.
3. Generate a P-256 key pair in Android Keystore or iOS Keychain/Secure Enclave.
4. POST the public key to `/v1/devices/challenges`.
5. Sign the exact UTF-8 canonical payload `AuthPlatform-Device-Bind-v1|<userUUID>|<challengeUUID>|<challenge>` with the device private key.
6. POST challenge ID, challenge, and DER-encoded ECDSA signature (base64) to `/v1/devices/bind`.

Never send the private key to AuthPlatform, Telegram, or the bot. The server must verify the signature before registering the public key.

## Status

This module is a source integration scaffold. Host app identifiers, signing keys, BotFather redirect registrations, platform callback wiring, and a successful Android/iOS build are still required. Do not label the mobile integration complete until the real host applications compile and callback round trips pass on devices/simulators.
