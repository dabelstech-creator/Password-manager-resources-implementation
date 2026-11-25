plugins {
    kotlin("multiplatform")
    id("com.android.library")
}

kotlin {
    androidTarget()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            implementation("app.univera.telegramlogin:telegram-login:0.3.0")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

android {
    namespace = "com.dabelstech.authplatform.telegramlogin"
    compileSdk = 35
    defaultConfig { minSdk = 23 }
}
