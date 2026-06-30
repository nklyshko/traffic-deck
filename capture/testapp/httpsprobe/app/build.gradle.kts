plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.httpsprobe"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.httpsprobe"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // OkHttp negotiates HTTP/2 via ALPN (over the platform Conscrypt TLS stack, so the
    // capture's frida TLS-keylog hook still sees the traffic). It's the default engine
    // so e2e tests exercise the gateway's live HTTP/2 decode; the framework
    // HttpURLConnection path (HTTP/1.1 here) stays available via `--es engine urlconn`.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
