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

// No dependencies: a plain framework Activity + HttpURLConnection (Conscrypt under the
// hood), so the capture's frida TLS-keylog hook sees real HTTPS with no extra libraries.
