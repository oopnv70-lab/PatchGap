plugins {
    id("com.android.application")
}

android {
    namespace = "com.oopnv.vulnscanner"
    compileSdk = 35
    buildToolsVersion = "36.1.0"

    defaultConfig {
        applicationId = "com.oopnv.vulnscanner"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

dependencies {
    implementation("com.google.android.material:material:1.12.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.google.code.gson:gson:2.11.0")
}
