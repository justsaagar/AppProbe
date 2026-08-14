"""High-confidence technology signatures.

Matching uses package paths, native library names, APK entries, and Maven
coordinates — not free-text keywords.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.technology import BundledKind, TechCategory


@dataclass(frozen=True)
class TechSignature:
    name: str
    vendor: str
    category: TechCategory
    path_prefixes: tuple[str, ...] = ()
    file_names: tuple[str, ...] = ()
    native_libs: tuple[str, ...] = ()
    maven: tuple[tuple[str, str], ...] = ()
    flutter_packages: tuple[str, ...] = ()
    bundled: BundledKind = BundledKind.APPLICATION_BUNDLED
    confidence: float = 0.94


SIGNATURES: tuple[TechSignature, ...] = (
    TechSignature(
        "Flutter",
        "Google",
        TechCategory.FRAMEWORK,
        path_prefixes=("assets/flutter_assets/", "io/flutter/", "io.flutter."),
        file_names=("libflutter.so", "libapp.so"),
        native_libs=("libflutter.so", "libapp.so"),
        confidence=0.99,
    ),
    TechSignature(
        "React Native",
        "Meta",
        TechCategory.FRAMEWORK,
        path_prefixes=("com/facebook/react/",),
        file_names=("libreactnativejni.so", "libreactnative.so", "index.android.bundle"),
        native_libs=("libreactnativejni.so", "libreactnative.so", "libhermes.so", "libjsc.so"),
        confidence=0.97,
    ),
    TechSignature(
        "Firebase Auth",
        "Google",
        TechCategory.AUTHENTICATION,
        path_prefixes=(
            "com/google/firebase/auth/",
            "io/flutter/plugins/firebase/auth/",
        ),
        flutter_packages=("firebase_auth",),
        maven=(("com.google.firebase", "firebase-auth"),),
        confidence=0.96,
    ),
    TechSignature(
        "Firebase Analytics",
        "Google",
        TechCategory.ANALYTICS,
        path_prefixes=("com/google/firebase/analytics/",),
        flutter_packages=("firebase_analytics",),
        maven=(("com.google.firebase", "firebase-analytics"),),
        confidence=0.96,
    ),
    TechSignature(
        "Firebase Crashlytics",
        "Google",
        TechCategory.SDK,
        path_prefixes=("com/google/firebase/crashlytics/",),
        flutter_packages=("firebase_crashlytics",),
        maven=(("com.google.firebase", "firebase-crashlytics"),),
        confidence=0.96,
    ),
    TechSignature(
        "Firebase Messaging",
        "Google",
        TechCategory.MESSAGING,
        path_prefixes=(
            "com/google/firebase/messaging/",
            "io/flutter/plugins/firebase/messaging/",
        ),
        flutter_packages=("firebase_messaging",),
        maven=(("com.google.firebase", "firebase-messaging"),),
        confidence=0.96,
    ),
    TechSignature(
        "Firebase Firestore",
        "Google",
        TechCategory.DATABASE,
        path_prefixes=("com/google/firebase/firestore/",),
        flutter_packages=("cloud_firestore",),
        maven=(("com.google.firebase", "firebase-firestore"),),
        confidence=0.96,
    ),
    TechSignature(
        "Firebase Storage",
        "Google",
        TechCategory.SDK,
        path_prefixes=("com/google/firebase/storage/",),
        flutter_packages=("firebase_storage",),
        maven=(("com.google.firebase", "firebase-storage"),),
        confidence=0.96,
    ),
    TechSignature(
        "Firebase Remote Config",
        "Google",
        TechCategory.SDK,
        path_prefixes=("com/google/firebase/remoteconfig/",),
        flutter_packages=("firebase_remote_config",),
        maven=(("com.google.firebase", "firebase-config"),),
        confidence=0.96,
    ),
    TechSignature(
        "Firebase App Check",
        "Google",
        TechCategory.AUTHENTICATION,
        path_prefixes=("com/google/firebase/appcheck/",),
        flutter_packages=("firebase_app_check",),
        maven=(("com.google.firebase", "firebase-appcheck"),),
        confidence=0.96,
    ),
    TechSignature(
        "Firebase",
        "Google",
        TechCategory.SDK,
        path_prefixes=("com/google/firebase/",),
        file_names=("google-services.json",),
        flutter_packages=("firebase_core",),
        maven=(("com.google.firebase", "firebase-common"), ("com.google.firebase", "firebase-core")),
        confidence=0.93,
    ),
    TechSignature(
        "Google Play Services",
        "Google",
        TechCategory.SDK,
        path_prefixes=("com/google/android/gms/common/", "com/google/android/gms/base/"),
        maven=(("com.google.android.gms", "play-services-base"),),
        confidence=0.93,
    ),
    TechSignature(
        "Google Maps",
        "Google",
        TechCategory.MAPS,
        path_prefixes=("com/google/android/gms/maps/",),
        flutter_packages=("google_maps_flutter",),
        maven=(("com.google.android.gms", "play-services-maps"),),
        confidence=0.96,
    ),
    TechSignature(
        "Google Places",
        "Google",
        TechCategory.MAPS,
        path_prefixes=(
            "com/google/android/libraries/places/",
            "com/google/android/gms/location/places/",
        ),
        maven=(("com.google.android.libraries.places", "places"),),
        confidence=0.96,
    ),
    TechSignature(
        "ML Kit",
        "Google",
        TechCategory.SDK,
        path_prefixes=("com/google/mlkit/",),
        maven=(("com.google.mlkit", "common"),),
        confidence=0.95,
    ),
    TechSignature(
        "Google Play Billing",
        "Google",
        TechCategory.PAYMENT,
        path_prefixes=("com/android/billingclient/",),
        maven=(("com.android.billingclient", "billing"),),
        confidence=0.96,
    ),
    TechSignature(
        "Google Sign-In",
        "Google",
        TechCategory.AUTHENTICATION,
        path_prefixes=("com/google/android/gms/auth/api/signin/",),
        maven=(("com.google.android.gms", "play-services-auth"),),
        confidence=0.96,
    ),
    TechSignature(
        "Stripe SDK",
        "Stripe",
        TechCategory.PAYMENT,
        path_prefixes=("com/stripe/android/",),
        flutter_packages=("stripe_android", "flutter_stripe"),
        maven=(("com.stripe", "stripe-android"),),
        confidence=0.96,
    ),
    TechSignature(
        "RevenueCat",
        "RevenueCat",
        TechCategory.PAYMENT,
        path_prefixes=("com/revenuecat/purchases/",),
        flutter_packages=("purchases_flutter",),
        maven=(("com.revenuecat.purchases", "purchases"),),
        confidence=0.96,
    ),
    TechSignature(
        "OkHttp",
        "Square",
        TechCategory.NETWORKING,
        path_prefixes=("okhttp3/", "com/squareup/okhttp3/"),
        maven=(("com.squareup.okhttp3", "okhttp"),),
        confidence=0.95,
    ),
    TechSignature(
        "Retrofit",
        "Square",
        TechCategory.NETWORKING,
        path_prefixes=("retrofit2/", "com/squareup/retrofit2/"),
        maven=(("com.squareup.retrofit2", "retrofit"),),
        confidence=0.95,
    ),
    TechSignature(
        "Volley",
        "Google",
        TechCategory.NETWORKING,
        path_prefixes=("com/android/volley/",),
        maven=(("com.android.volley", "volley"),),
        confidence=0.95,
    ),
    TechSignature(
        "Ktor",
        "JetBrains",
        TechCategory.NETWORKING,
        path_prefixes=("io/ktor/",),
        maven=(("io.ktor", "ktor-client-core"),),
        confidence=0.95,
    ),
    TechSignature(
        "Dio",
        "Flutter Community",
        TechCategory.NETWORKING,
        flutter_packages=("dio",),
        confidence=0.94,
    ),
    TechSignature(
        "Dart http",
        "Dart",
        TechCategory.NETWORKING,
        flutter_packages=("http",),
        confidence=0.94,
    ),
    TechSignature(
        "Chopper",
        "Flutter Community",
        TechCategory.NETWORKING,
        flutter_packages=("chopper",),
        confidence=0.94,
    ),
    TechSignature(
        "AppsFlyer",
        "AppsFlyer",
        TechCategory.ANALYTICS,
        path_prefixes=("com/appsflyer/",),
        maven=(("com.appsflyer", "af-android-sdk"),),
        confidence=0.95,
    ),
    TechSignature(
        "Mixpanel",
        "Mixpanel",
        TechCategory.ANALYTICS,
        path_prefixes=("com/mixpanel/android/",),
        maven=(("com.mixpanel.android", "mixpanel-android"),),
        confidence=0.95,
    ),
    TechSignature(
        "Amplitude",
        "Amplitude",
        TechCategory.ANALYTICS,
        path_prefixes=("com/amplitude/",),
        maven=(("com.amplitude", "android-sdk"),),
        confidence=0.95,
    ),
    TechSignature(
        "OneSignal",
        "OneSignal",
        TechCategory.MESSAGING,
        path_prefixes=("com/onesignal/",),
        maven=(("com.onesignal", "OneSignal"),),
        confidence=0.95,
    ),
    TechSignature(
        "Facebook SDK",
        "Meta",
        TechCategory.ANALYTICS,
        path_prefixes=(
            "com/facebook/FacebookSdk",
            "com/facebook/appevents/",
            "com/facebook/login/",
            "com/facebook/core/",
        ),
        maven=(("com.facebook.android", "facebook-android-sdk"),),
        confidence=0.94,
    ),
    TechSignature(
        "Adjust",
        "Adjust",
        TechCategory.ANALYTICS,
        path_prefixes=("com/adjust/sdk/",),
        maven=(("com.adjust.sdk", "adjust-android"),),
        confidence=0.95,
    ),
    TechSignature(
        "Mapbox",
        "Mapbox",
        TechCategory.MAPS,
        path_prefixes=("com/mapbox/",),
        native_libs=("libmapbox-gl.so", "libmapbox.so"),
        maven=(("com.mapbox.mapboxsdk", "mapbox-android-sdk"),),
        confidence=0.96,
    ),
    TechSignature(
        "Android WebView",
        "Google",
        TechCategory.OTHER,
        path_prefixes=("android/webkit/WebView",),
        bundled=BundledKind.PLATFORM_SYSTEM,
        confidence=0.85,
    ),
    TechSignature(
        "Flutter WebView",
        "Flutter",
        TechCategory.OTHER,
        path_prefixes=("io/flutter/plugins/webviewflutter/",),
        flutter_packages=("webview_flutter",),
        confidence=0.95,
    ),
    TechSignature(
        "React Native WebView",
        "React Native Community",
        TechCategory.OTHER,
        path_prefixes=("com/reactnativecommunity/webview/",),
        confidence=0.95,
    ),
    TechSignature(
        "OpenSSL",
        "OpenSSL",
        TechCategory.CRYPTOGRAPHY,
        native_libs=("libssl.so", "libcrypto.so"),
        file_names=("libssl.so", "libcrypto.so"),
        confidence=0.90,
    ),
    TechSignature(
        "SQLite",
        "SQLite",
        TechCategory.DATABASE,
        native_libs=("libsqlite.so", "libsqlite3.so"),
        file_names=("libsqlite.so", "libsqlite3.so"),
        flutter_packages=("sqflite",),
        confidence=0.90,
    ),
)


MAVEN_INDEX: dict[tuple[str, str], str] = {}
for _sig in SIGNATURES:
    for _coord in _sig.maven:
        MAVEN_INDEX[_coord] = _sig.name


PLATFORM_NATIVE_SKIP = {
    "libc.so",
    "libm.so",
    "libdl.so",
    "liblog.so",
    "libz.so",
    "libandroid.so",
    "libjnigraphics.so",
    "libegl.so",
    "libglesv2.so",
    "libglesv3.so",
    "libopensles.so",
    "libstdc++.so",
    "libcompiler_rt.so",
    "libnativehelper.so",
    "libcutils.so",
    "libutils.so",
}
