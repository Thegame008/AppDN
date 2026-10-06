#!/usr/bin/env python3
"""MobScope: tecnologías, protecciones y metadatos de Android e iOS.
Python >=3.9. Solo biblioteca estándar. Análisis local, sin ejecutar la aplicación.
Uso: python3 mobscope.py app.ipa --json resultado.json
Lee APK/IPA, Info.plist XML/binario y Mach-O thin/universal. No descifra código.
Multihilos por archivo interno: --threads N (automático hasta 4; 1 = secuencial).
"""
import argparse
import hashlib
import io
import json
import re
import os
import plistlib
import shutil
import struct
import sys
import tempfile
import threading
import time
import textwrap
import unicodedata
import zipfile
import zlib
import xml.etree.ElementTree as ET
from xml.parsers.expat import ExpatError
from datetime import datetime, timezone
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait

VERSION = "3.0.2"
CHUNK, OVERLAP = 1024 * 1024, 1024
ARCHIVES = {".apk", ".apks", ".xapk", ".aab", ".zip", ".aar", ".ipa"}
CONTENT = {".dex", ".so", ".js", ".bundle", ".hbc", ".json", ".xml", ".txt",
           ".properties", ".yaml", ".yml", ".lock", ".gradle", ".kts", ".kt",
           ".java", ".ts", ".tsx", ".dart", ".bin", ".dat", ".arsc", ".pb",
           ".dll", ".blob", ".manifest", ".config", ".html", ".css", ".md",
           ".plist", ".dylib", ".macho", ".jsbundle", ".swiftinterface", ".strings"}
RULES, RULE_META = [], {}
LEVEL_ORDER = {"especifica": 0, "probable": 1, "indicio": 2}

# Fuentes de las huellas: documentación y repositorios de sus autores.
# La confianza describe PRESENCIA ESTÁTICA, nunca eficacia o activación de controles.
TECH_INFO = {
    "FreeRASP / Talsec": ("RASP", "https://github.com/talsec/Free-RASP-Android"),
    "RootBeer": ("detección de root", "https://github.com/scottyab/rootbeer"),
    "JailMonkey": ("root / entorno", "https://github.com/GantMan/jail-monkey"),
    "Google Play Integrity": ("integridad", "https://developer.android.com/google/play/integrity/reference/com/google/android/play/core/integrity/package-summary"),
    "TrustKit": ("SDK de pinning TLS", "https://github.com/datatheorem/TrustKit-Android"),
    "React Native": ("framework", "https://github.com/facebook/react-native"),
    "Flutter": ("framework", "https://api.flutter.dev/javadoc/io/flutter/embedding/engine/FlutterJNI.html"),
    ".NET MAUI": ("framework", "https://learn.microsoft.com/dotnet/maui/deployment/runtimes-compilation"),
    "Xamarin.Forms": ("framework", "https://github.com/xamarin/Xamarin.Forms"),
    ".NET para Android / Xamarin.Android": ("plataforma .NET", "https://github.com/dotnet/android/blob/main/Documentation/project-docs/AssemblyStores.md"),
    "Mono": ("runtime .NET", "https://learn.microsoft.com/dotnet/maui/deployment/runtimes-compilation"),
    "CoreCLR": ("runtime .NET", "https://learn.microsoft.com/dotnet/maui/deployment/runtimes-compilation"),
    "Unity": ("motor de desarrollo", "https://docs.unity3d.com/Manual/android-plugins-java-code-from-c-sharp.html"),
    "Capacitor": ("puente nativo / web", "https://github.com/ionic-team/capacitor"),
    "Cordova": ("puente nativo / web", "https://github.com/apache/cordova-android"),
    "Ionic": ("interfaz web", "https://ionicframework.com/docs"),
    "NativeScript": ("framework", "https://old.docs.nativescript.org/angular/guides/integration-with-existing-ios-and-android-apps/extend-existing-android-app"),
    "Qt": ("framework", "https://doc.qt.io/qt-6/android/org/qtproject/qt/android/bindings/package-summary.html"),
    "Jetpack Compose": ("interfaz Android", "https://developer.android.com/jetpack/androidx/releases/compose-runtime"),
    "Hermes": ("motor JavaScript", "https://github.com/facebook/hermes"),
    "Kotlin": ("runtime / metadatos", "https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-metadata/"),
    "Dart": ("runtime / código AOT", "https://github.com/dart-lang/sdk"),
    "Rust (componente nativo)": ("lenguaje de componente", "https://doc.rust-lang.org/rustc/symbol-mangling/v0.html"),
    "C++ (runtime)": ("runtime nativo", "https://developer.android.com/ndk/guides/cpp-support"),
    "OkHttp": ("cliente HTTP", "https://github.com/square/okhttp"),
    "Cronet": ("pila de red", "https://developer.android.com/develop/connectivity/cronet"),
    "Android WebView": ("contenido web", "https://developer.android.com/reference/android/webkit/WebView"),
    "Cocos (familia)": ("motor de desarrollo", "https://github.com/cocos2d/cocos2d-x"),
    "Código nativo (ELF)": ("binarios compilados", "https://developer.android.com/ndk/guides/abis"),
    "Código nativo (Mach-O)": ("binarios Apple", "https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h"),
    "Swift (runtime / metadatos)": ("lenguaje de componente", "https://github.com/swiftlang/swift"),
    "Objective-C (runtime)": ("runtime nativo", "https://github.com/apple-oss-distributions/objc4"),
    ".NET para iOS / Xamarin.iOS": ("plataforma .NET", "https://github.com/dotnet/macios"),
    "SwiftUI": ("interfaz Apple", "https://developer.apple.com/documentation/swiftui"),
    "UIKit": ("interfaz Apple", "https://developer.apple.com/documentation/uikit"),
    "WKWebView": ("contenido web", "https://developer.apple.com/documentation/webkit/wkwebview"),
    "Apple App Attest": ("integridad", "https://developer.apple.com/documentation/devicecheck/dcappattestservice"),
    "IOSSecuritySuite": ("detección de jailbreak / entorno", "https://github.com/securing/IOSSecuritySuite"),
}
IOS_TECH_SOURCES = {
    "FreeRASP / Talsec": "https://github.com/talsec/Free-RASP-iOS",
    "TrustKit": "https://github.com/datatheorem/TrustKit",
    "Flutter": "https://api.flutter.dev/ios-embedder/interface_flutter_engine.html",
    "Cordova": "https://github.com/apache/cordova-ios",
    "Unity": "https://docs.unity3d.com/Manual/UnityasaLibrary-iOS.html",
    "Qt": "https://doc.qt.io/qt-6/ios.html",
    "C++ (runtime)": "https://libcxx.llvm.org/",
}
FAMILY_REASONS = {
    "namespace": "Referencia específica a clases o al namespace de este componente.",
    "dependencia": "Nombre específico de su dependencia encontrado en el contenido.",
    "método": "Nombre de método compatible; falta corroborar clases o bibliotecas.",
    "mención": "Solo una mención de marca; falta una huella específica del SDK.",
    "marca": "Solo una mención de marca; no confirma que la protección esté integrada.",
    "archivo": "Nombre de archivo característico; falta corroboración en el contenido.",
    "compilador": "Ruta característica del compilador dentro de un binario nativo.",
    "runtime": "Símbolo característico del runtime dentro de un binario nativo.",
    "símbolos": "Patrón de símbolo compatible; no se ha validado con un demangler.",
    "sección": "Cadena con el nombre de una sección; no se ha validado la tabla ELF.",
}


def literal(key, tech, category, level, family, values, reason=None, whole=False):
    patterns = []
    for enc in ("utf-8", "utf-16le", "utf-16be"):
        word = {"utf-8": rb"[a-z0-9_/-]", "utf-16le": rb"[a-z0-9_/-]\x00",
                "utf-16be": rb"\x00[a-z0-9_/-]"}[enc]
        pattern = b"(?:" + b"|".join(re.escape(v.lower().encode(enc)) for v in values) + b")"
        if whole:
            pattern = b"(?<!" + word + b")" + pattern + b"(?!" + word + b")"
        patterns.append((re.compile(pattern), enc))
    RULES.append(dict(key=key, tech=tech, category=category, level=level,
                      family=family, label=" / ".join(values), native=False, fold=True,
                      patterns=patterns))
    RULE_META[key] = reason or FAMILY_REASONS[family]


def binary(key, level, family, label, pattern, tech="Rust (componente nativo)", reason=None,
           category="Lenguaje de componente"):
    RULES.append(dict(key=key, tech=tech, category=category,
                      level=level, family=family, label=label, native=True, fold=False,
                      patterns=[(re.compile(pattern), "bytes")]))
    RULE_META[key] = reason or FAMILY_REASONS[family]


literal("freerasp_rn", "FreeRASP / Talsec", "Protección", "especifica", "namespace",
        ("com.freeraspreactnative", "com/freeraspreactnative", "FreeraspReactNativeModule"))
literal("freerasp_dep", "FreeRASP / Talsec", "Protección", "especifica", "dependencia",
        ("freerasp-react-native", "package:freerasp/", "talsec.app/freerasp"))
literal("freerasp_start", "FreeRASP / Talsec", "Protección", "probable", "método", ("talsecStart",))
literal("talsec_namespace", "FreeRASP / Talsec", "Protección", "probable", "namespace",
        ("com.aheaditec.talsec", "com/aheaditec/talsec", "com.talsec", "com/talsec"))
literal("freerasp_brand", "FreeRASP / Talsec", "Protección", "indicio", "mención", ("freerasp", "talsec"), whole=True)
# Diccionario del script original: candidatos sin validar con muestras del fabricante.
for key, name, values in (
    ("arxan", "Arxan", ("com.arxan.guardit", "com/arxan/guardit", "arxan")),
    ("liapp", "LIAPP", ("com.lockincomp", "com/lockincomp", "lockincompany", "liapp")),
    ("dexguard", "DexGuard", ("dexguard",)),
    ("promon", "Promon SHIELD", ("promon",)),
    ("appdome", "Appdome", ("appdome",)),
):
    literal(key, name, "Protección candidata", "indicio", "marca", values, whole=True)
for key, name, values in (
    ("rootbeer", "RootBeer", ("com.scottyab.rootbeer", "com/scottyab/rootbeer")),
    ("jailmonkey", "JailMonkey", ("com.gantix.JailMonkey", "com/gantix/JailMonkey")),
    ("play_integrity", "Google Play Integrity", ("com.google.android.play.core.integrity", "com/google/android/play/core/integrity")),
    ("trustkit", "TrustKit", ("com.datatheorem.android.trustkit", "com/datatheorem/android/trustkit")),
):
    literal(key, name, "Protección", "especifica", "namespace", values,
            "Namespace específico del SDK; su activación requiere comprobarse en ejecución.")
literal("jailmonkey_dep", "JailMonkey", "Protección", "especifica", "dependencia", ("jail-monkey",), whole=True)
for key, name, category, level, values in (
    ("rn", "React Native", "Framework", "especifica",
     ("com.facebook.react", "com/facebook/react")),
    ("flutter", "Flutter", "Framework", "especifica",
     ("io.flutter.embedding", "io/flutter/embedding", "io.flutter.plugin", "io/flutter/plugin")),
    ("hermes", "Hermes", "Motor JavaScript", "probable", ("HermesInternal", "facebook::hermes")),
    ("kotlin", "Kotlin", "Lenguaje o runtime", "probable",
     ("Lkotlin/Metadata;", "kotlin/jvm/internal/Intrinsics", "kotlin.Metadata")),
    ("unity", "Unity", "Framework", "especifica", ("com.unity3d.player", "com/unity3d/player")),
    ("capacitor", "Capacitor", "Framework", "especifica", ("com.getcapacitor", "com/getcapacitor")),
    ("cordova", "Cordova", "Framework", "especifica", ("org.apache.cordova", "org/apache/cordova")),
    ("maui", ".NET MAUI", "Framework", "especifica", ("Microsoft.Maui.Controls", "Microsoft.Maui.Hosting", "Microsoft.Maui.MauiApplication")),
    ("xamarin_forms", "Xamarin.Forms", "Framework", "especifica", ("Xamarin.Forms.Platform.Android", "Xamarin.Forms.Core")),
    ("dotnet_android", ".NET para Android / Xamarin.Android", "Framework", "especifica", ("mono.MonoPackageManager", "mono/MonoPackageManager", "Mono.Android.dll")),
    ("nativescript", "NativeScript", "Framework", "especifica", ("com.tns.Runtime", "com/tns/Runtime", "com.tns.NativeScriptActivity", "com/tns/NativeScriptActivity")),
    ("qt", "Qt", "Framework", "especifica", ("org.qtproject.qt.android", "org/qtproject/qt/android", "org.qtproject.qt5.android", "org/qtproject/qt5/android")),
    ("compose", "Jetpack Compose", "Framework", "especifica", ("androidx.compose.runtime", "androidx/compose/runtime")),
    ("cocos", "Cocos (familia)", "Framework", "especifica", ("org.cocos2dx.lib", "org/cocos2dx/lib", "com.cocos.lib.CocosActivity", "com/cocos/lib/CocosActivity")),
    ("okhttp", "OkHttp", "Biblioteca", "especifica", ("okhttp3.OkHttpClient", "okhttp3/OkHttpClient", "com.squareup.okhttp.OkHttpClient", "com/squareup/okhttp/OkHttpClient")),
    ("cronet", "Cronet", "Biblioteca", "especifica", ("org.chromium.net.CronetEngine", "org/chromium/net/CronetEngine")),
    ("webview", "Android WebView", "Biblioteca", "probable", ("android.webkit.WebView", "android/webkit/WebView")),
):
    literal(key, name, category, level, "namespace", values)
literal("rn_dep", "React Native", "Framework", "especifica", "dependencia", ("react-native",), whole=True)
literal("ionic", "Ionic", "Framework", "especifica", "dependencia", ("@ionic/core", "@ionic/angular", "@ionic/react", "@ionic/vue"), whole=True)
RULE_META.update({
    "hermes": "Solo una referencia a su API; falta corroborar la biblioteca del motor.",
    "kotlin": "Metadatos o runtime Kotlin; pueden proceder de una dependencia.",
    "dotnet_android": "Componente .NET para Android; esta huella no distingue MAUI de Xamarin clásico.",
    "webview": "Referencia a WebView; puede pertenecer a un SDK y no a la interfaz principal.",
    "cocos": "Namespace de la familia Cocos; no distingue por sí solo 2d-x de Creator.",
    "native_elf": "Cabecera ELF de código compilado; no determina el lenguaje ni el framework principal.",
})
binary("rust_path", "especifica", "compilador", "Ruta /rustc/<hash>/library",
       rb"[/\\]rustc[/\\][0-9a-fA-F]{40}[/\\]library[/\\]")
binary("rust_unwind", "especifica", "runtime", "rust_begin_unwind / rust_eh_personality",
       rb"(?<![A-Za-z0-9_])_?(?:rust_begin_unwind|rust_eh_personality)(?![A-Za-z0-9_])")
binary("rust_legacy", "probable", "símbolos", "Símbolo legacy _ZN...17h<16 hex>E",
       rb"(?<![A-Za-z0-9_])__?ZN[A-Za-z0-9_$]{4,220}17h[0-9a-f]{16}E(?![A-Za-z0-9_])")
binary("rust_v0", "indicio", "símbolos", "Símbolo compatible con la estructura Rust v0",
       rb"(?<![A-Za-z0-9_])__?R[A-Za-z0-9_]{2,768}(?![A-Za-z0-9_])",
       reason="Estructura v0 compatible; requiere corroborar un runtime o una ruta del compilador Rust.")
binary("rust_section", "probable", "sección", "Nombre .rustc", rb"\x00\.rustc\x00")
binary("dart_snapshot", "especifica", "runtime", "Símbolos de snapshot Dart",
       rb"(?<![A-Za-z0-9_])_?kDart(?:Vm|Isolate)Snapshot(?:Data|Instructions)(?![A-Za-z0-9_])", tech="Dart")
binary("mono_runtime", "especifica", "runtime", "Símbolo de inicialización Mono",
       rb"(?<![A-Za-z0-9_])_?mono_jit_init_version(?![A-Za-z0-9_])", tech="Mono", category="Lenguaje o runtime")
binary("coreclr_runtime", "especifica", "runtime", "Símbolo de inicialización CoreCLR",
       rb"(?<![A-Za-z0-9_])_?coreclr_initialize(?![A-Za-z0-9_])", tech="CoreCLR", category="Lenguaje o runtime")

# Huellas iOS: símbolos/clases en Mach-O, no coincidencias en documentación.
for key, tech, cat, classes in (
    ("ios_rn", "React Native", "Framework", ("RCTBridge", "RCTCxxBridge", "RCTRootView", "RCTFabricSurface")),
    ("ios_flutter", "Flutter", "Framework", ("FlutterEngine", "FlutterViewController")),
    ("ios_capacitor", "Capacitor", "Framework", ("CAPBridgeViewController", "CAPPlugin")),
    ("ios_cordova", "Cordova", "Framework", ("CDVViewController", "CDVPlugin")),
    ("ios_unity", "Unity", "Framework", ("UnityFramework", "UnityAppController")),
    ("ios_trustkit", "TrustKit", "Protección", ("TrustKit", "TSKPinningValidator")),
    ("ios_attest", "Apple App Attest", "Protección", ("DCAppAttestService",)),
    ("ios_wkwebview", "WKWebView", "Biblioteca", ("WKWebView",)),
):
    pattern = rb"(?<![A-Za-z0-9_])_?OBJC_CLASS_\$_(?:" + b"|".join(c.encode() for c in classes) + rb")(?![A-Za-z0-9_])"
    binary(key, "especifica", "namespace", "Clase Objective-C de " + tech, pattern, tech=tech, category=cat,
           reason="Símbolo de clase específico en un Mach-O; puede ser una referencia importada o una implementación incluida.")
    RULES[-1]["formats"] = {"Mach-O"}
    # Las clases conservan su nombre incluso cuando se han eliminado símbolos.
    binary(key + "_name", "probable", "namespace", "Nombre de clase iOS de " + tech,
           rb"\x00(?:" + b"|".join(c.encode() for c in classes) + rb")\x00", tech=tech, category=cat,
           reason="Nombre de clase iOS dentro del binario; sin resolver la tabla de clases se mantiene como probable.")
    RULES[-1]["formats"] = {"Mach-O"}
literal("dotnet_ios", ".NET para iOS / Xamarin.iOS", "Framework", "especifica", "dependencia",
        ("Xamarin.iOS.dll", "Microsoft.iOS.dll"), "Ensamblado de .NET para iOS; no distingue MAUI de Xamarin clásico.")
literal("maui_ios", ".NET MAUI", "Framework", "especifica", "namespace", ("Microsoft.Maui.MauiUIApplicationDelegate",))
literal("xamarin_forms_ios", "Xamarin.Forms", "Framework", "especifica", "namespace", ("Xamarin.Forms.Platform.iOS",))

# Una dependencia de carga Mach-O validada es evidencia más fuerte que un nombre ZIP.
# Nombre exacto del framework -> tecnología y categoría.
IOS_FRAMEWORKS = {
    "Flutter": ("Flutter", "Framework"), "React": ("React Native", "Framework"),
    "React_Core": ("React Native", "Framework"), "hermes": ("Hermes", "Motor JavaScript"),
    "TalsecRuntime": ("FreeRASP / Talsec", "Protección"),
    "TrustKit": ("TrustKit", "Protección"), "IOSSecuritySuite": ("IOSSecuritySuite", "Protección"),
    "Capacitor": ("Capacitor", "Framework"), "Cordova": ("Cordova", "Framework"),
    "UnityFramework": ("Unity", "Framework"), "NativeScript": ("NativeScript", "Framework"),
    "QtCore": ("Qt", "Framework"), "Qt5Core": ("Qt", "Framework"), "Qt6Core": ("Qt", "Framework"),
    "SwiftUI": ("SwiftUI", "Framework"), "UIKit": ("UIKit", "Biblioteca"),
}
for framework in IOS_FRAMEWORKS:
    RULE_META["ios_link_" + framework] = "Nombre específico en un comando de enlace Mach-O validado; prueba una referencia al componente, no su ejecución."
RULE_META.update({
    "native_macho": "Cabecera y comandos Mach-O validados; no determina el lenguaje de toda la app.",
    "swift_section": "Sección de metadatos Swift con contenido y rango válidos en Mach-O; puede proceder de un SDK.",
    "objc_section": "Sección de metadatos Objective-C en Mach-O; también la generan componentes Swift con interoperabilidad.",
    "swift_link": "Dependencia de carga del runtime Swift en Mach-O; puede proceder de un SDK.",
    "objc_link": "Dependencia de carga del runtime Objective-C; no identifica el lenguaje principal de la app.",
    "cpp_ios_link": "Dependencia de libc++ en Mach-O; identifica su runtime, no el lenguaje de toda la app.",
})

NAME_RULES = [
    ("flutter_lib", "Flutter", "Framework", "probable", r"(?:^|/)lib/[^/]+/libflutter\.so$"),
    ("flutter_assets", "Flutter", "Framework", "probable", r"(?:^|/)assets/flutter_assets/"),
    ("hermes_lib", "Hermes", "Motor JavaScript", "probable", r"(?:^|/)lib/[^/]+/libhermes\.so$"),
    ("rn_lib", "React Native", "Framework", "probable", r"(?:^|/)lib/[^/]+/libreactnative(?:jni)?\.so$"),
    ("unity_lib", "Unity", "Framework", "probable", r"(?:^|/)lib/[^/]+/libunity\.so$"),
    ("kotlin_module", "Kotlin", "Lenguaje o runtime", "probable", r"\.kotlin_module$"),
    ("maui_assembly", ".NET MAUI", "Framework", "probable", r"(?:^|/)(?:libaot-|lib_)?Microsoft\.Maui(?:\.[A-Za-z0-9_-]+)*\.dll(?:\.so)?$"),
    ("xamarin_assembly", "Xamarin.Forms", "Framework", "probable", r"(?:^|/)(?:libaot-|lib_)?Xamarin\.Forms(?:\.[A-Za-z0-9_-]+)*\.dll(?:\.so)?$"),
    ("dotnet_glue", ".NET para Android / Xamarin.Android", "Framework", "probable", r"(?:^|/)lib/[^/]+/libmonodroid\.so$"),
    ("dotnet_assembly", ".NET para Android / Xamarin.Android", "Framework", "probable", r"(?:^|/)(?:libaot-|lib_)?Mono\.Android\.dll(?:\.so)?$"),
    ("dotnet_store", ".NET para Android / Xamarin.Android", "Framework", "probable", r"(?:^|/)(?:assemblies/assemblies(?:\.[^/]+)?\.(?:blob|manifest)|lib/[^/]+/(?:libassemblies\.[^/]+(?:\.blob)?|libassembly-store)\.so)$"),
    ("mono_lib", "Mono", "Lenguaje o runtime", "probable", r"(?:^|/)lib/[^/]+/libmonosgen-2\.0\.so$"),
    ("coreclr_lib", "CoreCLR", "Lenguaje o runtime", "probable", r"(?:^|/)lib/[^/]+/libcoreclr\.so$"),
    ("cpp_lib", "C++ (runtime)", "Lenguaje o runtime", "probable", r"(?:^|/)lib/[^/]+/libc\+\+_shared\.so$"),
    ("qt_lib", "Qt", "Framework", "probable", r"(?:^|/)lib/[^/]+/libQt[56]Core(?:_[^/]+)?\.so$"),
    ("nativescript_lib", "NativeScript", "Framework", "probable", r"(?:^|/)lib/[^/]+/libNativeScript\.so$"),
]
NAME_RULES += [("ios_file_" + framework, tech, cat, "probable",
                r"(?:^|/)" + re.escape(framework) + r"\.framework/(?:Versions/[^/]+/)?" + re.escape(framework) + r"$")
               for framework, (tech, cat) in IOS_FRAMEWORKS.items()]
NAME_RULES += [
    ("ios_flutter_assets", "Flutter", "Framework", "probable", r"\.app/(?:Frameworks/App\.framework/)?flutter_assets/"),
    ("ios_dotnet_assembly", ".NET para iOS / Xamarin.iOS", "Framework", "probable", r"(?:^|/)(?:Xamarin|Microsoft)\.iOS\.dll$"),
]
NAME_RULES = [(a, b, c, d, re.compile(e, re.I)) for a, b, c, d, e in NAME_RULES]
for key, tech, cat, level, pattern in NAME_RULES:
    RULE_META[key] = FAMILY_REASONS["archivo"]
RULE_META["dotnet_glue"] = "Biblioteca compartida por .NET Android, Xamarin y MAUI; no los distingue."
RULE_META["dotnet_store"] = "Contenedor de ensamblados .NET; su nombre no identifica el framework de UI."
RULE_META["kotlin_module"] = "Metadatos de un módulo Kotlin; pueden proceder de una dependencia."
RULE_META["cpp_lib"] = "Runtime C++ compartido; no atribuye el lenguaje de toda la app."

# Combinaciones concretas; repetir una palabra o sumar marcas débiles nunca confirma.
CORROBORATIONS = {
    "Flutter": (({"flutter_lib", "flutter_assets"}, "Motor libflutter.so y recursos flutter_assets en el mismo contenedor."),),
    "Hermes": (({"hermes_lib", "hermes"}, "Biblioteca libhermes.so y referencias a Hermes en el mismo contenedor."),),
    ".NET para Android / Xamarin.Android": (({"dotnet_glue", "dotnet_store"}, "Puente libmonodroid.so y almacén de ensamblados .NET en el mismo contenedor."),),
}


ANDROID_NS = "http://schemas.android.com/apk/res/android"
MANIFEST_LIMIT = 4 * CHUNK


def manifest_fields(attrs):
    """Leer solo atributos del elemento manifest, respetando sus namespaces."""
    def integer(value):
        try:
            return int(value, 16 if str(value).startswith("0x") else 10)
        except (TypeError, ValueError):
            return None
    code = integer(attrs.get((ANDROID_NS, "versionCode")))
    major = integer(attrs.get((ANDROID_NS, "versionCodeMajor")))
    if code is not None and major is not None and 0 <= code <= 0xffffffff and 0 <= major <= 0xffffffff:
        code |= major << 32
    return {"app_id": attrs.get(("", "package")),
            "version_name": attrs.get((ANDROID_NS, "versionName")), "version_code": code}


def axml_manifest(data):
    """Lector acotado del elemento raíz AXML; no descompila el APK.

    Formato: AOSP androidfw/ResourceTypes.h (ResXMLTree y ResStringPool).
    """
    def chunk(offset, end):
        if offset + 8 > end:
            raise ValueError("Cabecera AXML truncada")
        kind, header, size = struct.unpack_from("<HHI", data, offset)
        if header < 8 or size < header or offset + size > end:
            raise ValueError("Tamaño de bloque AXML inválido")
        return kind, header, offset + size

    kind, head, end = chunk(0, len(data))
    if kind != 3:
        raise ValueError("No es AXML")
    offset, string_at = head, None
    while offset < end:
        kind, header, stop = chunk(offset, end)
        if kind == 1:
            if header < 28:
                raise ValueError("String pool incompleto")
            count, styles, flags, start, style_start = struct.unpack_from("<5I", data, offset + 8)
            if start < header + 4 * (count + styles) or offset + start > stop:
                raise ValueError("Índices del string pool inválidos")
            pool_end = offset + style_start if style_start else stop
            if not offset + start <= pool_end <= stop:
                raise ValueError("Límite del string pool inválido")
            base, indexes, utf8 = offset + start, offset + header, bool(flags & 0x100)

            def string_at(index, base=base, indexes=indexes, count=count, limit=pool_end, utf8=utf8):
                if index == 0xffffffff:
                    return ""
                if index >= count:
                    raise ValueError("Índice de cadena AXML fuera de rango")
                pos = base + struct.unpack_from("<I", data, indexes + 4 * index)[0]
                def length(pos, unit):
                    if pos + unit > limit:
                        raise ValueError("Longitud de cadena truncada")
                    first = int.from_bytes(data[pos:pos + unit], "little")
                    pos += unit
                    mask = 0x80 if unit == 1 else 0x8000
                    if first & mask:
                        if pos + unit > limit:
                            raise ValueError("Longitud de cadena truncada")
                        second = int.from_bytes(data[pos:pos + unit], "little")
                        first = ((first & (mask - 1)) << (unit * 8)) | second
                        pos += unit
                    return first, pos
                if utf8:
                    _, pos = length(pos, 1)
                    size, pos = length(pos, 1)
                    unit, enc = 1, "utf-8"
                else:
                    size, pos = length(pos, 2)
                    size *= 2
                    unit, enc = 2, "utf-16le"
                if pos + size + unit > limit or data[pos + size:pos + size + unit] != b"\0" * unit:
                    raise ValueError("Cadena AXML inválida")
                return data[pos:pos + size].decode(enc)
        elif kind == 0x0102:
            ext = offset + header
            if string_at is None or ext + 20 > stop:
                raise ValueError("Elemento AXML incompleto")
            namespace, name, start, size, count = struct.unpack_from("<IIHHH", data, ext)
            if string_at(name) != "manifest" or string_at(namespace):
                raise ValueError("La raíz no es manifest")
            if start < 20 or size < 20 or ext + start + size * count > stop:
                raise ValueError("Atributos AXML inválidos")
            attrs = {}
            for i in range(count):
                pos = ext + start + size * i
                ns, key, raw = struct.unpack_from("<III", data, pos)
                value_size, _, typ, val = struct.unpack_from("<HBBI", data, pos + 12)
                if value_size < 8:
                    raise ValueError("Valor AXML inválido")
                name, namespace = string_at(key), string_at(ns)
                if (namespace, name) not in (("", "package"), (ANDROID_NS, "versionName"),
                                             (ANDROID_NS, "versionCode"), (ANDROID_NS, "versionCodeMajor")):
                    continue
                if typ == 3:
                    value = string_at(val)
                elif typ in (0x10, 0x11):
                    value = str(val)
                elif typ in (1, 2):
                    value = string_at(raw) if raw != 0xffffffff else f"@0x{val:08x}"
                else:
                    value = string_at(raw) if raw != 0xffffffff else None
                if (namespace, name) in attrs:
                    raise ValueError("Atributo de metadatos duplicado")
                attrs[namespace, name] = value
            return manifest_fields(attrs)
        offset = stop
    raise ValueError("No se encontró el elemento manifest")


def protobuf_fields(data):
    """Campos protobuf sin dependencias; longitud y varints acotados."""
    offset = 0
    def varint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                raise ValueError("Protobuf truncado")
            byte = data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError("Varint protobuf inválido")
    while offset < len(data):
        tag = varint()
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise ValueError("Campo protobuf inválido")
        if wire == 0:
            yield number, wire, varint()
        elif wire in (1, 2, 5):
            length = varint() if wire == 2 else (8 if wire == 1 else 4)
            if offset + length > len(data):
                raise ValueError("Campo protobuf truncado")
            value = data[offset:offset + length]
            offset += length
            yield number, wire, value
        else:
            raise ValueError("Tipo protobuf no compatible")


def proto_manifest(data):
    # AOSP aapt2/Resources.proto: XmlNode.element=1; XmlElement.name=3, attribute=4.
    elements = [v for n, w, v in protobuf_fields(data) if n == 1 and w == 2]
    if len(elements) != 1:
        raise ValueError("Manifest protobuf sin raíz única")
    fields = list(protobuf_fields(elements[0]))
    if next((v for n, w, v in fields if n == 3 and w == 2), None) != b"manifest":
        raise ValueError("La raíz protobuf no es manifest")
    attrs = {}
    for n, w, value in fields:
        if n != 4 or w != 2:
            continue
        attr = {k: v.decode("utf-8") for k, wt, v in protobuf_fields(value) if wt == 2 and k in (1, 2, 3)}
        key = (attr.get(1, ""), attr.get(2, ""))
        if key in attrs:
            raise ValueError("Atributo protobuf duplicado")
        attrs[key] = attr.get(3)  # Un valor compilado sin texto se informa como no disponible.
    return manifest_fields(attrs)


def parse_manifest(data):
    if len(data) > MANIFEST_LIMIT:
        raise ValueError("Manifest mayor de 4 MiB")
    if data[:4] == b"\x03\x00\x08\x00":
        return axml_manifest(data), "AXML"
    if data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<") or data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise ValueError("Manifest con DTD no admitido")
        root = ET.fromstring(text)
        if root.tag != "manifest":
            raise ValueError("La raíz XML no es manifest")
        attrs = {}
        for key, value in root.attrib.items():
            ns, name = key[1:].split("}", 1) if key.startswith("{") else ("", key)
            attrs[ns, name] = value
        return manifest_fields(attrs), "XML"
    return proto_manifest(data), "protobuf"


def package_metadata(path, args):
    """Metadatos reales del manifest o Info.plist de la aplicación principal."""
    meta = {"app_id": None, "version_name": None, "version_code": None,
            "tamano_bytes": path.stat().st_size, "fuente": None, "formato_manifest": None,
            "observacion": None, "plataforma": None, "ejecutable": None}
    def read_entry(archive, entry, limit):
        if entry.flag_bits & 1 or entry.file_size > limit or entry.file_size / max(entry.compress_size, 1) > args.max_ratio:
            raise ValueError("Límite de lectura o entrada cifrada en metadatos")
        with archive.open(entry) as stream:
            value = stream.read(limit + 1)
        if len(value) > limit:
            raise ValueError("Entrada de metadatos demasiado grande")
        return value
    def read_archive(source, label, depth=0):
        with zipfile.ZipFile(source) as archive:
            entries = archive.infolist()
            if len(entries) > args.max_entries:
                raise ValueError("Demasiadas entradas para leer metadatos")
            app_plists = [e for e in entries if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", e.filename)]
            if app_plists:
                if len(app_plists) != 1:
                    raise ValueError("IPA con varios Info.plist principales; ID ambiguo")
                entry = app_plists[0]
                values, fmt = parse_info_plist(read_entry(archive, entry, min(MANIFEST_LIMIT, args.max_file_mb * CHUNK)))
                return dict(values, fuente=f"{label}!{entry.filename}", formato_manifest=fmt,
                            plataforma="iOS", raiz_app=entry.filename.rsplit("/", 1)[0])
            for candidate in ("AndroidManifest.xml", "base/manifest/AndroidManifest.xml"):
                matches = [e for e in entries if e.filename == candidate]
                if len(matches) > 1:
                    raise ValueError("El contenedor tiene manifests duplicados")
                if matches:
                    data = read_entry(archive, matches[0], min(MANIFEST_LIMIT, args.max_file_mb * CHUNK))
                    values, fmt = parse_manifest(data)
                    return dict(values, fuente=f"{label}!{candidate}", formato_manifest=fmt, plataforma="Android")
            if depth == 0:
                apks = [e for e in entries if e.filename.lower().endswith(".apk")]
                apks.sort(key=lambda e: (0 if Path(e.filename).name.lower() in ("base.apk", "base-master.apk", "universal.apk") else 1, e.filename))
                errors = []
                for entry in apks[:8]:
                    try:
                        data = read_entry(archive, entry, min(128 * CHUNK, args.max_file_mb * CHUNK))
                        result = read_archive(io.BytesIO(data), f"{label}!{entry.filename}", 1)
                        if result:
                            return result
                    except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error, ET.ParseError) as exc:
                        errors.append(str(exc))
                if errors:
                    raise ValueError(errors[0])
            return None
    try:
        if path.suffix.lower() in ARCHIVES:
            result = read_archive(path, str(path.resolve()))
            if result:
                meta.update(result)
            else:
                meta["observacion"] = "No se encontró AndroidManifest.xml ni Info.plist de la aplicación principal"
        elif path.name == "AndroidManifest.xml":
            with path.open("rb") as stream:
                values, fmt = parse_manifest(stream.read(MANIFEST_LIMIT + 1))
            meta.update(values, fuente=str(path.resolve()), formato_manifest=fmt, plataforma="Android")
        elif path.name == "Info.plist" and path.parent.suffix.lower() == ".app":
            with path.open("rb") as stream:
                values, fmt = parse_info_plist(stream.read(MANIFEST_LIMIT + 1))
            meta.update(values, fuente=str(path.resolve()), formato_manifest=fmt, plataforma="iOS")
        else:
            meta["observacion"] = "Archivo suelto: ID y versión requieren AndroidManifest.xml o Info.plist de la app"
    except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error, ET.ParseError, struct.error, IndexError) as exc:
        meta["observacion"] = f"No se pudieron leer los metadatos: {exc}"
    return meta


def parse_info_plist(data):
    """plistlib admite XML y plist binario; rechaza entidades XML externas."""
    if len(data) > MANIFEST_LIMIT:
        raise ValueError("Info.plist supera el límite de metadatos")
    try:
        doc = plistlib.loads(data)
    except (ValueError, TypeError, OverflowError, IndexError, struct.error, ExpatError) as exc:
        # plistlib puede lanzar también ExpatError/InvalidFileException.
        raise ValueError("Info.plist inválido: " + str(exc)) from exc
    if not isinstance(doc, dict):
        raise ValueError("Info.plist no contiene un diccionario")
    def string(key):
        value = doc.get(key)
        return value if isinstance(value, str) and value else None
    values = dict(app_id=string("CFBundleIdentifier"), version_name=string("CFBundleShortVersionString"),
                  version_code=string("CFBundleVersion"), ejecutable=string("CFBundleExecutable"),
                  nombre=string("CFBundleDisplayName") or string("CFBundleName"),
                  version_minima_os=string("MinimumOSVersion"))
    return values, "plist binario" if data.startswith(b"bplist00") else "plist XML"


def elf_description(data):
    if len(data) < 52 or not data.startswith(b"\x7fELF") or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        return None
    endian, header_size = ("<" if data[5] == 1 else ">"), (52 if data[4] == 1 else 64)
    if len(data) < header_size:
        return None
    typ, machine, version = struct.unpack_from(endian + "HHI", data, 16)
    ehsize = struct.unpack_from(endian + "H", data, 40 if data[4] == 1 else 52)[0]
    if typ not in (1, 2, 3) or version != 1 or ehsize != header_size:
        return None
    architecture = {3: "x86", 40: "ARM", 62: "x86-64", 183: "ARM64", 243: "RISC-V"}.get(machine, f"máquina {machine}")
    return f"ELF{32 if data[4] == 1 else 64} / {architecture}"


MACHO_MAGICS = {b"\xce\xfa\xed\xfe": ("<", 32), b"\xcf\xfa\xed\xfe": ("<", 64),
               b"\xfe\xed\xfa\xce": (">", 32), b"\xfe\xed\xfa\xcf": (">", 64)}
FAT_MAGICS = {b"\xca\xfe\xba\xbe": (">", 32), b"\xbe\xba\xfe\xca": ("<", 32),
             b"\xca\xfe\xba\xbf": (">", 64), b"\xbf\xba\xfe\xca": ("<", 64)}
MACHO_SOURCE = "https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h"


def parse_macho(stream, size):
    """Lee cabeceras y comandos con límites. Todos los offsets son de archivo.

    No desensambla ni descifra. En FAT valida cada slice por separado; si uno
    falla, conserva los demás y declara análisis parcial. No escanea el padding.
    """
    def read(offset, count):
        if offset < 0 or count < 0 or offset + count > size:
            raise ValueError("Rango Mach-O fuera del archivo")
        stream.seek(offset)
        data = stream.read(count)
        if len(data) != count:
            raise ValueError("Mach-O truncado")
        return data

    def thin(base, length, expected_cpu=None):
        magic = read(base, 4)
        if magic not in MACHO_MAGICS:
            raise ValueError("Slice sin cabecera Mach-O reconocida")
        endian, bits = MACHO_MAGICS[magic]
        header_size = 32 if bits == 64 else 28
        if length < header_size:
            raise ValueError("Cabecera Mach-O truncada")
        header = read(base, header_size)
        cpu, subtype, typ, ncmds, command_bytes, flags = struct.unpack_from(endian + "6I", header, 4)
        if expected_cpu is not None and cpu != expected_cpu:
            raise ValueError("Arquitectura FAT y cabecera Mach-O no coinciden")
        if typ not in range(1, 13):
            raise ValueError("Tipo de archivo Mach-O no reconocido")
        if command_bytes > 8 * CHUNK or command_bytes > length - header_size or ncmds > command_bytes // 8:
            raise ValueError("Tabla de comandos Mach-O inválida o mayor de 8 MiB")
        commands = read(base + header_size, command_bytes)
        arch = {7: "x86", 0x1000007: "x86-64", 12: "ARM", 0x100000c: "ARM64",
                0x200000c: "ARM64_32", 18: "PowerPC", 0x1000012: "PowerPC64"}.get(cpu, f"CPU 0x{cpu:x}")
        if cpu == 0x100000c and (subtype & 0xffffff) == 2:
            arch = "ARM64e"
        out = dict(offset=base, tamano=length, bits=bits, arquitectura=arch, tipo=typ,
                   endian="little" if endian == "<" else "big", cifrado="sin comando de cifrado",
                   rangos_cifrados=[], comandos_cifrado=[], bibliotecas=[], secciones=[])
        cursor = 0
        dylibs = {0xc: "carga", 0xd: "identidad", 0x80000018: "carga débil",
                  0x8000001f: "reexportación", 0x20: "carga diferida", 0x80000023: "carga ascendente"}
        for _ in range(ncmds):
            if cursor + 8 > command_bytes:
                raise ValueError("Comando Mach-O truncado")
            cmd, cmdsize = struct.unpack_from(endian + "II", commands, cursor)
            if cmdsize < 8 or cmdsize % (8 if bits == 64 else 4) or cursor + cmdsize > command_bytes:
                raise ValueError("Tamaño o alineación de comando Mach-O inválido")
            data = commands[cursor:cursor + cmdsize]
            offset = base + header_size + cursor
            if cmd in (0x21, 0x2c):  # LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64
                if cmdsize < (24 if cmd == 0x2c else 20):
                    raise ValueError("Comando de cifrado Mach-O truncado")
                cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", data, 8)
                if cryptoff + cryptsize > length or (cryptid and (not cryptsize or cryptoff < header_size + command_bytes)):
                    raise ValueError("Rango de cifrado Mach-O inválido")
                out["comandos_cifrado"].append(dict(offset=offset, cryptid=cryptid,
                                                      cryptoff=cryptoff, cryptsize=cryptsize))
                if cryptid:
                    out["rangos_cifrados"].append([base + cryptoff, base + cryptoff + cryptsize])
            elif cmd in dylibs:
                if cmdsize < 24:
                    raise ValueError("Comando de biblioteca Mach-O truncado")
                name_offset = struct.unpack_from(endian + "I", data, 8)[0]
                end = data.find(b"\0", name_offset) if 24 <= name_offset < cmdsize else -1
                if end < 0 or end - name_offset > 4096:
                    raise ValueError("Nombre de biblioteca Mach-O inválido")
                out["bibliotecas"].append(dict(nombre=data[name_offset:end].decode("utf-8", "replace"),
                                                tipo=dylibs[cmd], offset=offset + name_offset))
            elif cmd in (1, 0x19):  # LC_SEGMENT / LC_SEGMENT_64
                is64 = cmd == 0x19
                segment_size, section_size = (72, 80) if is64 else (56, 68)
                if cmdsize < segment_size:
                    raise ValueError("Comando de segmento Mach-O truncado")
                section_count = struct.unpack_from(endian + "I", data, 64 if is64 else 48)[0]
                if segment_size + section_count * section_size > cmdsize:
                    raise ValueError("Tabla de secciones Mach-O truncada")
                for i in range(section_count):
                    pos = segment_size + i * section_size
                    section = data[pos:pos + section_size]
                    name = section[:16].split(b"\0", 1)[0].decode("ascii", "replace")
                    segname = section[16:32].split(b"\0", 1)[0].decode("ascii", "replace")
                    amount = struct.unpack_from(endian + ("Q" if is64 else "I"), section, 40 if is64 else 36)[0]
                    fileoff = struct.unpack_from(endian + "I", section, 48 if is64 else 40)[0]
                    secttype = struct.unpack_from(endian + "I", section, 64 if is64 else 56)[0] & 0xff
                    zerofill = secttype in (1, 0xc, 0x12)
                    if not zerofill and fileoff + amount > length:
                        raise ValueError("Sección Mach-O fuera del slice")
                    out["secciones"].append(dict(nombre=name, segmento=segname, tamano=amount,
                                                offset=base + fileoff, zerofill=zerofill,
                                                offset_cabecera=offset + pos))
            cursor += cmdsize
        if cursor != command_bytes:
            raise ValueError("sizeofcmds no coincide con los comandos Mach-O")
        out["rangos_cifrados"] = merge_ranges(out["rangos_cifrados"])
        if out["rangos_cifrados"]:
            out["cifrado"] = "cifrado declarado (cryptid != 0)"
        elif out["comandos_cifrado"]:
            out["cifrado"] = "sin cifrado declarado (cryptid = 0)"
        return out

    magic = read(0, 4)
    report = dict(formato="Mach-O", slices=[], errores=[])
    if magic in MACHO_MAGICS:
        report["slices"].append(thin(0, size))
        return report
    if magic not in FAT_MAGICS:
        raise ValueError("No es un Mach-O reconocido")
    endian, bits = FAT_MAGICS[magic]
    report["formato"] = f"Mach-O universal / FAT{bits}"
    count = struct.unpack(endian + "I", read(4, 4))[0]
    if not 1 <= count <= 64:
        raise ValueError("Número de slices FAT inválido o mayor de 64")
    record_size = 32 if bits == 64 else 20
    table_end = 8 + count * record_size
    table = read(8, count * record_size)
    slices = []
    for i in range(count):
        values = struct.unpack_from(endian + ("IIQQII" if bits == 64 else "IIIII"), table, i * record_size)
        cpu, _, offset, length, alignment = values[:5]
        if alignment > 63 or offset < table_end or length < 28 or offset + length > size or offset % (1 << alignment):
            raise ValueError("Offset, tamaño o alineación FAT inválidos")
        slices.append((offset, length, cpu))
    slices.sort()
    if any(a + length > b for (a, length, _), (b, _, _) in zip(slices, slices[1:])):
        raise ValueError("Slices FAT superpuestos")
    for offset, length, cpu in slices:
        try:
            report["slices"].append(thin(offset, length, cpu))
        except ValueError as exc:
            report["errores"].append(f"Slice @0x{offset:x}: {exc}")
    return report


def merge_ranges(ranges):
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return merged


def readable_ranges(part):
    position, end = part["offset"], part["offset"] + part["tamano"]
    for start, stop in part["rangos_cifrados"]:
        if position < start:
            yield position, start
        position = stop
    if position < end:
        yield position, end


def apple_content_path(name):
    """Incluye ejecutables sin extensión y con punto dentro de .app/.framework."""
    normal = name.replace("\\", "/")
    return bool(re.search(r"(?:^|/)[^/]+\.(?:app|framework|appex)/(?:Versions/[^/]+/)?[^/]+$", normal)
                or "/flutter_assets/" in normal or "/www/" in normal or "/public/" in normal)


def rust_v0_candidate(symbol):
    """Filtro sintáctico conservador, no un demangler ni prueba de compilación.

    Valida longitudes, terminadores, referencias previas y consumo completo.
    Los tags no soportados se descartan. Evita confundir RC2/RCT con Rust.
    Referencia: https://doc.rust-lang.org/rustc/symbol-mangling/v0.html
    """
    if symbol.startswith(b"__R"):  # prefijo adicional de símbolos Mach-O
        symbol = symbol[1:]
    if not symbol.startswith(b"_R") or len(symbol) > 772:
        return False
    try:
        text = symbol[2:].decode("ascii")
    except UnicodeDecodeError:
        return False
    position, work = 0, 0
    completed = {"path": set(), "type": set(), "const": set()}
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def peek():
        return text[position:position + 1]

    def take(expected=None):
        nonlocal position
        char = peek()
        if not char or (expected is not None and char != expected):
            raise ValueError("Token incompleto")
        position += 1
        return char

    def optional(char):
        if peek() == char:
            take()
            return True
        return False

    def decimal():
        if optional("0"):
            return 0
        start = position
        while peek() and peek() in "0123456789":
            take()
        if start == position or position - start > 4:
            raise ValueError("Longitud inválida")
        return int(text[start:position])

    def base62():
        value, start = 0, position
        while peek() and peek() in alphabet:
            value = value * 62 + alphabet.index(take())
        if position - start > 16:
            raise ValueError("Número excesivo")
        empty = position == start
        take("_")
        return 0 if empty else value + 1

    def disambiguator():
        if optional("s"):
            base62()

    def identifier(disambiguated=True):
        nonlocal position
        if disambiguated:
            disambiguator()
        optional("u")
        length = decimal()
        optional("_")
        end = position + length
        if end > len(text) or any(c not in alphabet + "_" for c in text[position:end]):
            raise ValueError("Identificador incompleto")
        position = end

    def lifetime():
        take("L")
        base62()

    def parse(kind, depth=0):
        nonlocal work
        work += 1
        if depth > 64 or work > 2048:
            raise ValueError("Símbolo demasiado complejo")
        start = position
        tag = take()
        def sub(part):
            parse(part, depth + 1)
        if tag == "B":
            target = base62()
            valid = completed[kind] | (completed["path"] if kind == "type" else set())
            if target >= start or target not in valid:
                raise ValueError("Backref inválida")
        elif kind == "path":
            if tag == "C":
                identifier()
            elif tag == "N":
                if take() not in alphabet[10:]:
                    raise ValueError("Namespace inválido")
                sub("path")
                identifier()
            elif tag in ("M", "X"):
                disambiguator()
                sub("path")
                sub("type")
                if tag == "X":
                    sub("path")
            elif tag == "Y":
                sub("type")
                sub("path")
            elif tag == "I":
                sub("path")
                while peek() != "E":
                    if peek() == "L":
                        lifetime()
                    elif optional("K"):
                        sub("const")
                    else:
                        sub("type")
                take("E")
            else:
                raise ValueError("Ruta no soportada")
        elif kind == "type":
            if tag in "abcdefghijklmnopqrstuvwxyz":
                pass
            elif tag in "CNMXYI":
                # Devolver el tag al parser de rutas.
                rewind(start)
                sub("path")
            elif tag in "ASPO":
                sub("type")
                if tag == "A":
                    sub("const")
            elif tag in "RQ":
                if peek() == "L":
                    lifetime()
                sub("type")
            elif tag == "T":
                while peek() != "E":
                    sub("type")
                take("E")
            elif tag == "F":
                if optional("G"):
                    base62()
                optional("U")
                if optional("K") and not optional("C"):
                    identifier(False)
                while peek() != "E":
                    sub("type")
                take("E")
                sub("type")
            elif tag == "D":
                if optional("G"):
                    base62()
                while peek() != "E":
                    sub("path")
                    while optional("p"):
                        identifier(False)
                        sub("type")
                take("E")
                lifetime()
            else:
                raise ValueError("Tipo no soportado")
        elif tag != "p":
            rewind(start)
            sub("type")
            optional("n")
            while peek() and peek() in "0123456789abcdef":
                take()
            take("_")
        completed[kind].add(start)

    def rewind(offset):
        nonlocal position
        position = offset

    try:
        if peek() and peek() in "0123456789":
            decimal()
        parse("path")
        if position < len(text):
            parse("path")  # crate de instanciación opcional
        return position == len(text)
    except (ValueError, RecursionError):
        return False


def safe(value):
    return json.dumps(str(value), ensure_ascii=False)[1:-1]


def short_path(value):
    """Ruta legible en pantalla; el informe conserva la ruta y entrada originales."""
    parts = str(value).split("!")
    parts = [re.sub(r" \[entrada \d+\]$", "", part) for part in parts]
    return safe("!".join(parts[1:]) if len(parts) > 1 else Path(parts[0]).name)


def evidence_path(value):
    """Conservar el APK de origen y toda la ruta interna, sin el prefijo del PC."""
    parts = [re.sub(r" \[entrada \d+\]$", "", p) for p in str(value).split("!")]
    parts[0] = Path(parts[0]).name
    return safe("!".join(parts))


def evidence_order(item):
    return (LEVEL_ORDER[item["fuerza"]], 0 if item["familia"] == "namespace" else 1,
            item["regla"], item["archivo"], item["offset"] or 0)


def representative_items(items, limit=2):
    """Una muestra por regla; no repetir tres offsets o ABI del mismo indicador."""
    selected, seen = [], set()
    for item in sorted(items, key=evidence_order):
        if item["regla"] in seen:
            continue
        seen.add(item["regla"])
        selected.append(item)
        if len(selected) >= limit:
            break
    return selected


def section_for(category):
    if category == "Framework":
        return "FRAMEWORKS DE DESARROLLO"
    if category.startswith("Protección"):
        return "PROTECCIONES Y SDK DE SEGURIDAD"
    if category == "Biblioteca":
        return "OTRAS TECNOLOGÍAS"
    return "LENGUAJES Y MOTORES"


SECTIONS = ("FRAMEWORKS DE DESARROLLO", "PROTECCIONES Y SDK DE SEGURIDAD",
            "LENGUAJES Y MOTORES", "OTRAS TECNOLOGÍAS")


def fit(text, width):
    """Evitar que una fila de progreso se envuelva, también con nombres Unicode."""
    used, out = 0, []
    for char in text:
        size = 0 if unicodedata.combining(char) else (2 if unicodedata.east_asian_width(char) in "WF" else 1)
        if used + size > max(0, width - 3):
            return "".join(out) + "..."
        used += size
        out.append(char)
    return text


class Display:
    COLORS = {"green": "32", "yellow": "33", "cyan": "36", "red": "31", "bold": "1"}

    def __init__(self, stream=None, color="auto"):
        self.stream = stream if stream is not None else sys.stdout
        self.tty = self.stream.isatty() and os.environ.get("TERM") != "dumb"
        self.color = color == "always" or (color == "auto" and self.tty and "NO_COLOR" not in os.environ)
        self.encoding = getattr(self.stream, "encoding", None) or "utf-8"
        try:
            "✓●→⠋🔎".encode(self.encoding)
            self.unicode = True
        except (UnicodeEncodeError, LookupError):
            self.unicode = False

    def symbol(self, unicode, ascii):
        return unicode if self.unicode else ascii

    def paint(self, text, color):
        return f"\033[{self.COLORS[color]}m{text}\033[0m" if self.color else text

    def write(self, text):
        self.stream.write(text.encode(self.encoding, errors="replace").decode(self.encoding))
        self.stream.flush()

    def line(self, text="", color=None):
        self.write((self.paint(text, color) if color else text) + "\n")

    def wrapped(self, text, indent="    ", color=None):
        width = max(30, shutil.get_terminal_size((100, 24)).columns - 1)
        for line in textwrap.wrap(text, width=width, initial_indent=indent,
                                  subsequent_indent=indent + "  ", break_on_hyphens=False) or [indent]:
            self.line(line, color)

    def highlighted(self, prefix, emphasis, suffix="", indent="    "):
        """Ajustar líneas antes de insertar ANSI para mantener la alineación."""
        text = prefix + emphasis + suffix
        start, end, position = len(prefix), len(prefix) + len(emphasis), 0
        width = max(30, shutil.get_terminal_size((100, 24)).columns - 1) - len(indent)
        for part in textwrap.wrap(text, width=width, break_on_hyphens=False, expand_tabs=False,
                                  replace_whitespace=False, drop_whitespace=False) or [""]:
            left, right = max(0, start - position), min(len(part), end - position)
            styled = part
            if left < right:
                styled = part[:left] + self.paint(part[left:right], "bold") + part[right:]
            self.line(indent + styled.rstrip())
            position += len(part)


class Progress:
    """Tres filas reutilizables: archivo actual y los dos últimos analizados."""
    def __init__(self, display, enabled=True, message="Analizando archivos..."):
        self.display, self.enabled = display, enabled and display.tty
        self.message = message
        self.started = time.monotonic()
        self.stage, self.current, self.recent, self.count = "Preparando", "archivos", [], 0
        self.lock, self.stop_event = threading.Lock(), threading.Event()
        self.thread = None
        self.reserved = False

    def update(self, stage, path):
        with self.lock:
            self.stage, self.current = stage, short_path(path)

    def done(self, path):
        with self.lock:
            self.count += 1
            self.recent = [short_path(path)] + self.recent[:1]

    def render(self, frame):
        with self.lock:
            stage, current, recent, count = self.stage, self.current, list(self.recent), self.count
        elapsed = int(time.monotonic() - self.started)
        frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if self.display.unicode else "|/-\\"
        mark = self.display.symbol("✓", "+")
        rows = [f"{frames[frame % len(frames)]} {elapsed // 60:02}:{elapsed % 60:02} | {count} analizados | {stage}: {current}"]
        rows.extend(f"{mark} Revisado: {name}" for name in recent)
        rows.extend(["  Esperando el siguiente archivo..."] * (3 - len(rows)))
        width = max(4, shutil.get_terminal_size((80, 24)).columns - 1)
        self.display.write("\033[3F" + "".join(
            "\033[2K" + self.display.paint(fit(row, width), "cyan" if n == 0 else "green") + "\n"
            for n, row in enumerate(rows)))

    def animate(self):
        frame = 1
        while not self.stop_event.wait(0.12):
            self.render(frame)
            frame += 1

    def __enter__(self):
        if self.enabled:
            self.reserved = True
            try:
                self.display.write("\033[?25l\n\n\n")
                self.render(0)
                self.thread = threading.Thread(target=self.animate, daemon=True)
                self.thread.start()
            except BaseException:
                self.__exit__(None, None, None)
                raise
        else:
            self.display.line(self.message)
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop_event.set()
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join()
        if self.reserved:
            self.display.write("\033[3F\033[J\033[?25h")
            self.reserved = False


class Scanner:
    def __init__(self, args, progress=None):
        self.args = args
        self.progress = progress
        self.limit_file, self.limit_total = args.max_file_mb * CHUNK, args.max_total_mb * CHUNK
        self.read_bytes = self.files_scanned = self.names_scanned = self.ignored = 0
        self.evidence, self.issues, self.inputs = [], [], []
        self.macho_binaries, self.encrypted_bytes = [], 0
        self.metadata = {}
        self.seen, self.samples, self.fatal = set(), {}, False

    def issue(self, path, why, fatal=False):
        self.issues.append({"archivo": path, "motivo": why})
        self.fatal |= fatal

    def add(self, key, tech, cat, level, family, label, path, offset, encoding, kind, matched=None,
            link_type=None):
        if key == "rust_v0" and not rust_v0_candidate((matched or label).encode("ascii", "replace")):
            return
        unique, bucket = (key, path, offset, encoding), (key, path)
        if unique in self.seen or self.samples.get(bucket, 0) >= 3:
            return
        self.seen.add(unique)
        self.samples[bucket] = self.samples.get(bucket, 0) + 1
        reason = RULE_META[key]
        if link_type == "carga débil":
            level = "probable"
            reason = "Referencia opcional (LC_LOAD_WEAK_DYLIB); no demuestra uso del componente."
        elif link_type == "identidad":
            reason = "Identidad del framework dentro de un binario Mach-O incluido en el paquete."
        member = re.sub(r" \[entrada \d+\]$", "", str(path).split("!")[-1])
        name = Path(member).name.lower()
        documentation = (Path(member).suffix.lower() in {".md", ".txt", ".log"}
                         or name.startswith(("readme", "license", "notice", "changelog")))
        if level == "especifica" and kind not in {"ELF", "Mach-O"} and documentation:
            level = "probable"
            reason = "Referencia en texto o documentación; puede describir un componente no integrado."
        self.evidence.append(dict(regla=key, tecnologia=tech, categoria=cat, fuerza=level,
                                 familia=family, indicador=label, archivo=path, offset=offset,
                                 codificacion=encoding, tipo_archivo=kind,
                                 coincidencia=label if matched is None else matched, motivo=reason,
                                 **({"tipo_enlace": link_type} if link_type else {})))

    def names(self, path, name):
        if self.progress:
            self.progress.update("Comprobando", path)
        self.names_scanned += 1
        for key, tech, cat, level, pattern in NAME_RULES:
            if pattern.search(name.replace("\\", "/")):
                filename = name.replace("\\", "/").rsplit("/", 1)[-1]
                self.add(key, tech, cat, level, "archivo", "Nombre de archivo", path, None, "nombre", "ruta", filename)

    def permitted(self, path, size):
        if size > self.limit_file:
            self.issue(path, "Omitido: supera --max-file-mb")
            return False
        if self.read_bytes + size > self.limit_total:
            self.issue(path, "Omitido: supera presupuesto --max-total-mb")
            return False
        return True

    def scan_bytes(self, data, origin, path, native, kind, final=False):
        folded = data.lower()
        for rule in RULES:
            if ((rule["native"] and not native) or
                    (rule.get("formats") and kind not in rule["formats"]) or
                    self.samples.get((rule["key"], path), 0) >= 3):
                continue
            for pattern, encoding in rule["patterns"]:
                for match in pattern.finditer(folded if rule["fold"] else data):
                    if rule["key"] == "rust_v0" and match.end() == len(data) and not final:
                        continue  # esperar el bloque siguiente antes de validar el símbolo
                    self.add(rule["key"], rule["tech"], rule["category"], rule["level"], rule["family"],
                             rule["label"], path, origin + match.start(), encoding, kind,
                             data[match.start():match.end()].decode("ascii" if encoding == "bytes" else encoding, errors="replace"))
                    if self.samples.get((rule["key"], path), 0) >= 3:
                        break

    def inspect_macho(self, first, stream, path):
        # Spool local acotado: no cargar un ejecutable de 128 MiB completo en RAM.
        with tempfile.SpooledTemporaryFile(max_size=8 * CHUNK, mode="w+b") as binary_file:
            consumed, chunk = 0, first
            while chunk:
                if self.read_bytes + len(chunk) > self.limit_total or consumed + len(chunk) > self.limit_file:
                    self.issue(path, "Lectura Mach-O detenida por límite de bytes")
                    return
                binary_file.write(chunk)
                consumed += len(chunk)
                self.read_bytes += len(chunk)
                chunk = stream.read(CHUNK)
            try:
                result = parse_macho(binary_file, consumed)
            except ValueError as exc:
                result = dict(formato="Mach-O no validado", slices=[], errores=[str(exc)])
            self.macho_binaries.append(dict(archivo=path, **result))
            for error in result["errores"]:
                self.issue(path, error)
            for part in result["slices"]:
                self.add("native_macho", "Código nativo (Mach-O)", "Biblioteca", "especifica", "formato",
                         "Cabecera Mach-O", path, part["offset"], "cabecera", "Mach-O",
                         f"Mach-O{part['bits']} / {part['arquitectura']}")
                encrypted = sum(end - start for start, end in part["rangos_cifrados"])
                if encrypted:
                    self.encrypted_bytes += encrypted
                    self.issue(path, f"{part['arquitectura']}: código cifrado declarado; {encrypted} bytes excluidos de la búsqueda")
                for library in part["bibliotecas"]:
                    name = library["nombre"]
                    framework = re.search(r"(?:^|/)([^/]+)\.framework/(?:Versions/[^/]+/)?([^/]+)$", name)
                    if framework and framework[1] == framework[2] and framework[1] in IOS_FRAMEWORKS:
                        tech, cat = IOS_FRAMEWORKS[framework[1]]
                        self.add("ios_link_" + framework[1], tech, cat, "especifica", "dependencia",
                                 "Comando de enlace Mach-O", path, library["offset"], "load command", "Mach-O", name,
                                 link_type=library["tipo"])
                    for pattern, key, tech in (
                        (r"(?:^|/)libswiftCore\.dylib$", "swift_link", "Swift (runtime / metadatos)"),
                        (r"(?:^|/)libobjc(?:\.[^/]+)?\.dylib$", "objc_link", "Objective-C (runtime)"),
                        (r"(?:^|/)libc\+\+(?:\.[^/]+)?\.dylib$", "cpp_ios_link", "C++ (runtime)"),
                    ):
                        if re.search(pattern, name):
                            self.add(key, tech, "Lenguaje o runtime", "especifica", "dependencia",
                                     "Runtime enlazado", path, library["offset"], "load command", "Mach-O", name,
                                     link_type=library["tipo"])
                for section in part["secciones"]:
                    if not section["tamano"] or section["zerofill"]:
                        continue
                    if any(section["offset"] < end and section["offset"] + section["tamano"] > start
                           for start, end in part["rangos_cifrados"]):
                        continue
                    if section["nombre"].startswith("__swift5_"):
                        key, tech = "swift_section", "Swift (runtime / metadatos)"
                    elif section["nombre"] in ("__objc_classlist", "__objc_catlist", "__objc_classrefs", "__objc_imageinfo"):
                        key, tech = "objc_section", "Objective-C (runtime)"
                    else:
                        continue
                    self.add(key, tech, "Lenguaje o runtime", "especifica", "sección",
                             "Sección Mach-O", path, section["offset_cabecera"], "sección", "Mach-O",
                             section["segmento"] + "/" + section["nombre"])
                # Reiniciar tail en cada rango evita unir texto a través de bytes
                # cifrados, padding FAT o dos arquitecturas distintas.
                for start, end in readable_ranges(part):
                    binary_file.seek(start)
                    position, tail = start, b""
                    while position < end:
                        chunk = binary_file.read(min(CHUNK, end - position))
                        if not chunk:
                            self.issue(path, "Lectura Mach-O incompleta")
                            break
                        data = tail + chunk
                        self.scan_bytes(data, position - len(tail), path, True, "Mach-O",
                                        final=(position + len(chunk) == end))
                        position += len(chunk)
                        tail = data[-OVERLAP:]
        self.files_scanned += 1
        if self.progress:
            self.progress.done(path)

    def inspect(self, stream, path):
        if self.progress:
            self.progress.update("Analizando", path)
        first = stream.read(CHUNK)
        if first[:4] in MACHO_MAGICS or first[:4] in FAT_MAGICS:
            self.inspect_macho(first, stream, path)
            return
        tail, consumed, native = b"", 0, None
        chunk = first
        while chunk:
            if self.read_bytes + len(chunk) > self.limit_total or consumed + len(chunk) > self.limit_file:
                self.issue(path, "Lectura detenida por límite de bytes")
                return
            if native is None:
                native = chunk.startswith(b"\x7fELF")
                kind = "ELF" if native else ("DEX" if chunk.startswith(b"dex\n") else "contenido")
                elf = elf_description(chunk)
                if elf:
                    self.add("native_elf", "Código nativo (ELF)", "Biblioteca", "especifica", "formato",
                             "Cabecera ELF", path, 0, "cabecera", "ELF", elf)
            data, origin = tail + chunk, consumed - len(tail)
            self.scan_bytes(data, origin, path, native, kind)
            consumed += len(chunk)
            self.read_bytes += len(chunk)
            tail = data[-OVERLAP:]
            chunk = stream.read(CHUNK)
        if consumed:
            self.scan_bytes(tail, consumed - len(tail), path, native, kind, final=True)
        self.files_scanned += 1
        if self.progress:
            self.progress.done(path)

    def inspect_entry(self, archive, entry, path):
        """Estado independiente por miembro; patrones y ZIP compartidos de solo lectura."""
        worker = Scanner(self.args, self.progress)
        # ZipExtFile limita la lectura al tamaño declarado. La reserva global
        # ya se hizo en el coordinador; no compartir contadores mutables.
        worker.limit_total = entry.file_size
        worker.names(path, entry.filename)
        try:
            with archive.open(entry) as stream:
                worker.inspect(stream, path)
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, NotImplementedError, zlib.error) as exc:
            worker.issue(path, f"Error de lectura: {exc}")
        return worker

    def merge_worker(self, worker):
        """Solo el coordinador agrega resultados, en orden del contenedor."""
        self.read_bytes += worker.read_bytes
        self.files_scanned += worker.files_scanned
        self.names_scanned += worker.names_scanned
        self.ignored += worker.ignored
        self.encrypted_bytes += worker.encrypted_bytes
        self.macho_binaries.extend(worker.macho_binaries)
        self.issues.extend(worker.issues)
        self.fatal |= worker.fatal
        for item in worker.evidence:
            unique = (item["regla"], item["archivo"], item["offset"], item["codificacion"])
            bucket = (item["regla"], item["archivo"])
            if unique not in self.seen and self.samples.get(bucket, 0) < 3:
                self.seen.add(unique)
                self.samples[bucket] = self.samples.get(bucket, 0) + 1
                self.evidence.append(item)

    def archive(self, source, label, depth=0, executor=None):
        workers = getattr(self.args, "threads", 1)
        if executor is None and workers > 1:
            # Un único pool, también para los contenedores anidados. Los workers
            # nunca esperan otros futures: la recursión la realiza el coordinador.
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="appdn") as pool:
                return self.archive(source, label, depth, pool)
        if self.progress:
            self.progress.update("Abriendo", label)
        try:
            with zipfile.ZipFile(source) as archive:
                entries = archive.infolist()
                if len(entries) > self.args.max_entries:
                    self.issue(label, "Omitido: demasiadas entradas ZIP")
                    return
                pending, reserved = deque(), 0

                def collect_one():
                    nonlocal reserved
                    future, size = pending[0]
                    self.merge_worker(future.result())
                    pending.popleft()
                    reserved -= size

                try:
                    for index, entry in enumerate(entries):
                        if entry.is_dir():
                            continue
                        path = f"{label}!{entry.filename} [entrada {index}]"
                        suffix = Path(entry.filename).suffix.lower()
                        nested = suffix in ARCHIVES
                        eligible = suffix in CONTENT or "/assets/" in "/" + entry.filename.lower() or apple_content_path(entry.filename)
                        parallel = (executor is not None and not nested and eligible
                                    and not (entry.flag_bits & 1)
                                    and ((entry.external_attr >> 16) & 0o170000) != 0o120000
                                    and entry.file_size / max(entry.compress_size, 1) <= self.args.max_ratio
                                    and entry.file_size <= self.limit_file)
                        if parallel:
                            # Cola acotada y reserva ANTES de lanzar el trabajo.
                            # Si falta presupuesto, esperar lecturas anteriores:
                            # un error/CRC puede consumir menos de lo anunciado.
                            while pending and (len(pending) >= workers * 2 or
                                               self.read_bytes + reserved + entry.file_size > self.limit_total):
                                collect_one()
                            if self.read_bytes + reserved + entry.file_size <= self.limit_total:
                                future = executor.submit(self.inspect_entry, archive, entry, path)
                                pending.append((future, entry.file_size))
                                reserved += entry.file_size
                                continue
                        # Mantener exactamente el orden original de evidencias,
                        # incidencias y presupuesto, incluso al entrar en otro ZIP.
                        while pending:
                            collect_one()
                        self.names(path, entry.filename)
                        if not nested and not eligible:
                            self.ignored += 1
                            continue
                        if entry.flag_bits & 1:
                            self.issue(path, "Omitido: entrada cifrada")
                            continue
                        if ((entry.external_attr >> 16) & 0o170000) == 0o120000:
                            self.issue(path, "Omitido: enlace simbólico dentro del contenedor")
                            continue
                        if entry.file_size / max(entry.compress_size, 1) > self.args.max_ratio:
                            self.issue(path, "Omitido: ratio de compresión excesivo")
                            continue
                        if not self.permitted(path, entry.file_size):
                            continue
                        try:
                            with archive.open(entry) as stream:
                                if nested:
                                    if depth >= 2:
                                        self.issue(path, "Omitido: anidamiento mayor de 2")
                                        continue
                                    data = stream.read(self.limit_file + 1)
                                    if len(data) > self.limit_file:
                                        self.issue(path, "Omitido: contenedor supera límite")
                                        continue
                                    self.read_bytes += len(data)
                                    self.archive(io.BytesIO(data), path, depth + 1, executor)
                                else:
                                    self.inspect(stream, path)
                        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, NotImplementedError, zlib.error) as exc:
                            self.issue(path, f"Error de lectura: {exc}")
                    while pending:
                        collect_one()
                finally:
                    # No cerrar el ZIP mientras un worker todavía lo utiliza,
                    # también ante Ctrl+C o una excepción inesperada.
                    futures = [future for future, _ in pending]
                    for future in futures:
                        future.cancel()
                    if futures:
                        wait(futures)
        except (OSError, ValueError, zipfile.BadZipFile, zlib.error) as exc:
            self.issue(label, f"Contenedor inválido: {exc}", fatal=(depth == 0))

    def file(self, path):
        label = str(path.resolve())
        if self.progress:
            self.progress.update("Calculando huella", label)
        try:
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(CHUNK), b""):
                    digest.update(chunk)
            self.inputs.append({"archivo": label, "sha256": digest.hexdigest(),
                                "tamano_bytes": path.stat().st_size, "aplicacion": self.metadata.get(label)})
            self.names(label, path.as_posix())
            if path.suffix.lower() in ARCHIVES:
                self.archive(path, label)
            elif self.permitted(label, path.stat().st_size):
                with path.open("rb") as stream:
                    self.inspect(stream, label)
        except (OSError, ValueError, RuntimeError, zlib.error) as exc:
            self.issue(label, str(exc), fatal=True)

    def report(self):
        groups = {}
        for item in self.evidence:
            group = groups.setdefault(item["tecnologia"], dict(tecnologia=item["tecnologia"],
                                      categoria=item["categoria"], evidencias=[]))
            group["evidencias"].append(item)
        for group in groups.values():
            levels = {e["fuerza"] for e in group["evidencias"]}
            group["evaluacion"] = ("EVIDENCIA_ESPECIFICA" if "especifica" in levels else
                                   "PROBABLE" if "probable" in levels else "INDICIO_NO_CONFIRMADO")
            group["reglas_distintas"] = len({e["regla"] for e in group["evidencias"]})
            group["familias"] = sorted({e["familia"] for e in group["evidencias"]})
            group["seccion"] = section_for(group["categoria"])
            group["tipo"], reference = TECH_INFO.get(group["tecnologia"], ("candidato a protector", None))
            group["referencias"] = [reference] if reference else []
            ios_reference = IOS_TECH_SOURCES.get(group["tecnologia"])
            if ios_reference and any(e["regla"].startswith("ios_") or e["tipo_archivo"] == "Mach-O"
                                     for e in group["evidencias"]):
                group["referencias"].insert(0, ios_reference)
            group["motivo"] = min(group["evidencias"], key=evidence_order)["motivo"]
            group["corroboracion"] = []
            # No combinar huellas de APK independientes para elevar la confianza.
            containers = {}
            for e in group["evidencias"]:
                if "!" in e["archivo"]:
                    containers.setdefault(e["archivo"].split("!")[0], set()).add(e["regla"])
            if group["evaluacion"] != "EVIDENCIA_ESPECIFICA":
                for required, reason in CORROBORATIONS.get(group["tecnologia"], ()):
                    matching = next((c for c, keys in containers.items() if required <= keys), None)
                    if matching:
                        group["evaluacion"] = "EVIDENCIA_ESPECIFICA"
                        group["motivo"] = reason
                        group["corroboracion"] = representative_items([
                            e for e in group["evidencias"] if e["regla"] in required
                            and e["archivo"].split("!")[0] == matching], len(required))
                        break
            # La confianza en una huella y lo que demuestra son cosas distintas.
            # No presentar un framework débilmente enlazado como implementación.
            items = group["evidencias"]
            group["alcance"] = "huellas del componente"
            if all(e.get("tipo_enlace") == "carga débil" for e in items):
                group["alcance"] = "dependencia opcional"
            elif all(e.get("tipo_enlace") and e["tipo_enlace"] != "identidad" for e in items):
                group["alcance"] = "runtime enlazado" if group["categoria"] == "Lenguaje o runtime" else "dependencia enlazada"
        return dict(herramienta="MobScope", version=VERSION, fecha_utc=datetime.now(timezone.utc).isoformat(), entradas=self.inputs,
                    analisis_incompleto=bool(self.issues),
                    estadisticas=dict(archivos_analizados=self.files_scanned, nombres_analizados=self.names_scanned,
                                      bytes_leidos=self.read_bytes, archivos_fuera_de_seleccion=self.ignored,
                                      bytes_cifrados_excluidos=self.encrypted_bytes),
                    binarios_macho=self.macho_binaries,
                    resultados=sorted(groups.values(), key=lambda g: (g["categoria"], g["tecnologia"])),
                    incidencias=self.issues,
                    limites=["Presencia estática no equivale a activación, vulnerabilidad o bypass.",
                             "Rust puede pertenecer a una biblioteca; no implica RASP ni que toda la app use Rust.",
                             "Sin coincidencias no descarta componentes ofuscados, cifrados o sin símbolos.",
                             "Offsets relativos al miembro descomprimido; máximo tres muestras por regla y archivo.",
                             "Varios APK se agregan: usar juntos solo splits de la misma app.",
                             "Mach-O: se validan cabeceras y comandos thin/FAT32/FAT64; no se desensambla ni se descifra.",
                             "Las regiones Mach-O con cryptid != 0 no se buscan; no tener comando de cifrado no garantiza ausencia de otras protecciones.",
                             "Se analizan ejecutables, frameworks y recursos compatibles; no se interpreta semánticamente todo el código.",
                             "Se buscan huellas en DLL y almacenes .NET; no se descomprimen ensamblados XALZ ni se desofuscan.",
                             "Framework identificado significa componentes presentes, no que toda la interfaz use ese framework.",
                             "Rust v0 usa un filtro sintáctico conservador; formatos futuros no soportados pueden no detectarse.",
                             "Otros fabricantes son candidatos heredados del original, sin muestras de validación."])


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Debe ser mayor que cero")
    return number


def show_metadata(display, files, metadata, verbose=False):
    containers = [p for p in files if p.suffix.lower() in ARCHIVES or p.name == "AndroidManifest.xml"
                  or (p.name == "Info.plist" and p.parent.suffix.lower() == ".app")]
    selected = containers or (files if len(files) == 1 else [])
    if not selected and files:
        total = sum(metadata.get(str(p), {}).get("tamano_bytes", 0) for p in files)
        display.line(f"\nEntradas: {len(files)} archivos sueltos · {total / CHUNK:.2f} MiB")
        display.line("ID y versión: requieren AndroidManifest.xml o Info.plist de la app.")
    for path in selected if verbose else selected[:6]:
        meta = metadata.get(str(path), {})
        size = meta.get("tamano_bytes")
        weight = f"{size / CHUNK:.2f} MiB" if size is not None else "tamaño no disponible"
        display.line()
        display.highlighted("Archivo: ", safe(path.name), " · " + weight, indent="  ")
        ios = meta.get("plataforma") == "iOS"
        if meta.get("plataforma"):
            display.highlighted("Plataforma: ", meta["plataforma"], indent="  ")
        display.highlighted("Bundle ID: " if ios else "ID de app: ", safe(meta.get("app_id") or "no disponible"), indent="  ")
        version = str(meta.get("version_name") or "no disponible")
        if version.startswith("@"):
            version += " (referencia sin resolver)"
        code = meta.get("version_code")
        build_label = "Build" if ios else "Código"
        display.highlighted("Versión: ", safe(version), f" · {build_label}: {safe(code) if code is not None else 'no disponible'}", indent="  ")
        if meta.get("ejecutable"):
            display.highlighted("Ejecutable: ", safe(meta["ejecutable"]), indent="  ")
        if meta.get("fuente"):
            display.wrapped("Fuente: " + evidence_path(meta["fuente"]), indent="  ")
        if meta.get("observacion"):
            display.wrapped(safe(meta["observacion"]), indent="  ")
    if not verbose and len(selected) > 6:
        display.line(f"  + {len(selected) - 6} entradas; metadatos adicionales en --verbose o JSON.")
    if files:
        display.line()


def show_report(display, report, verbose, elapsed, evidence_limit=2):
    width = max(30, shutil.get_terminal_size((100, 24)).columns - 1)
    states = {
        "EVIDENCIA_ESPECIFICA": (display.symbol("✓", "+"), "IDENTIFICADO", "green"),
        "PROBABLE": (display.symbol("●", "~"), "PROBABLE", "yellow"),
        "INDICIO_NO_CONFIRMADO": ("?", "POR CONFIRMAR", "yellow"),
    }
    groups = report["resultados"]
    binaries = report.get("binarios_macho", [])
    if binaries:
        parts = [part for binary in binaries for part in binary["slices"]]
        architectures = " / ".join(sorted({part["arquitectura"] for part in parts})) or "no validada"
        encrypted = sum(bool(part["rangos_cifrados"]) for part in parts)
        display.line()
        noun = "binario" if len(binaries) == 1 else "binarios"
        display.line(f"  Mach-O: {len(binaries)} {noun} · {architectures}", "cyan")
        if encrypted:
            display.line(f"  {display.symbol('🔒', '!')} {encrypted} arquitecturas con código cifrado · análisis parcial", "yellow")
            display.wrapped("Se revisan las partes accesibles. Los rangos cifrados quedan fuera de la búsqueda.", indent="  ")
        elif parts:
            display.line("  Cifrado: sin regiones declaradas activas en los Mach-O validados.")
        if verbose:
            for binary in binaries:
                for part in binary["slices"]:
                    display.wrapped(f"{safe(binary['archivo'])} · {part['arquitectura']} · {part['cifrado']}", indent="  ")
    for title in SECTIONS:
        section = [g for g in groups if g["seccion"] == title]
        display.line()
        display.line(title, "cyan")
        if not section:
            display.line("  Sin coincidencias en los archivos revisados.")
        for group in sorted(section, key=lambda g: (
                {"EVIDENCIA_ESPECIFICA": 0, "PROBABLE": 1, "INDICIO_NO_CONFIRMADO": 2}[g["evaluacion"]],
                g["tecnologia"])):
            icon, label, color = states[group["evaluacion"]]
            scope = group.get("alcance")
            if scope == "dependencia opcional":
                icon, label, color = display.symbol("●", "~"), "DEPENDENCIA OPCIONAL", "yellow"
            elif scope in ("runtime enlazado", "dependencia enlazada"):
                label = scope.upper()
            role = f" ({group['tipo']})" if group["categoria"].startswith("Protección") else ""
            display.line(f"  {icon} {group['tecnologia']}{role} — {label}", color)
            items = sorted(group["evidencias"], key=evidence_order)
            if not verbose:
                items = group["corroboracion"] or representative_items(items, evidence_limit)
            for item in items:
                source = safe(item["archivo"]) if verbose else evidence_path(item["archivo"])
                marker = safe(item["coincidencia"])
                if item["codificacion"] == "nombre":
                    marker += " (nombre de archivo)"
                if item.get("tipo_enlace") == "carga débil":
                    marker += " (enlace opcional)"
                offset = f" @0x{item['offset']:x}" if verbose and item["offset"] is not None else ""
                display.highlighted(f"{display.symbol('↳', '>')} {source}{offset} → ", marker)
            display.highlighted("", "Motivo:", " " + group["motivo"])
            if verbose:
                for reference in group["referencias"]:
                    display.wrapped("Referencia: " + reference)
    issues, stats = report["incidencias"], report["estadisticas"]
    display.line()
    duration = f"{elapsed:.1f} s"
    scanned = f"{stats['archivos_analizados']} " + ("archivo" if stats['archivos_analizados'] == 1 else "archivos")
    if issues:
        display.line(f"  ! Análisis parcial · {scanned} · {len(issues)} incidencias · {duration}", "yellow")
        for issue in issues if verbose else issues[:3]:
            message = f"    {safe(issue['archivo']) if verbose else short_path(issue['archivo'])}: {safe(issue['motivo'])}"
            display.line(message if verbose else fit(message, width))
        if not verbose and len(issues) > 3:
            display.line(f"    + {len(issues) - 3} incidencias. Consulta --verbose o el JSON.")
    else:
        display.line(f"  {display.symbol('✓', '+')} Finalizado · {scanned} · {stats['bytes_leidos'] / CHUNK:.1f} MB · {duration}", "green")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("entradas", nargs="*", help="APK/IPA/APKS/XAPK/AAB/ZIP, carpeta .app/splits, Mach-O, .so, .dll o bundle")
    parser.add_argument("--json", dest="json_path", help="Guardar metadatos, resumen y muestras conservadas como JSON")
    parser.add_argument("--verbose", action="store_true", help="Mostrar rutas completas y todas las muestras conservadas (máx. 3 por regla/archivo)")
    parser.add_argument("--evidence", type=positive, default=2, metavar="N", help="Hasta N huellas distintas por tecnología (2 por defecto; una corroboración siempre muestra sus dos huellas)")
    parser.add_argument("--list-technologies", action="store_true", help="Mostrar tecnologías y tipo de firmas disponibles, sin analizar archivos")
    parser.add_argument("--no-progress", action="store_true", help="Desactivar la animación de tres líneas")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="Colores de terminal (auto por defecto)")
    parser.add_argument("--no-color", action="store_const", const="never", dest="color", help="Desactivar colores")
    parser.add_argument("--threads", type=positive, default=min(4, os.cpu_count() or 1), metavar="N",
                        help="Hilos para archivos internos de APK/IPA y otros ZIP (por defecto: hasta 4 según CPU; 1 = secuencial)")
    parser.add_argument("--max-file-mb", type=positive, default=128)
    parser.add_argument("--max-total-mb", type=positive, default=1024)
    parser.add_argument("--max-entries", type=positive, default=20000)
    parser.add_argument("--max-ratio", type=positive, default=300)
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    display = Display(color=args.color)
    display.line(f"{display.symbol('🔎', '>')} MobScope {VERSION} · Tecnologías y protecciones Android + iOS", "cyan")
    if args.list_technologies:
        catalog = {}
        for rule in RULES:
            key = (rule["tech"], rule["category"])
            catalog.setdefault(key, set()).add(rule["level"])
        for key, tech, category, level, pattern in NAME_RULES:
            catalog.setdefault((tech, category), set()).add(level)
        catalog[("Código nativo (ELF)", "Biblioteca")] = {"especifica"}
        catalog[("Código nativo (Mach-O)", "Biblioteca")] = {"especifica"}
        for framework, (tech, category) in IOS_FRAMEWORKS.items():
            catalog.setdefault((tech, category), set()).add("especifica")
        for tech in ("Swift (runtime / metadatos)", "Objective-C (runtime)", "C++ (runtime)"):
            catalog.setdefault((tech, "Lenguaje o runtime"), set()).add("especifica")
        for title in SECTIONS:
            display.line("\n" + title, "cyan")
            for (tech, cat), levels in sorted(catalog.items()):
                if section_for(cat) == title:
                    kind = "solo menciones débiles" if levels == {"indicio"} else "huellas de contenido / archivos"
                    display.line(f"  {tech} · {kind}")
        return 0
    if not args.entradas:
        parser.error("Indica un archivo o carpeta, o usa --list-technologies")
    display.line("Análisis estático de APK, IPA, bibliotecas y bundles.")
    started = time.monotonic()
    progress = Progress(display, not args.no_progress, "Leyendo datos de la aplicación...")
    scan, files = Scanner(args, progress), []
    output_path = Path(args.json_path).resolve() if args.json_path else None
    with progress:
        for item in args.entradas:
            path = Path(item)
            progress.update("Buscando archivos", path)
            if path.is_dir():
                try:
                    selected = sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink()
                                      and (p.suffix.lower() in ARCHIVES | CONTENT or apple_content_path(p.as_posix()))
                                      and p.resolve() != output_path)
                    files.extend(selected)
                    if not selected:
                        scan.issue(str(path), "Carpeta sin archivos compatibles", fatal=True)
                except OSError as exc:
                    scan.issue(str(path), str(exc), fatal=True)
            elif path.is_file():
                files.append(path)
            else:
                scan.issue(str(path), "Archivo no encontrado", fatal=True)
        files = list(dict.fromkeys(p.resolve() for p in files))
        output_conflict = output_path in files
        if not output_conflict:
            for path in files:
                progress.update("Leyendo metadatos", path)
                try:
                    scan.metadata[str(path)] = package_metadata(path, args)
                except OSError as exc:
                    scan.metadata[str(path)] = {"observacion": str(exc)}
    if output_conflict:
        parser.error("--json no puede sobrescribir una entrada")
    show_metadata(display, files, scan.metadata, args.verbose)
    scan.progress = Progress(display, not args.no_progress,
                             f"Analizando archivos... ({args.threads} hilo(s))")
    with scan.progress:
        for path in files:
            scan.file(path)
    report = scan.report()
    show_report(display, report, args.verbose, time.monotonic() - started, args.evidence)
    if args.json_path:
        try:
            Path(args.json_path).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            display.line("  Informe JSON: " + safe(args.json_path), "cyan")
        except OSError as exc:
            print(f"Error al escribir JSON: {safe(exc)}", file=sys.stderr)
            return 2
    return 2 if scan.fatal else (1 if scan.issues else 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrumpido; no se obtuvo un resultado completo.", file=sys.stderr)
        sys.exit(130)
