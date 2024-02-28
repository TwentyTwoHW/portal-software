# libportal-android
This project builds an .aar package for the Android platform that provide Kotlin language bindings for the Portal SDK.

## How to Use
To use the Kotlin language bindings in your Android project add the following to your gradle dependencies:
```kotlin
repositories {
    mavenCentral()
}

dependencies { 
    implementation("xyz.twenty_two:libportal-android:<version>")
}
```

You may then import and use the `xyz.twenty_two` library in your Kotlin code.

### Snapshot releases
To use a snapshot release, specify the snapshot repository url in the `repositories` block and use the snapshot version in the `dependencies` block:
```kotlin
repositories {
    maven("https://s01.oss.sonatype.org/content/repositories/snapshots/")
}

dependencies { 
    implementation("xyz.twenty_two:libportal-android:<version-SNAPSHOT>")
}
```

### How to build
_Note that Kotlin version `1.6.10` or later is required to build the library._

1. Install required targets
```sh
rustup target add x86_64-linux-android aarch64-linux-android armv7-linux-androideabi i686-linux-android
```
2. Install `cargo-ndk`
```sh
cargo install cargo-ndk
```
3. Install Android SDK and Build-Tools for API level 30+
4. Setup `$ANDROID_SDK_ROOT` and `$ANDROID_NDK_ROOT` path variables (which are required by the
   build tool), for example (note that currently, NDK version 25.2.9519653 or above is required):
```shell
export ANDROID_SDK_ROOT=~/Android/Sdk
export ANDROID_NDK_ROOT=$ANDROID_SDK_ROOT/ndk/25.2.9519653
```
5. Build kotlin bindings
 ```sh
 # build Android library
 ./gradlew buildAndroidLib
 ```

## How to publish to your local Maven repo
```shell
./gradlew publishToMavenLocal --exclude-task signMavenPublication
```

Note that the commands assume you don't need the local libraries to be signed. If you do wish to sign them, simply set your `~/.gradle/gradle.properties` signing key values like so:
```properties
signing.gnupg.keyName=<YOUR_GNUPG_ID>
signing.gnupg.passphrase=<YOUR_GNUPG_PASSPHRASE>
```

and use the `publishToMavenLocal` task without excluding the signing task:
```shell
./gradlew publishToMavenLocal
```

## Known issues
### JNA dependency
Depending on the JVM version you use, you might not have the JNA dependency on your classpath. The exception thrown will be
```shell
class file for com.sun.jna.Pointer not found
```
The solution is to add JNA as a dependency like so:
```kotlin
dependencies {
    // ...
    implementation("net.java.dev.jna:jna:5.14.0")
}
```
