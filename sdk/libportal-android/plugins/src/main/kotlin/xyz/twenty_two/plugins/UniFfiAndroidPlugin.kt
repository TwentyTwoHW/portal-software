package xyz.twenty_two.plugins

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.Copy
import org.gradle.api.tasks.Exec
import org.gradle.kotlin.dsl.environment
import org.gradle.kotlin.dsl.getValue
import org.gradle.kotlin.dsl.provideDelegate
import org.gradle.kotlin.dsl.register

internal class UniFfiAndroidPlugin : Plugin<Project> {
    override fun apply(target: Project): Unit = target.run {
        // arm64-v8a is the most popular hardware architecture for Android
        val buildAndroidAarch64Binary by tasks.register<Exec>("buildAndroidAarch64Binary") {
            workingDir("${projectDir}/../../")
            val cargoArgs: List<String> = listOf("ndk", "-t", "arm64-v8a", "build", "--release", "--features", "android,bindings,debug")

            executable("cargo")
            args(cargoArgs)

            doLast {
                println("Native library on aarch64 built successfully")
            }
        }

        // the x86_64 version of the library is mostly used by emulators
        val buildAndroidX86_64Binary by tasks.register<Exec>("buildAndroidX86_64Binary") {
            workingDir("${projectDir}/../../")
            val cargoArgs: List<String> = listOf("ndk", "-t", "x86_64", "build", "--release", "--features", "android,bindings,debug")

            executable("cargo")
            args(cargoArgs)

            doLast {
                println("Native library on x86_64 built successfully")
            }
        }

        // used by some emulators
        val buildAndroidX86Binary by tasks.register<Exec>("buildAndroidX86Binary") {
            workingDir("${projectDir}/../../")
            val cargoArgs: List<String> = listOf("ndk", "-t", "x86", "build", "--release", "--features", "android,bindings,debug")

            executable("cargo")
            args(cargoArgs)

            doLast {
                println("Native library on x86 built successfully")
            }
        }

        // armeabi-v7a version of the library for older 32-bit Android hardware
        val buildAndroidArmv7Binary by tasks.register<Exec>("buildAndroidArmv7Binary") {
            workingDir("${projectDir}/../../")
            val cargoArgs: List<String> = listOf("ndk", "-t", "armeabi-v7a", "build", "--release", "--features", "android,bindings,debug")

            executable("cargo")
            args(cargoArgs)

            doLast {
                println("Native library on armv7 built successfully")
            }
        }

        // move the native libs build by cargo from target/<architecture>/release/
        // to their place in the libportal library
        // the task only copies the available binaries built using the buildAndroid<architecture>Binary tasks
        val moveNativeAndroidLibs by tasks.register<Copy>("moveNativeAndroidLibs") {
            dependsOn(buildAndroidAarch64Binary)
            dependsOn(buildAndroidX86_64Binary)

            into("${project.projectDir}/src/main/jniLibs/")

            into("arm64-v8a") {
                from("${project.projectDir}/../../../target/aarch64-linux-android/release/libportal.so")
            }

            into("x86_64") {
                from("${project.projectDir}/../../../target/x86_64-linux-android/release/libportal.so")
            }

            into("x86") {
                from("${project.projectDir}/../../../target/i686-linux-android/release/libportal.so")
            }

            into("armeabi-v7a") {
                from("${project.projectDir}/../../../target/armv7-linux-androideabi/release/libportal.so")
            }

            doLast {
                println("Native binaries for Android moved to ./lib/src/main/jniLibs/")
            }
        }

        // generate the bindings using the uniffi-bindgen tool
        val generateAndroidBindings by tasks.register<Exec>("generateAndroidBindings") {
            dependsOn(moveNativeAndroidLibs)

            val libraryPath = "${project.projectDir}/../../../target/aarch64-linux-android/release/libportal.so"
            workingDir("${project.projectDir}/")
            val cargoArgs: List<String> = listOf("run", "--features=bindings", "--bin", "uniffi-bindgen", "generate", "--library", libraryPath, "--language", "kotlin", "--out-dir", "./src/main/kotlin", "--no-format")

            executable("cargo")
            args(cargoArgs)

            doLast {
                println("Android bindings file successfully created")
            }
        }

        // create an aggregate task which will run the required tasks to build the Android libs in order
        // the task will also appear in the printout of the ./gradlew tasks task with group and description
        tasks.register("buildAndroidLib") {
            group = "Bitcoindevkit"
            description = "Aggregate task to build Android library"

            dependsOn(
                buildAndroidAarch64Binary,
                buildAndroidX86_64Binary,
                buildAndroidX86Binary,
                buildAndroidArmv7Binary,
                moveNativeAndroidLibs,
                generateAndroidBindings
            )
        }
    }
}
