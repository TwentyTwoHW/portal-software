plugins {
    id("java-gradle-plugin")
    `kotlin-dsl`
}

gradlePlugin {
    plugins {
        create("uniFfiAndroidBindings") {
            id = "xyz.twenty_two.plugins.generate-android-bindings"
            implementationClass = "xyz.twenty_two.plugins.UniFfiAndroidPlugin"
        }
    }
}
