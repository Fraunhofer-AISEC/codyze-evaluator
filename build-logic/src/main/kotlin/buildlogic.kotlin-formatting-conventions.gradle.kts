import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.diffplug.spotless")
}

tasks.withType<KotlinCompile> {
    dependsOn("spotlessApply")
}

val headerWithStars = """/*
 * This file is part of the OpenStack Checker
 */
"""

spotless {
    kotlin {
        target("**/*.kt", "**/*.codyze.kts")
        ktfmt().kotlinlangStyle()
        licenseHeader(headerWithStars).yearSeparator(" - ")
    }
    kotlinGradle {
        ktfmt().kotlinlangStyle()
    }
}
