plugins { id("buildlogic.kotlin-application-conventions") }

dependencies {
    api(project(":app"))
    api(libs.bundles.cpg)
}
