plugins { id("buildlogic.kotlin-library-conventions") }

dependencies {
    api(project(":codyze-evaluator"))

    testImplementation(testFixtures(project(":codyze-evaluator")))
}
