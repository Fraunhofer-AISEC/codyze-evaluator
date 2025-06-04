plugins { id("buildlogic.kotlin-application-conventions") }

dependencies {
    api(project(":codyze-evaluator"))
    api(project(":codyze-query-catalog"))
    api(project(":codyze-technology-openstack"))
}
