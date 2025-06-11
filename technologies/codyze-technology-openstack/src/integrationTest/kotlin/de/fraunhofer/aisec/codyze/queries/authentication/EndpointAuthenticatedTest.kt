/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.authentication

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * This test suite contains tests for authentication-related queries in OpenStack in [Cinder] and
 * [Barbican].
 */
class EndpointAuthenticatedTest {

    /**
     * Test case for [endpointsAreAuthenticated] using [OpenStackProfile]. The analyzed components
     * are [Cinder], [Barbican].
     */
    @Test
    fun testEndpointsAreAuthenticated() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                OpenStackProfile(it)
                it.exclusionPatterns("tests", "drivers")
                it.includePath("external/oslo.context")
                it.softwareComponents(
                    mutableMapOf(
                        Cinder.name to listOf(topLevel.resolve("cinder/cinder/api").toFile()),
                        Barbican.name to listOf(topLevel.resolve("barbican/barbican/api").toFile()),
                        KeystoneMiddleware.name to
                            listOf(
                                topLevel.resolve("keystonemiddleware/keystonemiddleware").toFile()
                            ),
                        Conf.name to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        Cinder.name to topLevel.resolve("cinder").toFile(),
                        Barbican.name to topLevel.resolve("barbican").toFile(),
                        KeystoneMiddleware.name to topLevel.resolve("keystonemiddleware").toFile(),
                        Conf.name to topLevel.resolve("conf").toFile(),
                    )
                )
            }
        assertNotNull(result)

        with(result) {
            val r =
                endpointsAreAuthenticated(
                    shouldHaveAuthentication = HttpEndpoint::isCurrentBarbicanOrCinderAPI
                )
            assertTrue(r.value)
            println(r.printNicely())
        }
    }
}
