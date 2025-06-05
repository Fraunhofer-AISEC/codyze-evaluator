/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.authentication

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import kotlin.io.path.Path
import kotlin.test.*
import org.junit.jupiter.api.Test

/**
 * This test suite contains tests for queries that check whether an OpenStack component uses
 * [Keystone] for authentication.
 */
class KeystoneUseTest {

    /**
     * Test case for [useKeystoneForAuthentication] using [OpenStackProfile]. The analyzed
     * components are [Cinder] and [Barbican].
     */
    @Test
    fun testAuthStrategyProvider() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                OpenStackProfile(it)
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        Cinder.name to listOf(topLevel.resolve("cinder/cinder/api").toFile()),
                        Barbican.name to listOf(topLevel.resolve("barbican/barbican/api").toFile()),
                        Conf.name to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        Cinder.name to topLevel.resolve("cinder/api").toFile(),
                        Barbican.name to topLevel.resolve("barbican/api").toFile(),
                        Conf.name to topLevel.resolve("conf").toFile(),
                    )
                )
            }
        assertNotNull(result)

        with(result) {
            val query = useKeystoneForAuthentication()
            println(query.printNicely())
            assertEquals(true, query.value)
        }
    }
}
