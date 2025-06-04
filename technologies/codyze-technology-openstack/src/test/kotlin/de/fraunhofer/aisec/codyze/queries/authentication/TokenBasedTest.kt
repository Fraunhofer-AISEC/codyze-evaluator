/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.authentication

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.technology.openstack.*
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.passes.concepts.*
import de.fraunhofer.aisec.cpg.query.and
import kotlin.io.path.Path
import kotlin.test.*
import org.junit.jupiter.api.Test

/**
 * This test suite contains tests for token-based authentication queries in OpenStack components. It
 * checks whether a valid token provider is configured and whether access tokens are used correctly.
 */
class TokenBasedTest {

    /**
     * Test case for [tokenBasedAuthenticationWhenRequired] using [OpenStackProfile]. The analyzed
     * components are [Cinder] and [Barbican].
     */
    @Test
    fun testTokenBasedAuthenticationWhenRequired() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                OpenStackProfile(it)
                it.exclusionPatterns("tests", "drivers")
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
            // Is a valid token provider configured?
            val r = tokenBasedAuthenticationWhenRequired()
            assertTrue(r.value)
            println(r.printNicely())
        }
    }

    /**
     * Test case for [usesSameTokenAsCredential] using [OpenStackProfile] in the
     * [KeystoneMiddleware] library.
     */
    @Test
    fun testUsesSameTokenAsCredential() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.exclusionPatterns("tests")
                it.includePath("external/keystoneauth")
                it.softwareComponents(
                    mutableMapOf(
                        KeystoneMiddleware.name to
                            listOf(
                                topLevel.resolve("keystonemiddleware/keystonemiddleware").toFile()
                            )
                    )
                )
                it.topLevels(
                    mapOf(
                        KeystoneMiddleware.name to topLevel.resolve("keystonemiddleware").toFile()
                    )
                )
                it.registerPass<TagOverlaysPass>()
                it.configurePass<TagOverlaysPass>(
                    TagOverlaysPass.Configuration(
                        tag = tag { tagKeystoneMiddlewareAuthentication() }
                    )
                )
            }

        assertNotNull(result)
        with(result) {
            val q = usesSameTokenAsCredential() and hasDataFlowToToken()
            assertFalse(q.value)
        }
    }
}
