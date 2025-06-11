/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.authorization

import de.fraunhofer.aisec.codyze.*
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import kotlin.io.path.Path
import kotlin.test.*

/**
 * This test suite contains tests for domain-based authorization checks using the
 * [OpenStackProfile]. It includes tests for database query filters, domain usage in authorization,
 * and unauthorized response handling.
 */
class DomainCheckTest {

    /**
     * Test case for [databaseAccessBasedOnDomainOrProject] using [OpenStackProfile]. The analyzed
     * component is [Cinder].
     */
    @Test
    fun testDatabaseAccessBasedOnDomainOrProject() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                OpenStackProfile(it)
                it.exclusionPatterns("tests", "drivers", "migrations")
                it.taggingProfiles { tagDatabaseAccess() }
                it.softwareComponents(
                    mutableMapOf(
                        Cinder.name to
                            listOf(topLevel.resolve("cinder/cinder/db/sqlalchemy/api.py").toFile())
                    )
                )
                it.topLevels(mapOf(Cinder.name to topLevel.resolve("cinder").toFile()))
            }

        assertNotNull(result)
        with(result) {
            val q = databaseAccessBasedOnDomainOrProject()
            assertFalse(q.value)
        }
    }

    /**
     * Test case for [endpointAuthorizationBasedOnDomainOrProject] using [OpenStackProfile]. The
     * analyzed component is [Cinder].
     */
    @Test
    fun testEndpointAuthorizationBasedOnDomainOrProject() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                OpenStackProfile(it)
                it.exclusionPatterns("tests", "drivers", "sqlalchemy")
                it.includePath("external/oslo.policy")
                it.includePath("external/oslo.context")
                it.softwareComponents(
                    mutableMapOf(
                        Cinder.name to
                            listOf(
                                topLevel.resolve("cinder/cinder/api").toFile(),
                                topLevel.resolve("cinder/cinder/policies").toFile(),
                                topLevel.resolve("cinder/cinder/context.py").toFile(),
                                topLevel.resolve("cinder/cinder/policy.py").toFile(),
                            ),
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
                        KeystoneMiddleware.name to topLevel.resolve("keystonemiddleware").toFile(),
                        Conf.name to topLevel.resolve("conf").toFile(),
                    )
                )
            }
        assertNotNull(result)

        with(result) {
            val q = endpointAuthorizationBasedOnDomainOrProject()
            assertFalse(q.value)
            assertEquals(
                62,
                q.children.size,
                "Expected 62 endpoints with domain-based authorization",
            )
            assertEquals(
                62,
                q.children.map { it.children[0] }.filter { it.value == true }.size,
                "Expected all 62 endpoints to pass target-value checks",
            )

            val failingPolicyEndpoints =
                q.children.map { it.children[1] }.filter { it.value == false }
            assertEquals(
                8,
                failingPolicyEndpoints.size,
                "Expected 8 endpoints to fail domain-based policy authorization checks",
            )
        }
    }

    /**
     * Test case for [unauthorizedResponseFromAnotherDomainQuery] using [OpenStackProfile]. The
     * analyzed component is [Cinder].
     */
    @Test
    fun testUnauthorizedResponseFromAnotherDomainQuery() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                OpenStackProfile(it)
                it.registerPass<ProgramDependenceGraphPass>()
                it.exclusionPatterns("tests", "drivers", "sqlalchemy")
                it.includePath("external/oslo.policy")
                it.includePath("external/oslo.context")
                it.softwareComponents(
                    mutableMapOf(
                        Cinder.name to
                            listOf(
                                topLevel.resolve("cinder/cinder/api").toFile(),
                                topLevel.resolve("cinder/cinder/policies").toFile(),
                                topLevel.resolve("cinder/cinder/context.py").toFile(),
                                topLevel.resolve("cinder/cinder/policy.py").toFile(),
                                topLevel.resolve("cinder/cinder/exception.py").toFile(),
                                topLevel.resolve("cinder/cinder/i18n.py").toFile(),
                            ),
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
                        Conf.name to topLevel.resolve("conf").toFile(),
                        KeystoneMiddleware.name to topLevel.resolve("keystonemiddleware").toFile(),
                    )
                )
                it.taggingProfiles { tagDomainScope() }
            }
        assertNotNull(result)
        with(result) {
            val q =
                unauthorizedResponseFromAnotherDomainQuery(policy = UnauthorizedResponsePolicy())
            assertFalse(q.value)
        }
    }
}
