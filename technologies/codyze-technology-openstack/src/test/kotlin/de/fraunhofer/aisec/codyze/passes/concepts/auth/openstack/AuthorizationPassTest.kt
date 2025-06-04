/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.auth.openstack

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.concepts.auth.Authorize
import de.fraunhofer.aisec.codyze.passes.concepts.http.python.HttpWsgiPass
import de.fraunhofer.aisec.codyze.queries.authorization.*
import de.fraunhofer.aisec.codyze.technology.openstack.*
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.passes.concepts.*
import kotlin.io.path.Path
import kotlin.test.*

/**
 * This test suite contains tests for the [AuthorizationPass], which analyzes OpenStack
 * [Authorization] concepts and their relationships with [HttpEndpoint]s.
 */
class AuthorizationPassTest {

    /**
     * Test case to verify that the [AuthorizationPass] correctly identifies [Authorization]
     * concepts and their relationships with [HttpEndpoint]s.
     */
    @Test
    fun testAuthorizationPass() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<PreAuthorizationPass>()
                it.registerPass<AuthorizationPass>()
                it.registerPass<HttpWsgiPass>()
                it.registerPass<OsloPolicyPass>()
                it.exclusionPatterns("tests", "drivers")
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
                        Conf.name to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        Cinder.name to topLevel.resolve("cinder").toFile(),
                        Conf.name to topLevel.resolve("conf").toFile(),
                    )
                )
            }
        assertNotNull(result)

        val authorizations = result.conceptNodes.filterIsInstance<Authorization>()
        assertNotNull(authorizations)

        val endpoints = result.conceptNodes.filterIsInstance<HttpEndpoint>()
        assertNotNull(endpoints)
        val endpointsWithAuthZ = endpoints.filter { it.authorization != null }
        assertNotNull(endpointsWithAuthZ, "Some endpoints should have authorization assigned")

        // Check some endpoints as an example
        endpointsWithAuthZ.take(3).forEach { endpoint ->
            val auth = endpoint.authorization
            assertNotNull(auth, "Authorization should not be null")
            val relatedAuthzOps = auth.ops.singleOrNull()
            assertNotNull(relatedAuthzOps, "Authorization should have an operation")
            assertIs<Authorize>(relatedAuthzOps)
            val action = relatedAuthzOps.action
            assertNotNull(action, "Authorize operation should have an associated action")
            val targets = relatedAuthzOps.targets
            assertNotNull(targets, "Authorize operation should have targets")
        }
    }
}
