/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.codyze.concepts.auth.Authorize
import de.fraunhofer.aisec.codyze.queries.authorization.UnauthorizedResponsePolicy
import de.fraunhofer.aisec.codyze.queries.authorization.databaseAccessBasedOnDomainOrProject
import de.fraunhofer.aisec.codyze.queries.authorization.endpointAuthorizationBasedOnDomainOrProject
import de.fraunhofer.aisec.codyze.queries.authorization.unauthorizedResponseFromAnotherDomainQuery
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull

class AuthorizationPassTest {
    @Test
    fun authorizationPass() {
        val topLevel = Path("external")
        val result = analyze(listOf(), topLevel, true)
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

    @Test
    fun testDatabaseQueryFilter() {
        val topLevel = Path("external")
        val result = analyze(listOf(), topLevel, true)

        assertNotNull(result)
        with(result) {
            val q = databaseAccessBasedOnDomainOrProject()
            assertFalse(q.value)
        }
    }

    @Test
    fun testDomainIsUsedInAuthorization() {
        val topLevel = Path("external")
        val result = analyze(listOf(), topLevel, true)
        assertNotNull(result)
        with(result) {
            val q = endpointAuthorizationBasedOnDomainOrProject()
            assertFalse(q.value)
            println(q.printNicely())
        }
    }

    @Test
    fun testUnauthorizedResponse() {
        val topLevel = Path("external")
        val result = analyze(listOf(), topLevel, true)
        assertNotNull(result)
        with(result) {
            val q =
                unauthorizedResponseFromAnotherDomainQuery(policy = UnauthorizedResponsePolicy())
            assertFalse(q.value)
        }
    }
}
