/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.query.Must
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.and
import de.fraunhofer.aisec.cpg.query.dataFlow
import de.fraunhofer.aisec.openstack.concepts.auth.AuthorizationWithPolicy
import de.fraunhofer.aisec.openstack.concepts.auth.Authorize
import de.fraunhofer.aisec.openstack.concepts.auth.ExtendedRequestContext
import de.fraunhofer.aisec.openstack.passes.auth.AuthorizationPass
import de.fraunhofer.aisec.openstack.passes.auth.OsloPolicyPass
import de.fraunhofer.aisec.openstack.passes.auth.PreAuthorizationPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import kotlin.io.path.Path
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AuthorizationPassTest {
    @Test
    fun authorizationPass() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<PreAuthorizationPass>()
                it.registerPass<AuthorizationPass>()
                it.registerPass<HttpWsgiPass>()
                it.registerPass<OsloPolicyPass>()
                it.exclusionPatterns("tests", "drivers")
                it.includePath("../external/oslo.policy")
                it.includePath("../external/oslo.context")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to
                            listOf(
                                topLevel.resolve("cinder/cinder/api").toFile(),
                                topLevel.resolve("cinder/cinder/policies").toFile(),
                                topLevel.resolve("cinder/cinder/context.py").toFile(),
                                topLevel.resolve("cinder/cinder/policy.py").toFile(),
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
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

    @Test
    fun testDomainIsUsedInAuthorization() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<PreAuthorizationPass>()
                it.registerPass<AuthorizationPass>()
                it.registerPass<HttpWsgiPass>()
                it.registerPass<OsloPolicyPass>()
                it.exclusionPatterns("tests", "drivers", "sqlalchemy")
                it.includePath("../external/oslo.policy")
                it.includePath("../external/oslo.context")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to
                            listOf(
                                topLevel.resolve("cinder/cinder/api").toFile(),
                                topLevel.resolve("cinder/cinder/policies").toFile(),
                                topLevel.resolve("cinder/cinder/context.py").toFile(),
                                topLevel.resolve("cinder/cinder/policy.py").toFile(),
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }
        assertNotNull(result)
        val q =
            result.allExtended<HttpEndpoint>(
                sel = { it.authorization != null },
                mustSatisfy = { endpoint ->
                    val targetValues = endpoint.targetValuesForUserOrProject()
                    endpoint
                        .hasDataFlowToDomain(targetValues)
                        .and(endpoint.hasDataFlowFromPolicyToAuthorizeAction())
                },
            )

        assertTrue(q.value)
        println(q.printNicely())
    }

    /**
     * Checks if there is a data flow from any authorization target to one of the provided
     * [targetValues].
     */
    fun HttpEndpoint.hasDataFlowToDomain(targetValues: Set<Node?>): QueryTree<Boolean> {
        val flows =
            this.authorization?.ops?.filterIsInstance<Authorize>()?.flatMap { auth ->
                auth.targets.map { target ->
                    dataFlow(
                        startNode = target,
                        type = Must,
                        direction = Backward(GraphToFollow.DFG),
                        predicate = { dataFlowNode ->
                            val ref = dataFlowNode as? Reference
                            targetValues.contains(ref?.refersTo)
                        },
                    )
                }
            } ?: emptyList()

        return QueryTree(
            value = flows.all { it.value },
            children = flows.toMutableList(),
            stringRepresentation =
                if (flows.isEmpty()) "No data flows from targets to domain values"
                else "All data flows to domain values are valid",
            node = this,
        )
    }

    /**
     * Extracts relevant target values (e.g., user ID and project ID) from the request context of
     * the [HttpEndpoint] [this].
     *
     * Note: This logic may need to be adapted if other identifiers are also relevant.
     */
    fun HttpEndpoint.targetValuesForUserOrProject(): Set<Node?> {
        val userInfo = (this.requestContext as? ExtendedRequestContext)?.userInfo
        return setOf(userInfo?.userId, userInfo?.projectId)
    }

    /**
     * Checks if there is a data flow from the policy reference into the `action` argument of the
     * `policy.authorize` call.
     */
    fun HttpEndpoint.hasDataFlowFromPolicyToAuthorizeAction(): QueryTree<Boolean> {
        val policyRef =
            (this.authorization as? AuthorizationWithPolicy)?.policy?.policyRef
                ?: return QueryTree(
                    value = false,
                    stringRepresentation = "No policy found",
                    node = this,
                )

        return dataFlow(
            startNode = policyRef,
            predicate = { dataflowNode ->
                val authorizeCall = dataflowNode.astParent as? CallExpression
                authorizeCall?.overlays?.filterIsInstance<Authorize>()?.isNotEmpty() == true &&
                    authorizeCall.arguments.getOrNull(1) == dataflowNode
            },
        )
    }
}
