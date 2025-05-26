/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.declarations.RecordDeclaration
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.graph.statements.ThrowExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.query.Must
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.and
import de.fraunhofer.aisec.cpg.query.dataFlow
import de.fraunhofer.aisec.cpg.query.mergeWithAll
import de.fraunhofer.aisec.openstack.concepts.auth.AuthorizationWithPolicy
import de.fraunhofer.aisec.openstack.concepts.auth.Authorize
import de.fraunhofer.aisec.openstack.concepts.auth.ExtendedRequestContext
import de.fraunhofer.aisec.openstack.passes.auth.AuthenticationPass
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
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<AuthenticationPass>()
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
                        "keystonemiddleware" to
                            listOf(
                                topLevel.resolve("keystonemiddleware/keystonemiddleware").toFile()
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                        "keystonemiddleware" to topLevel.resolve("keystonemiddleware").toFile(),
                    )
                )
            }
        assertNotNull(result)
        val q =
            result.allExtended<HttpEndpoint>(
                sel = { it.authorization != null },
                mustSatisfy = { endpoint ->
                    val targetValues = endpoint.targetValuesForUserOrProject()
                    if (targetValues.isEmpty()) {
                        QueryTree(false, stringRepresentation = "No target values found")
                    } else {
                        endpoint
                            .hasDataFlowToDomain(targetValues)
                            .and(endpoint.hasDataFlowFromPolicyToAuthorizeAction())
                    }
                },
            )

        assertTrue(q.value)
        println(q.printNicely())
    }

    /**
     * Checks if there is a data flow from any authorization target to one of the provided
     * [targetValues].
     */
    fun HttpEndpoint.hasDataFlowToDomain(targetValues: Set<Node>): QueryTree<Boolean> {
        return this.authorization
            ?.ops
            ?.filterIsInstance<Authorize>()
            ?.flatMap { auth ->
                auth.targets.map { target ->
                    dataFlow(
                        startNode = target,
                        type = Must,
                        direction = Backward(GraphToFollow.DFG),
                        predicate = { dataFlowNode ->
                            val ref = dataFlowNode as? Reference
                            ref?.refersTo?.let { refersTo -> targetValues.contains(refersTo) }
                                ?: false
                        },
                    )
                }
            }
            ?.mergeWithAll()
            ?: QueryTree(
                false,
                stringRepresentation = "No data flow to domain due to missing authorization",
            )
    }

    /**
     * Extracts relevant target values (e.g., user ID and project ID) from the request context of
     * the [HttpEndpoint] [this].
     *
     * Note: This logic may need to be adapted if other identifiers are also relevant.
     */
    fun HttpEndpoint.targetValuesForUserOrProject(): Set<Node> {
        val userInfo = (this.requestContext as? ExtendedRequestContext)?.userInfo
        userInfo?.let {
            return setOf(userInfo.projectId, userInfo.userId)
        }
        return setOf()
    }

    /**
     * Checks if there is a data flow from the policy reference into the `action` argument of the
     * `policy.authorize` call.
     *
     * The `action` argument is expected to be the second argument of the `authorize` call.
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
                    // Check if the data flow matches the `action` argument, which is expected to be
                    // the second argument of the authorize call
                    authorizeCall.arguments.getOrNull(1) == dataflowNode
            },
        )
    }

    @Test
    fun testUnauthorizedResponse() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<AuthenticationPass>()
                it.registerPass<PreAuthorizationPass>()
                it.registerPass<AuthorizationPass>()
                it.registerPass<HttpWsgiPass>()
                it.registerPass<OsloPolicyPass>()
                it.registerPass<ControlDependenceGraphPass>()
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
                                topLevel.resolve("cinder/cinder/exception.py").toFile(),
                                topLevel.resolve("cinder/cinder/i18n.py").toFile(),
                            ),
                        "keystonemiddleware" to
                            listOf(
                                topLevel.resolve("keystonemiddleware/keystonemiddleware").toFile()
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                        "keystonemiddleware" to topLevel.resolve("keystonemiddleware").toFile(),
                    )
                )
            }
        assertNotNull(result)

        val blacklist = setOf("exist", "not found")
        val q =
            result.allExtended<HttpEndpoint>(
                sel = { it.authorization != null },
                mustSatisfy = { endpoint ->
                    endpoint.authorization
                        ?.ops
                        ?.filterIsInstance<Authorize>()
                        ?.map { auth ->
                            val ref = auth.exception as? Reference
                            ref?.refersTo?.let { refs ->
                                val record = refs as? RecordDeclaration
                                val superClass = record?.superTypeDeclarations?.singleOrNull()
                                val message = record.fields["message"]?.evaluate().toString()
                                QueryTree(
                                    superClass?.name?.localName == "NotAuthorized" &&
                                        blacklist.none { message.contains(it, ignoreCase = true) }
                                )
                            } ?: QueryTree(false)
                        }
                        ?.mergeWithAll()
                        ?: QueryTree(false)
                            .and(
                                endpoint.authorization
                                    ?.ops
                                    ?.filterIsInstance<Authorize>()
                                    ?.map { auth ->
                                        val authorize = auth.underlyingNode
                                        QueryTree(false)
                                    }
                                    ?.mergeWithAll() ?: QueryTree(false)
                            )
                },
            )
        val q1 =
            result
                .functions("enforce")[1]
                .allExtended<MemberCallExpression>(
                    sel = { it.name.localName == "_enforce_scope" },
                    mustSatisfy = {
                        QueryTree(
                            it.followNextCDGUntilHit(
                                    predicate = {
                                        it is ThrowExpression &&
                                            it.exception?.name?.localName == "PolicyNotAuthorized"
                                    }
                                )
                                .failed
                                .isEmpty()
                        )
                    },
                )
        assertTrue(q1.value)
        assertTrue(q.value)
    }
}
