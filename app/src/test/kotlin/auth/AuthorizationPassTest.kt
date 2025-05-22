/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.concepts.TagOverlaysPass
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.getOverlaysByPrevDFG
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with
import de.fraunhofer.aisec.cpg.passes.concepts.withMultiple
import de.fraunhofer.aisec.cpg.query.Must
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.dataFlow
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
                    val tmp =
                        endpoint.authorization
                            ?.ops
                            ?.filterIsInstance<Authorize>()
                            ?.flatMap { auth ->
                                auth.targets.map { target ->
                                    dataFlow(
                                        startNode = target,
                                        type = Must,
                                        direction = Backward(GraphToFollow.DFG),
                                        predicate = { dataFlowNode ->
                                            val data = dataFlowNode as? Reference
                                            val userInfo =
                                                (endpoint.requestContext as? ExtendedRequestContext)
                                                    ?.userInfo
                                            data?.refersTo == userInfo?.projectId ||
                                                data?.refersTo == userInfo?.userId
                                        },
                                    )
                                }
                            }
                            ?.toMutableList() ?: mutableListOf()
                    val tmp2 =
                        endpoint.authorization?.ops?.filterIsInstance<Authorize>()?.map { auth ->
                            dataFlow(
                                startNode = auth.action,
                                type = Must,
                                direction = Backward(GraphToFollow.DFG),
                                predicate = { dataFlowNode ->
                                    (dataFlowNode.astParent
                                            ?.overlays
                                            ?.filterIsInstance<Authorization>()
                                            ?.firstOrNull()
                                            ?.underlyingNode as? MemberCallExpression)
                                        ?.arguments
                                        ?.getOrNull(0) != null
                                },
                            )
                        } ?: listOf()
                    tmp.addAll(tmp2)
                    QueryTree<Boolean>(
                        value = tmp.all { it.value },
                        children = tmp.toMutableList(),
                        node = endpoint,
                    )
                },
            )
        assertTrue(q.value)
    }

    @Test
    fun testDomainIsUsedInAuthorization2() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
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
                it.registerPass<TagOverlaysPass>()
                it.configurePass<TagOverlaysPass>(
                    TagOverlaysPass.Configuration(
                        tag =
                            tag {
                                each<FunctionDeclaration>("authorize").with {
                                    Authorization(underlyingNode = node)
                                }
                                each<CallExpression>("policy.authorize").withMultiple {
                                    val authorization =
                                        node.getOverlaysByPrevDFG<Authorization>(state)
                                    authorization.flatMap { authorization -> state.values }
                                    //                                    Authorize(node, concept =
                                    // authorization)
                                    authorization
                                }
                            }
                    )
                )
            }
        assertNotNull(result)
        val q =
            result.allExtended<HttpEndpoint>(
                sel = { it.authorization != null },
                mustSatisfy = { endpoint ->
                    val tmp =
                        endpoint.authorization?.ops?.filterIsInstance<Authorize>()?.flatMap { auth
                            ->
                            auth.targets.map { target ->
                                dataFlow(
                                    startNode = target,
                                    type = Must,
                                    direction = Backward(GraphToFollow.DFG),
                                    predicate = { dataFlowNode ->
                                        val data = dataFlowNode as? Reference
                                        val userInfo =
                                            (endpoint.requestContext as? ExtendedRequestContext)
                                                ?.userInfo
                                        data?.refersTo == userInfo?.projectId ||
                                            data?.refersTo == userInfo?.userId
                                    },
                                )
                            }
                        } ?: listOf()
                    QueryTree<Boolean>(
                        value = tmp.all { it.value },
                        children = tmp.toMutableList(),
                        node = endpoint,
                    )
                },
            )
        assertTrue(q.value)
    }
}
