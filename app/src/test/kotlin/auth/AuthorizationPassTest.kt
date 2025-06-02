/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.assumptions.AssumptionType
import de.fraunhofer.aisec.cpg.assumptions.assume
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.OverlayNode
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.followDFGEdgesUntilHit
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.passes.ControlFlowSensitiveDFGPass
import de.fraunhofer.aisec.cpg.passes.concepts.TagOverlaysPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.withMultiple
import de.fraunhofer.aisec.cpg.query.Must
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.and
import de.fraunhofer.aisec.cpg.query.dataFlow
import de.fraunhofer.aisec.cpg.query.mergeWithAll
import de.fraunhofer.aisec.openstack.concepts.auth.AuthorizationWithPolicy
import de.fraunhofer.aisec.openstack.concepts.auth.Authorize
import de.fraunhofer.aisec.openstack.concepts.auth.ExtendedRequestContext
import de.fraunhofer.aisec.openstack.concepts.database.DatabaseAccess
import de.fraunhofer.aisec.openstack.concepts.database.Filter
import de.fraunhofer.aisec.openstack.passes.auth.AuthenticationPass
import de.fraunhofer.aisec.openstack.passes.auth.AuthorizationPass
import de.fraunhofer.aisec.openstack.passes.auth.OsloPolicyPass
import de.fraunhofer.aisec.openstack.passes.auth.PreAuthorizationPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import de.fraunhofer.aisec.openstack.queries.authorization.authorizeActionComesFromPolicyRef
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull

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
    fun testDatabaseQueryFilter() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.exclusionPatterns("tests", "drivers", "migrations")
                it.registerPass<ControlFlowSensitiveDFGPass>()
                it.registerPass<TagOverlaysPass>()
                it.configurePass<TagOverlaysPass>(
                    TagOverlaysPass.Configuration(
                        tag =
                            tag {
                                each<CallExpression>(
                                        predicate = { it.name.localName == "model_query" }
                                    )
                                    .withMultiple {
                                        val overlays = mutableListOf<OverlayNode>()
                                        val contextArg = node.arguments.getOrNull(0)
                                        val dbAccess =
                                            DatabaseAccess(
                                                underlyingNode = node,
                                                context = contextArg,
                                            )
                                        overlays += dbAccess

                                        val paths =
                                            node.followDFGEdgesUntilHit {
                                                (it is MemberCallExpression ||
                                                    it is MemberExpression) &&
                                                    // It can be `filter` or `filter_by`
                                                    it.name.localName.startsWith("filter") ||
                                                    it.name.localName.startsWith("with_entities")
                                            }

                                        val filterCalls =
                                            paths.fulfilled.map { path -> path.nodes.last() }
                                        val by = node.arguments.getOrNull(1)

                                        if (by != null) {
                                            filterCalls.forEach { filterCall ->
                                                overlays +=
                                                    Filter(
                                                        underlyingNode = filterCall,
                                                        concept = dbAccess,
                                                        by = by,
                                                    )
                                            }
                                        }
                                        overlays
                                    }
                            }
                    )
                )
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to
                            listOf(topLevel.resolve("cinder/cinder/db/sqlalchemy/api.py").toFile())
                    )
                )
                it.topLevels(mapOf("cinder" to topLevel.resolve("cinder").toFile()))
            }

        assertNotNull(result)
        // When a user reads data from or writes data to a database, the user’s domain is used as a
        // filter in the database query
        val q =
            result
                .allExtended<DatabaseAccess>(
                    mustSatisfy = {
                        if (it.context == null) {
                            QueryTree(
                                value = false,
                                node = it,
                                stringRepresentation = "No context provided",
                            )
                        }
                        QueryTree<Boolean>(it.ops.any { it is Filter })
                    }
                )
                .assume(
                    assumptionType = AssumptionType.DataFlowAssumption,
                    message =
                        "We assume that there exists a data flow from a method that performs a database access (e.g., within an HTTP endpoint) to the 'model_query' call expression represented by this node." +
                            "To verify this assumption, it is necessary to check the data flow",
                )
        assertFalse(q.value)
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
                            .and(endpoint.authorization.authorizeActionComesFromPolicyRef(endpoint))
                    }
                },
            )

        assertFalse(q.value)
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
                        predicate = { dataFlowNode -> dataFlowNode in targetValues },
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
        return setOfNotNull(userInfo?.projectId, userInfo?.userId)
    }

    /**
     * Checks if the `action` argument of the call to `policy.authorize` always comes from the
     * policy ref belonging to [currentEndpoint].
     *
     * Note: This function is specific to the OpenStack authorization model and the call to
     * `policy.authorize`.
     */
    fun Authorization?.authorizeActionComesFromPolicyRef(
        currentEndpoint: HttpEndpoint
    ): QueryTree<Boolean> {
        val authorizeCalls =
            this?.ops?.filterIsInstance<Authorize>()
                ?: return QueryTree(
                    value = false,
                    stringRepresentation = "No authorization was specified",
                )
        if (authorizeCalls.isEmpty()) {
            return QueryTree(
                value = false,
                stringRepresentation = "No authorize calls found in the authorization operations.",
            )
        }

        return authorizeCalls
            .map { authorize ->
                // Check that the requirement holds for all authorize calls.
                // This is the call to `policy.authorize` which performs the authorization check.
                val policyAuthorize =
                    (authorize.underlyingNode as? CallExpression)
                        ?: return@map QueryTree(
                            value = false,
                            stringRepresentation =
                                "No underlyingNode of the authorize operation is found. This is unexpected.",
                            node = authorize,
                        )

                // The second argument of the authorize call is expected to be the `action`
                // argument.
                val actionArgument =
                    policyAuthorize.arguments.getOrNull(1)
                        ?: return@map QueryTree(
                            value = false,
                            stringRepresentation =
                                "No action argument found in the authorize call. This is invalid.",
                            node = authorize,
                        )
                // Retrieve the policy reference which should be used when authorizing the request
                // handled by the currentEndpoint.
                // If there is no policy, return a QueryTree with value false, indicating that no
                // policy was found.
                val policyRef =
                    (currentEndpoint.authorization as? AuthorizationWithPolicy)?.policy?.policyRef
                        ?: return@map QueryTree(
                            value = false,
                            stringRepresentation = "No policy found for the endpoint",
                            node = currentEndpoint,
                        )

                dataFlow(
                    // We start at the `action` argument of the authorize call.
                    startNode = actionArgument,
                    // We traverse the data flow graph in the backward direction to find out if it
                    // comes
                    // from the policy reference.
                    direction = Backward(GraphToFollow.DFG),
                    // The criterion must hold on every path, so we use `Must` analysis.
                    type = Must,
                    // The predicate checks if the node is the policy reference of the authorization
                    // belonging to the given HttpEndpoint.
                    predicate = { it == policyRef },
                )
            }
            .mergeWithAll()
    }
}
