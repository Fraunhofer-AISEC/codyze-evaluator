/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.assumptions.AssumptionType
import de.fraunhofer.aisec.cpg.assumptions.assume
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
import de.fraunhofer.aisec.cpg.graph.statements.ReturnStatement
import de.fraunhofer.aisec.cpg.graph.statements.ThrowExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.concepts.TagOverlaysPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with
import de.fraunhofer.aisec.cpg.query.Must
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.and
import de.fraunhofer.aisec.cpg.query.dataFlow
import de.fraunhofer.aisec.cpg.query.mergeWithAll
import de.fraunhofer.aisec.cpg.query.not
import de.fraunhofer.aisec.openstack.concepts.auth.AuthorizationWithPolicy
import de.fraunhofer.aisec.openstack.concepts.auth.Authorize
import de.fraunhofer.aisec.openstack.concepts.auth.CheckDomainScope
import de.fraunhofer.aisec.openstack.concepts.auth.ExtendedRequestContext
import de.fraunhofer.aisec.openstack.passes.auth.AuthenticationPass
import de.fraunhofer.aisec.openstack.passes.auth.AuthorizationPass
import de.fraunhofer.aisec.openstack.passes.auth.OsloPolicyPass
import de.fraunhofer.aisec.openstack.passes.auth.PreAuthorizationPass
import de.fraunhofer.aisec.openstack.passes.auth.SetOsloPolicyEnforcerTypePass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

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
                it.registerPass<SetOsloPolicyEnforcerTypePass>()
                it.registerPass<AuthorizationPass>()
                it.registerPass<HttpWsgiPass>()
                it.registerPass<OsloPolicyPass>()
                it.registerPass<ProgramDependenceGraphPass>()
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
                it.registerPass<TagOverlaysPass>()
                it.configurePass<TagOverlaysPass>(
                    TagOverlaysPass.Configuration(
                        tag =
                            tag {
                                each<MemberCallExpression>(
                                        predicate = { it.name.localName == "_enforce_scope" }
                                    )
                                    .with {
                                        // Authorization concept is already set in the
                                        // `AuthorizationPass`
                                        CheckDomainScope(
                                            underlyingNode = node,
                                            concept = Authorization(),
                                            rule = node.arguments[1],
                                        )
                                    }
                            }
                    )
                )
            }
        assertNotNull(result)
        val q =
            unauthorizedResponseFromAnotherDomainQuery(
                result = result,
                policy = UnauthorizedResponsePolicy(),
            )
        assertTrue(q.value)
    }

    data class UnauthorizedResponsePolicy(
        val notAllowedThrowMessages: Set<String> = setOf("exist", "not found"),
        val allowedExceptions: Set<String> = setOf("PolicyNotAuthorized", "exc"),
        val allowedExceptionParentClass: String = "NotAuthorized",
        val throwMessageField: String = "message",
    )

    /**
     * Checks whether an HttpEndpoint with an authorization set only throws allowed "Not Authorized"
     * exceptions and does not contain disallowed throw messages.
     */
    private fun unauthorizedResponseFromAnotherDomainQuery(
        result: TranslationResult,
        policy: UnauthorizedResponsePolicy,
    ): QueryTree<Boolean> {
        return result.allExtended<HttpEndpoint>(
            sel = { it.authorization != null },
            mustSatisfy = { endpoint ->
                endpoint
                    .onlyThrowsNotAuthorized(policy = policy)
                    .and(endpoint.throwsNotAuthorizedWhenDomainCheckFails(policy = policy))
            },
        )
    }

    /**
     * Checks if an [HttpEndpoint] only throws "Not Authorized" exceptions of a permitted class and
     * none of the disallowed messages appear.
     */
    fun HttpEndpoint.onlyThrowsNotAuthorized(
        policy: UnauthorizedResponsePolicy
    ): QueryTree<Boolean> {
        return this.allExtended<HttpEndpoint>(
            sel = { it.authorization != null },
            mustSatisfy = { endpoint ->
                endpoint.authorization
                    ?.ops
                    ?.filterIsInstance<Authorize>()
                    ?.map { auth ->
                        // ref contains the exception thrown by the authorization operation
                        val ref = auth.exception as? Reference
                        ref?.refersTo?.let { refs ->
                            val record = refs as? RecordDeclaration
                            val superClass = record?.superTypeDeclarations?.singleOrNull()
                            val message =
                                record.fields[policy.throwMessageField]?.evaluate().toString()
                            QueryTree(
                                // Checks that the exception's super-class is in the list of allowed classes.
                                superClass?.name?.localName == policy.allowedExceptionParentClass &&
                                    policy.notAllowedThrowMessages.none {
                                        // Checks if the message does not contain any of the forbidden words.
                                        message.contains(it, ignoreCase = true)
                                    }
                            )
                        } ?: QueryTree(false)
                    }
                    ?.mergeWithAll() ?: QueryTree(false)
            },
        )
    }

    /**
     * Checks if an [HttpEndpoint] only throws allowed exceptions when domain checks fail.
     *
     * This query follows a blacklisting approach: It checks if no exception is thrown or if the
     * exception contains some keywords and in this case, lets the query fail.
     */
    fun HttpEndpoint.throwsNotAuthorizedWhenDomainCheckFails(
        policy: UnauthorizedResponsePolicy
    ): QueryTree<Boolean> {
        return this.allExtended<HttpEndpoint>(
            // We only consider endpoints with authorization
            sel = { it.authorization != null },
            mustSatisfy = { endpoint ->
                endpoint.authorization
                    ?.ops
                    ?.filterIsInstance<Authorize>()
                    ?.map { auth ->
                        // We start from all the Authorize operations and check where the action is
                        // used to check the scope of the domain. We collect the underlying node of
                        // the CheckDomainScope operations.
                        auth.action
                            .followNextFullDFGEdgesUntilHit {
                                it.astParent
                                    ?.overlays
                                    ?.filterIsInstance<CheckDomainScope>()
                                    ?.isNotEmpty() == true
                            }
                            .fulfilled
                            .mapNotNull { it.nodes.last().astParent }
                            .map { node ->
                                // node is the astParent of the CheckDomainScope operation's
                                // underlyingNode.
                                // We invert the result of the dataflow query because its result is
                                // bad.
                                not(
                                    // We check if the node flows into an exception which is allowed
                                    dataFlow(
                                            node,
                                            // We only perform an intraprocedural data flow analysis
                                            // because it's strange to populate the check outside
                                            // the function and throw an exception there.
                                            scope = Intraprocedural(),
                                            sensitivities =
                                                FieldSensitive + ContextSensitive + Implicit,
                                            predicate = {
                                                // We have a fulfilled path if the node throws an
                                                // exception which is in the allowedExceptions list.
                                                if (node !is ThrowExpression) false
                                                else {
                                                    node.name.localName in policy.allowedExceptions
                                                }
                                            },
                                            // If we reach a ReturnStatement, we stop following the
                                            // data flow path.
                                            // Here, we assume that the authorization check is not
                                            // performed because we most likely ignore the result of
                                            // the check.
                                            earlyTermination = { it is ReturnStatement },
                                        )
                                        .assume(
                                            AssumptionType.ExhaustiveEnumerationAssumption,
                                            "We assume that the earlyTermination is correct and that no more exception will be thrown outside the function where the domain scope check is performed.",
                                        ) // TODO: Would be nice to have this evaluated only if the
                                    // earlyTermination was hit.
                                )
                            }
                            .mergeWithAll() // It has to be fulfilled for all domain scope checks
                    }
                    ?.mergeWithAll() // It has to be fulfilled for all Authorize operations
                ?: QueryTree(false)
            },
        )
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
