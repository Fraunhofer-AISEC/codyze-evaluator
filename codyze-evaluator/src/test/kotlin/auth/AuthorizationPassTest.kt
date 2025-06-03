/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.OverlayNode
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.followDFGEdgesUntilHit
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.passes.ControlFlowSensitiveDFGPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.concepts.*
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.openstack.concepts.auth.Authorize
import de.fraunhofer.aisec.openstack.concepts.auth.CheckDomainScope
import de.fraunhofer.aisec.openstack.concepts.database.DatabaseAccess
import de.fraunhofer.aisec.openstack.concepts.database.Filter
import de.fraunhofer.aisec.openstack.passes.auth.*
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import de.fraunhofer.aisec.openstack.queries.authorization.UnauthorizedResponsePolicy
import de.fraunhofer.aisec.openstack.queries.authorization.databaseAccessBasedOnDomainOrProject
import de.fraunhofer.aisec.openstack.queries.authorization.endpointAuthorizationBasedOnDomainOrProject
import de.fraunhofer.aisec.openstack.queries.authorization.unauthorizedResponseFromAnotherDomainQuery
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
        with(result) {
            val q = databaseAccessBasedOnDomainOrProject()
            assertFalse(q.value)
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
        with(result) {
            val q = endpointAuthorizationBasedOnDomainOrProject()
            assertFalse(q.value)
            println(q.printNicely())
        }
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
        with(result) {
            val q =
                unauthorizedResponseFromAnotherDomainQuery(policy = UnauthorizedResponsePolicy())
            assertFalse(q.value)
        }
    }
}
