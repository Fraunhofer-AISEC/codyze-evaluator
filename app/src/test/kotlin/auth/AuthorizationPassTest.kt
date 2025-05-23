/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.Name
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.passes.concepts.TagOverlaysPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.openstack.concepts.auth.Authorize
import de.fraunhofer.aisec.openstack.passes.auth.AuthenticationPass
import de.fraunhofer.aisec.openstack.passes.auth.AuthorizationPass
import de.fraunhofer.aisec.openstack.passes.auth.OsloPolicyPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import kotlin.io.path.Path
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import org.junit.jupiter.api.Test

class AuthorizationPassTest {
    @Test
    fun authorizationPass() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<AuthorizationPass>()
                it.registerPass<AuthenticationPass>()
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
                        "keystonemiddleware" to topLevel.resolve("keystonemiddleware").toFile(),
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
            val policy = relatedAuthzOps.policy
            assertNotNull(policy, "Authorize operation should have an associated policy")
            val targets = relatedAuthzOps.targets
            assertNotNull(targets, "Authorize operation should have targets")
        }
    }

    @Test
    fun testDatabaseQueryFilter() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.exclusionPatterns("tests", "drivers", "migrations")
                it.registerPass<TagOverlaysPass>()
                it.configurePass<TagOverlaysPass>(
                    TagOverlaysPass.Configuration(
                        tag =
                            tag {
                                each<CallExpression>("model_query").with {
                                    DatabaseAccess(underlyingNode = node)
                                }
                                each<MemberCallExpression>(
                                        Name("filter_by", parent = Name("UNKNOWN"))
                                    )
                                    .with {
                                        val concept =
                                            node.conceptNodes
                                                .filterIsInstance<DatabaseAccess>()
                                                .single()
                                        val by = node.arguments.first()
                                        Filter(underlyingNode = node, concept = concept, by = by)
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
            result.allExtended<DatabaseAccess>(
                mustSatisfy = { QueryTree<Boolean>(it.ops.any { it is Filter }) }
            )
    }
}

class DatabaseAccess(underlyingNode: Node? = null) : Concept(underlyingNode)

class Filter(underlyingNode: Node?, concept: DatabaseAccess, val by: Node) :
    Operation(underlyingNode, concept)
