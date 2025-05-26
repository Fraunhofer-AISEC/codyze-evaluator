/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.assumptions.AssumptionType
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.allChildrenWithOverlays
import de.fraunhofer.aisec.cpg.graph.component
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authenticate
import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOptionSource
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.declarations.ConstructorDeclaration
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.passes.concepts.TagOverlaysPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.getOverlaysByPrevDFG
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with
import de.fraunhofer.aisec.cpg.passes.concepts.withMultiple
import de.fraunhofer.aisec.cpg.query.Must
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.and
import de.fraunhofer.aisec.cpg.query.dataFlow
import de.fraunhofer.aisec.cpg.query.existsExtended
import de.fraunhofer.aisec.cpg.query.or
import de.fraunhofer.aisec.openstack.concepts.auth.ExtendedRequestContext
import de.fraunhofer.aisec.openstack.concepts.auth.UserInfo
import de.fraunhofer.aisec.openstack.passes.*
import de.fraunhofer.aisec.openstack.passes.auth.AuthenticationPass
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import kotlin.io.path.Path
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AuthenticationPassTest {
    @Test
    fun testAuthenticationPass() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<AuthenticationPass>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<HttpWsgiPass>()
                it.exclusionPatterns("tests", "drivers", "sqlalchemy")
                it.includePath("../external/oslo.context")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to listOf(topLevel.resolve("cinder/cinder").toFile()),
                        "barbican" to listOf(topLevel.resolve("barbican/barbican").toFile()),
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
                        "barbican" to topLevel.resolve("barbican").toFile(),
                        "keystonemiddleware" to topLevel.resolve("keystonemiddleware").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }

        val tokenBasedAuths = result.conceptNodes.filterIsInstance<TokenBasedAuth>()
        assertNotNull(tokenBasedAuths, "At least one TokenBasedAuth concept should be created")

        val cinderComponent = result.components.singleOrNull { it.name.localName == "cinder" }
        assertNotNull(cinderComponent)
        val cinderEndpoints = cinderComponent.allChildrenWithOverlays<HttpEndpoint>()
        assertNotNull(cinderEndpoints)
        cinderEndpoints.forEach { endpoint ->
            // Check that authentication is applied only to the /v3 endpoints
            if (endpoint.path.contains("/v3")) {
                assertNotNull(endpoint.authentication, "Endpoints should have authentication set")
                assertTrue(
                    endpoint.authentication is TokenBasedAuth,
                    "Authentication should be TokenBasedAuth",
                )
            } else {
                assertNull(
                    endpoint.authentication,
                    "Non 'v3' version endpoints should not have authentication set",
                )
            }
        }

        val barbicanComponent = result.components.singleOrNull { it.name.localName == "barbican" }
        assertNotNull(barbicanComponent)
        val barbicanEndpoints = barbicanComponent.allChildrenWithOverlays<HttpEndpoint>()
        assertNotNull(barbicanEndpoints)
        barbicanEndpoints.forEach { endpoint ->
            // Check that authentication is applied only to the /v1 endpoints
            if (endpoint.path.contains("/v1")) {
                assertNotNull(endpoint.authentication, "Endpoints should have authentication set")
                assertTrue(
                    endpoint.authentication is TokenBasedAuth,
                    "Authentication should be TokenBasedAuth",
                )
            } else {
                assertNull(
                    endpoint.authentication,
                    "Non 'v1' version endpoints should not have authentication set ",
                )
            }
        }
    }

    @Test
    fun testAllComponentEndpointsHaveAuthentication() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<AuthenticationPass>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<HttpWsgiPass>()
                it.exclusionPatterns("tests", "drivers")
                it.includePath("../external/oslo.context")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to listOf(topLevel.resolve("cinder/cinder/api").toFile()),
                        "barbican" to listOf(topLevel.resolve("barbican/barbican/api").toFile()),
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
                        "barbican" to topLevel.resolve("barbican").toFile(),
                        "keystonemiddleware" to topLevel.resolve("keystonemiddleware").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }

        assertNotNull(result)

        val r =
            result.allExtended<HttpEndpoint>(
                sel = { endpoint -> endpoint.shouldHaveAuthentication() },
                mustSatisfy = { endpoint ->
                    QueryTree(
                        value = endpoint.authentication != null,
                        children = mutableListOf(QueryTree(endpoint)),
                    )
                },
            )
        assertTrue(r.value)
        println(r.printNicely())
    }

    fun HttpEndpoint.shouldHaveAuthentication(): Boolean {
        return (this.underlyingNode?.component?.name?.localName == "cinder" &&
            this.path.startsWith("/v3/")) ||
            (this.underlyingNode?.component?.name?.localName == "barbican" &&
                this.path.startsWith("/v1/"))
    }

    @Test
    fun testAuthStrategyProvider() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                        "cinder" to listOf(topLevel.resolve("cinder/cinder/api").toFile()),
                        "barbican" to listOf(topLevel.resolve("barbican/barbican/api").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "conf" to topLevel.resolve("conf").toFile(),
                        "cinder" to topLevel.resolve("cinder/api").toFile(),
                        "barbican" to topLevel.resolve("barbican/api").toFile(),
                    )
                )
            }

        assertNotNull(result)

        val query =
            result.allExtended<ConfigurationOptionSource>(
                sel = { it.name.localName == "auth_strategy" },
                mustSatisfy = {
                    QueryTree<Boolean>(
                        value = it.evaluate().toString() == "keystone",
                        stringRepresentation = "Component config: ${it.location?.artifactLocation}",
                    )
                },
            )
        println(query.printNicely())
        assertEquals(true, query.value)
    }

    @Test
    fun testTokenBasedAuthentication() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<AuthenticationPass>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<HttpWsgiPass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to listOf(topLevel.resolve("cinder/cinder/api").toFile()),
                        "barbican" to listOf(topLevel.resolve("barbican/barbican/api").toFile()),
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
                        "barbican" to topLevel.resolve("barbican").toFile(),
                        "keystonemiddleware" to topLevel.resolve("keystonemiddleware").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }

        assertNotNull(result)

        // Is a valid token provider configured?
        val tokenProviderConfigured = result.isTokenProviderConfigured()
        val r =
            result.allExtended<HttpEndpoint>(
                mustSatisfy = { endpoint ->
                    // The requirement is satisfied if the endpoint has token-based authentication
                    // enabled and a valid token provider is configured or if the endpoint does not
                    // need authentication.
                    (tokenProviderConfigured and endpoint.hasTokenBasedAuth()) or
                        endpoint.doesNotNeedAuthentication()
                }
            )
        assertTrue(r.value)
        println(r.printNicely())
    }

    /**
     * Determines if the [HttpEndpoint] [this] does not require authentication.
     *
     * Note: This whitelist has to be customized for each project.
     */
    fun HttpEndpoint.doesNotNeedAuthentication(): QueryTree<Boolean> {
        // Currently, we assume that only the endpoints under "/v3" (for cinder) and "/v1" (for
        // barbican) need authentication.
        val doesNotNeedAuth =
            !((this.underlyingNode?.component?.name?.localName == "cinder" &&
                this.path.startsWith("/v3/")) ||
                (this.underlyingNode?.component?.name?.localName == "barbican" &&
                    this.path.startsWith("/v1/")))

        // Creates the QueryTree with the result of the assessment.
        return QueryTree(
                value = doesNotNeedAuth,
                stringRepresentation =
                    if (doesNotNeedAuth) "The endpoint $this does not need authentication"
                    else "The endpoint $this does not need authentication",
                children = mutableListOf(QueryTree(this)),
                node = this,
            )
            .assume(
                AssumptionType.ExhaustiveEnumerationAssumption,
                "We assume that the list of endpoints that do not require authentication is exhaustive and does not contain too many elements.\n\n" +
                    "To validate this assumption, it is necessary to check if this list is in accordance with the documentation provided.",
            )
    }

    /**
     * Checks if the [TranslationResult] [this] contains a [ConfigurationSource] that configures
     * that the provider is a valid token provider.
     */
    fun TranslationResult.isTokenProviderConfigured(): QueryTree<Boolean> {
        return this.existsExtended<ConfigurationSource>(
            sel = { config -> config.name.toString() == "keystone.conf" },
            mustSatisfy = { config ->
                val providerGroups =
                    config.groups.flatMap { group ->
                        group.options.filter { it.name.localName == "provider" }
                    }

                val configuresTokenAuth =
                    providerGroups.singleOrNull { it.evaluate().toString() in tokenProvider } !=
                        null

                QueryTree(
                    value = configuresTokenAuth,
                    stringRepresentation =
                        if (configuresTokenAuth) "The config configures token-based authentication"
                        else "The config does not configure token-based authentication",
                    children = mutableListOf(QueryTree(config), QueryTree(providerGroups)),
                )
            },
        )
    }

    /**
     * The list of valid token providers that are valid for the project.
     *
     * Note: This set may change depending on the project or state-of-the-art.
     */
    val tokenProvider = setOf("fernet", "jws")

    /**
     * Checks if the [HttpEndpoint] [this] requires token-based authentication. The attribute
     * [HttpEndpoint.authentication] is set by the pass only if a token provider has been
     * configured.
     */
    fun HttpEndpoint.hasTokenBasedAuth(): QueryTree<Boolean> {
        val isTokedBasedAuth = this.authentication is TokenBasedAuth
        return QueryTree(
            value = isTokedBasedAuth,
            stringRepresentation =
                if (isTokedBasedAuth) {
                    "The endpoint $this requires token-based authentication"
                } else {
                    "The endpoint $this does not require token-based authentication"
                },
            children = mutableListOf(QueryTree(this.authentication)),
            node = this,
        )
    }

    @Test
    fun testAccessToken() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.exclusionPatterns("tests")
                it.includePath("../external/keystoneauth")
                it.softwareComponents(
                    mutableMapOf(
                        "keystonemiddleware" to
                            listOf(
                                topLevel.resolve("keystonemiddleware/keystonemiddleware").toFile()
                            )
                    )
                )
                it.topLevels(
                    mapOf("keystonemiddleware" to topLevel.resolve("keystonemiddleware").toFile())
                )
                it.registerPass<TagOverlaysPass>()
                it.configurePass<TagOverlaysPass>(
                    TagOverlaysPass.Configuration(
                        tag =
                            tag {
                                each<MemberExpression>(
                                        predicate = { it.name.localName == "user_token" }
                                    )
                                    .with { TokenBasedAuth(token = node) }
                                each<CallExpression>(
                                        predicate = { it.name.localName == "_do_fetch_token" }
                                    )
                                    .withMultiple {
                                        val auth = node.getOverlaysByPrevDFG<TokenBasedAuth>(state)
                                        auth.map { concept ->
                                            Authenticate(
                                                underlyingNode = node,
                                                concept = concept,
                                                credential = node.arguments[0],
                                            )
                                        }
                                    }
                                each<ConstructorDeclaration>(
                                        predicate = { it.name.localName.startsWith("AccessInfoV3") }
                                    )
                                    .withMultiple {
                                        val overlays = mutableListOf<OverlayNode>()
                                        val token = node.parameters[1]
                                        val reqContext =
                                            ExtendedRequestContext(
                                                underlyingNode = node,
                                                token = token,
                                            )
                                        val accessInfo = node.recordDeclaration
                                        val userInfo =
                                            UserInfo(
                                                accessInfo,
                                                userId = accessInfo.methods["user_id"],
                                                projectId = accessInfo.methods["project_id"],
                                                domainId = accessInfo.methods["domain_id"],
                                            )
                                        reqContext.userInfo = userInfo
                                        overlays.add(reqContext)
                                        overlays
                                    }
                            }
                    )
                )
            }

        assertNotNull(result)
        val q =
            result.allExtended<Authenticate>(
                mustSatisfy = { it.usesSameTokenAsCredential() and it.hasDataFlowIntoContext() }
            )
        assertTrue(q.value)
    }

    /**
     * Checks if any [Authenticate] uses a [TokenBasedAuth] where the token is equal to the
     * credential of that [Authenticate].
     */
    fun Authenticate.usesSameTokenAsCredential(): QueryTree<Boolean> {
        return this.allExtended<Authenticate>(
            mustSatisfy = { token ->
                val tokens = token.credential.overlays.filterIsInstance<TokenBasedAuth>()
                val hasTokenDataFlow = tokens.all { it.token == token.credential }
                QueryTree(value = hasTokenDataFlow, node = token)
            }
        )
    }

    /**
     * Checks if there is a data flow from the credential of this [Authenticate] into an
     * [ExtendedRequestContext], where user-related info is set.
     */
    fun Authenticate.hasDataFlowIntoContext(): QueryTree<Boolean> {
        return dataFlow(
            startNode = this.credential,
            type = Must,
            predicate = { target ->
                target.overlays.filterIsInstance<ExtendedRequestContext>().any {
                    it.userInfo?.userId != null &&
                        it.userInfo?.projectId != null &&
                        it.userInfo?.domainId != null
                }
            },
        )
    }
}
