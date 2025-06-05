/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.profiles.openstack

import de.fraunhofer.aisec.codyze.graph.concepts.auth.CheckDomainScope
import de.fraunhofer.aisec.codyze.graph.concepts.auth.ExtendedRequestContext
import de.fraunhofer.aisec.codyze.graph.concepts.auth.UserInfo
import de.fraunhofer.aisec.codyze.graph.concepts.database.DatabaseAccess
import de.fraunhofer.aisec.codyze.graph.concepts.database.Filter
import de.fraunhofer.aisec.codyze.openstack.passes.*
import de.fraunhofer.aisec.codyze.passes.concepts.auth.openstack.AuthenticationPass
import de.fraunhofer.aisec.codyze.passes.concepts.auth.openstack.AuthorizationPass
import de.fraunhofer.aisec.codyze.passes.concepts.crypto.encryption.openstack.CinderKeyManagerSecretPass
import de.fraunhofer.aisec.codyze.passes.concepts.diskEncryption.openstack.CinderDiskEncryptionPass
import de.fraunhofer.aisec.codyze.passes.concepts.flows.python.PythonEntryPointPass
import de.fraunhofer.aisec.codyze.passes.concepts.http.openstack.SecureKeyRetrievalPass
import de.fraunhofer.aisec.codyze.passes.concepts.http.python.*
import de.fraunhofer.aisec.codyze.passes.concepts.memory.openstack.StevedoreDynamicLoadingPass
import de.fraunhofer.aisec.codyze.passes.openstack.MakeThingsWorkPrototypicallyPass
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.OverlayNode
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authenticate
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.declarations.ConstructorDeclaration
import de.fraunhofer.aisec.cpg.graph.followDFGEdgesUntilHit
import de.fraunhofer.aisec.cpg.graph.get
import de.fraunhofer.aisec.cpg.graph.methods
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.concepts.TaggingContext
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.getOverlaysByPrevDFG
import de.fraunhofer.aisec.cpg.passes.concepts.with
import de.fraunhofer.aisec.cpg.passes.concepts.withMultiple

/**
 * The OpenStack profile for Codyze, which registers all necessary passes to analyze OpenStack
 * projects.
 */
val OpenStackProfile = { it: TranslationConfiguration.Builder ->
    // Extra analysis passes for OpenStack projects
    it.registerPass<ProgramDependenceGraphPass>()

    // Required languages (Python and IniFile)
    it.registerLanguage<PythonLanguage>()
    it.registerLanguage<IniFileLanguage>()

    // Required passes for OpenStack analysis
    it.registerPass<CinderKeyManagerSecretPass>()
    it.registerPass<CinderDiskEncryptionPass>()
    it.registerPass<PythonMemoryPass>()
    it.registerPass<HttpPecanLibPass>()
    it.registerPass<HttpWsgiPass>()
    it.registerPass<AuthenticationPass>()
    it.registerPass<AuthorizationPass>()
    it.registerPass<SecureKeyRetrievalPass>()
    it.registerPass<IniFileConfigurationSourcePass>()
    it.registerPass<PythonEntryPointPass>()
    it.registerPass<StevedoreDynamicLoadingPass>()

    // TODO(oxisto): Remove and replace with tagging API
    it.registerPass<MakeThingsWorkPrototypicallyPass>()
}

/**
 * Tags appropriate nodes inside [KeystoneMiddleware] with authentication concepts.
 * - [TokenBasedAuth] for `user_token` member expressions.
 * - [Authenticate] for calls to `_do_fetch_token` that use the `user_token`.
 * - [ExtendedRequestContext] for constructors of `AccessInfoV3` that use the `user_token`.
 *
 * This allows the analysis to track authentication flows and user information within OpenStack
 * components that use [Keystone].
 */
fun TaggingContext.tagKeystoneMiddlewareAuthentication() {
    each<MemberExpression>(predicate = { it.name.localName == "user_token" }).with {
        TokenBasedAuth(token = node)
    }
    each<CallExpression>(predicate = { it.name.localName == "_do_fetch_token" }).withMultiple {
        val auth = node.getOverlaysByPrevDFG<TokenBasedAuth>(state)
        auth.map { concept ->
            Authenticate(underlyingNode = node, concept = concept, credential = node.arguments[0])
        }
    }
    each<ConstructorDeclaration>(predicate = { it.name.localName.startsWith("AccessInfoV3") })
        .withMultiple {
            val overlays = mutableListOf<OverlayNode>()
            val token = node.parameters[1]
            val reqContext = ExtendedRequestContext(underlyingNode = node, token = token)
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

/** Tagging profile to tag database access in OpenStack components that use [SqlAlchemy]. */
fun TaggingContext.tagDatabaseAccess() {
    each<CallExpression>(predicate = { it.name.localName == "model_query" }).withMultiple {
        val overlays = mutableListOf<OverlayNode>()
        val contextArg = node.arguments.getOrNull(0)
        val dbAccess = DatabaseAccess(underlyingNode = node, context = contextArg)
        overlays += dbAccess

        val paths =
            node.followDFGEdgesUntilHit {
                (it is MemberCallExpression || it is MemberExpression) &&
                    // It can be `filter` or `filter_by`
                    it.name.localName.startsWith("filter") ||
                    it.name.localName.startsWith("with_entities")
            }

        val filterCalls = paths.fulfilled.map { path -> path.nodes.last() }
        val by = node.arguments.getOrNull(1)

        if (by != null) {
            filterCalls.forEach { filterCall ->
                overlays += Filter(underlyingNode = filterCall, concept = dbAccess, by = by)
            }
        }
        overlays
    }
}

/**
 * Tags the scope enforcement calls in [OsloPolicy] that use [Authorization]. This is typically used
 * to enforce domain-specific scopes in authorization checks.
 */
fun TaggingContext.tagDomainScope() {
    each<MemberCallExpression>(predicate = { it.name.localName == "_enforce_scope" }).with {
        // Authorization concept is already set in the `AuthorizationPass`
        CheckDomainScope(underlyingNode = node, concept = Authorization(), rule = node.arguments[1])
    }
}
