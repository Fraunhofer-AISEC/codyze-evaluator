/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.auth.openstack

import de.fraunhofer.aisec.codyze.graph.concepts.auth.ExtendedRequestContext
import de.fraunhofer.aisec.codyze.graph.concepts.auth.newRequestContext
import de.fraunhofer.aisec.codyze.graph.concepts.auth.newUserInfo
import de.fraunhofer.aisec.codyze.passes.concepts.http.python.*
import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.auth.*
import de.fraunhofer.aisec.cpg.graph.concepts.config.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.declarations.*
import de.fraunhofer.aisec.cpg.graph.statements.expressions.*
import de.fraunhofer.aisec.cpg.graph.types.recordDeclaration
import de.fraunhofer.aisec.cpg.helpers.Util.warnWithFileLocation
import de.fraunhofer.aisec.cpg.helpers.identitySetOf
import de.fraunhofer.aisec.cpg.passes.TranslationResultPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn

/**
 * This pass creates the authentication concepts and operations. It extracts the relevant settings
 * from the configuration files, identifies the middleware handling authentication.
 */
@DependsOn(IniFileConfigurationSourcePass::class)
@DependsOn(HttpPecanLibPass::class)
@DependsOn(HttpWsgiPass::class)
@DependsOn(IniFileConfigurationSourcePass::class)
class AuthenticationPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun accept(t: TranslationResult) {
        handleCinderConfig(t = t)
        handleBarbicanConfig(t = t)
    }

    /**
     * Handles authentication for Cinder component.
     *
     * Assumptions:
     * - The configuration for Cinder component is located in `cinder.conf`
     * - The authentication strategy is defined in `auth_strategy`
     * - The API paste config file is specified in `api_paste_config`
     *
     * See
     * [Cinder Config samples](https://docs.openstack.org/cinder/2025.1/configuration/block-storage/samples/index.html)
     */
    private fun handleCinderConfig(t: TranslationResult) {
        val cinderConfig = getConfigSourceByNameOrPath(t = t, value = "cinder.conf") ?: return
        // The `api-paste.ini` file path is specified in cinder config
        val apiPasteConfigPath =
            getConfigOptionValue(conf = cinderConfig, optionName = "api_paste_config") ?: return
        val apiPasteConfig =
            getConfigSourceByNameOrPath(t = t, value = apiPasteConfigPath) ?: return
        // The authentication strategy (e.g., "keystone")
        val authStrategyValue =
            getConfigOptionValue(conf = cinderConfig, optionName = "auth_strategy") ?: return
        val requestContext =
            registerRequestContext(t = t, conf = apiPasteConfig, authStrategy = authStrategyValue)
        // Get the API version with authentication applied
        val apiVersionWithAuth =
            findApiVersionNameWithAuth(conf = apiPasteConfig, authStrategy = authStrategyValue)
        if (apiVersionWithAuth != null) {
            applyAuthentication(
                t = t,
                configSource = apiPasteConfig,
                componentName = "cinder",
                apiVersionWithAuth = apiVersionWithAuth,
                requestContext = requestContext,
            )
        }
    }

    /**
     * Handles authentication for Barbican component. Unlike in Cinder, the Barbican configuration
     * file does not specify the authentication strategy or the path to the API paste config file.
     * Therefore, we use the values following the guidelines from
     * [Barbican Keystone Middleware setup](https://docs.openstack.org/barbican/2025.1/configuration/keystone.html).
     *
     * Assumptions:
     * - The API paste config file for Barbican component is located in `barbican-api-paste.ini`.
     * - The authentication strategy is defined in the `/v1` section
     */
    private fun handleBarbicanConfig(t: TranslationResult) {
        val barbicanConfig =
            getConfigSourceByNameOrPath(t = t, value = "barbican-api-paste.ini") ?: return
        // Extract the authentication strategy
        val authStrategyValue =
            getConfigOptionValue(conf = barbicanConfig, optionName = "/v1") ?: return
        val requestContext =
            registerRequestContext(t = t, conf = barbicanConfig, authStrategy = authStrategyValue)
        // Get the API version with authentication applied
        val apiVersionWithAuth =
            findApiVersionNameWithAuth(conf = barbicanConfig, authStrategy = authStrategyValue)
        if (apiVersionWithAuth != null) {
            applyAuthentication(
                t = t,
                configSource = barbicanConfig,
                componentName = "barbican",
                apiVersionWithAuth = apiVersionWithAuth,
                requestContext = requestContext,
            )
        }
    }

    private fun registerRequestContext(
        t: TranslationResult,
        conf: ConfigurationSource,
        authStrategy: String,
    ): RequestContext? {
        // We need to extract the name of the context from the pipeline
        val pipeline =
            getPipelineWithAuthToken(conf = conf, authStrategy).firstOrNull() ?: return null
        val context =
            pipeline.evaluate().toString().split(" ").firstOrNull {
                it.contains("context", ignoreCase = true)
            } ?: ""
        val contextOptionValue = getConfigOptionValueByGroupName(conf = conf, groupName = context)
        if (contextOptionValue == null) {
            warnWithFileLocation(conf, log, "Could not find '{}' in configuration", context)
            return null
        }
        val adjustedContextOptionValue = contextOptionValue.replace(":", ".")
        val contextClass =
            t.records.singleOrNull { adjustedContextOptionValue.contains(it.name.toString()) }
                as? RecordDeclaration

        // TODO: Need to find a way how to reach the RequestContext from the context class (which we
        // get from the config)
        //  for now we assume that the RequestContext is set in the same file and we know that
        // `context.RequestContext.from_environ(req.environ, **kwargs)`
        // is called, therefore we search for that call manually
        val fromEnvironCall =
            contextClass?.astParent.mcalls.singleOrNull { it.name.localName == "from_environ" }
        val requestContext =
            fromEnvironCall?.followPrevDFG { it is RecordDeclaration }?.nodes?.lastOrNull()
                as? RecordDeclaration
        if (requestContext != null) {
            // Here, we should normally follow the data flow of the token through the middleware and
            // keystone. For now, we assume that the validation is done, and we can access the user
            // data of the RequestContext base class from oslo.context
            val token = getFieldOfRecordOrSupertype(requestContext, "auth_token") ?: return null
            val reqContext =
                newRequestContext(underlyingNode = requestContext, token = token, connect = true)
            registerUserInfo(record = requestContext, requestContext = reqContext)
            return reqContext
        }
        return null
    }

    private fun getFieldOfRecordOrSupertype(
        recordDeclaration: RecordDeclaration,
        fieldName: String,
    ): FieldDeclaration? {
        val alreadySeen = identitySetOf<RecordDeclaration>()
        alreadySeen.add(recordDeclaration)
        val worklist = mutableListOf(recordDeclaration)
        while (worklist.isNotEmpty()) {
            val currentRecord = worklist.removeFirst()
            val field = currentRecord.fields.singleOrNull { it.name.localName == fieldName }
            if (field != null) {
                return field
            }
            worklist += currentRecord.superTypeDeclarations.filter { alreadySeen.add(it) }
        }
        return null
    }

    /** Registers user information into the provided request context. */
    fun registerUserInfo(record: RecordDeclaration, requestContext: ExtendedRequestContext) {
        val userId = getFieldOfRecordOrSupertype(record, "user_id")
        val projectId = getFieldOfRecordOrSupertype(record, "project_id")
        val roles = getFieldOfRecordOrSupertype(record, "roles")
        val systemScope = getFieldOfRecordOrSupertype(record, "system_scope")
        val domainId = getFieldOfRecordOrSupertype(record, "domain_id")
        newUserInfo(
            underlyingNode = record,
            concept = requestContext,
            userId = userId,
            projectId = projectId,
            roles = roles,
            systemScope = systemScope,
            domainId = domainId,
            connect = true,
        )
    }

    /**
     * Processes the PasteDeploy pipeline for the given configuration source, registers token-based
     * authentication, and applies it to the HTTP endpoints of the corresponding component.
     */
    private fun applyAuthentication(
        t: TranslationResult,
        configSource: ConfigurationSource,
        componentName: String,
        apiVersionWithAuth: ConfigurationOptionSource,
        requestContext: RequestContext?,
    ) {
        val middlewareClass = resolveMiddlewareHandler(t = t, configSource = configSource) ?: return
        val tokenBasedAuth = registerTokenAuthentication(middlewareClass = middlewareClass, t = t)
        if (tokenBasedAuth != null) {
            val component = t.components.singleOrNull { it.name.localName == componentName }
            component?.allChildrenWithOverlays<HttpEndpoint>()?.forEach {
                if (it.path.contains(apiVersionWithAuth.name.localName)) {
                    it.authentication = tokenBasedAuth
                    it.requestContext = requestContext
                }
            }
        }
    }

    /**
     * Retrieves the pipeline containing the authentication token from the [ConfigurationSource].
     */
    private fun getPipelineWithAuthToken(
        conf: ConfigurationSource,
        authStrategy: String?,
    ): List<ConfigurationOptionSource> {
        val keystonemiddlewareGroup = findMiddlewareGroup(conf = conf) ?: return emptyList()
        // Since this is a filter: take the name of the group and find the pipelines that reference
        // this filter
        val keystonemiddlewareGroupName =
            keystonemiddlewareGroup.name.localName.substringAfterLast(":")

        return conf.groups.flatMap { group ->
            val matchingOptions =
                group.options.filter { option ->
                    val optionValue = option.evaluate() as? String
                    optionValue?.split(" ")?.contains(keystonemiddlewareGroupName) == true
                }
            when {
                matchingOptions.size == 1 -> matchingOptions
                matchingOptions.size > 1 && authStrategy != null ->
                    matchingOptions.filter { option -> option.name.localName == authStrategy }

                else -> emptyList()
            }
        }
    }

    /**
     * Returns the API version which has authentication applied.
     *
     * This method searches for the middleware group containing `keystonemiddleware.auth_token`,
     * then identifies all options and groups referencing this middleware group. The method
     * continues the search until it reaches the 'root/main' group, which specifies the API version
     * (e.g., `/v1`, `/v2`) that has authentication registered.
     */
    private fun findApiVersionNameWithAuth(
        conf: ConfigurationSource,
        authStrategy: String?,
    ): ConfigurationOptionSource? {
        val matchingOptions = getPipelineWithAuthToken(conf = conf, authStrategy = authStrategy)
        val relevantGroupNames =
            conf.groups
                .filter { group -> group.options.any { it in matchingOptions } }
                .map { it.name.localName.substringAfterLast(":") }
        // We check that the option matches the relevant group names found above and
        // look for the option that specifies the API version
        return conf.groups
            .flatMap { it.options }
            .singleOrNull { option ->
                val optionValue = option.evaluate() as? String
                val nameContainsV = option.name.contains("/v")
                val valueMatches = relevantGroupNames.any { optionValue?.contains(it) == true }
                nameContainsV && valueMatches
            }
    }

    /**
     * Resolves the class that is returned by the `filter_factory` defined in the PasteDeploy
     * configuration.
     *
     * This is the middleware class that processes incoming HTTP requests and responses, by
     * implementing a `__call__` method.
     */
    private fun resolveMiddlewareHandler(
        t: TranslationResult,
        configSource: ConfigurationSource,
    ): RecordDeclaration? {
        val middleware = findMiddlewareGroup(conf = configSource)
        val middlewareFunctionName =
            (middleware?.options?.singleOrNull()?.evaluate() as? String)?.replace(":", ".")
        val middlewareFilterFunction =
            t.functions.firstOrNull { it.name.toString() == middlewareFunctionName } ?: return null

        val construct =
            middlewareFilterFunction
                .followPrevDFG { it is ConstructExpression }
                ?.nodes
                ?.lastOrNull() as? ConstructExpression
        val middlewareClass = construct?.instantiates as? RecordDeclaration
        return middlewareClass?.superClasses?.firstOrNull()?.recordDeclaration
    }

    /**
     * Searches for the middleware group in the given [ConfigurationSource] that contains
     * `keystonemiddleware.auth_token`.
     *
     * **Note:** This search is somewhat to specific for `keystonemiddleware.auth_token`. In the
     * future it may need to be generalized to support potential configuration changes.
     */
    private fun findMiddlewareGroup(conf: ConfigurationSource): ConfigurationGroupSource? {
        return conf.groups.singleOrNull() { group ->
            group.options.any { option ->
                (option.underlyingNode?.evaluate() as? String)?.contains(
                    "keystonemiddleware.auth_token"
                ) == true
            }
        }
    }

    /**
     * Registers token-based authentication by creating the concepts and operations.
     *
     * As Keystone is not parsed at the moment, and he token is sent back to Keystone for
     * validation, we do not know the actual token provider used. Instead, we simulate this by
     * checking `keystone.conf` for the `provider` option (e.g., `fernet`) to decide whether to
     * register the authentication.
     */
    private fun registerTokenAuthentication(
        middlewareClass: RecordDeclaration,
        t: TranslationResult,
    ): TokenBasedAuth? {
        // The `__call__` method handles incoming requests and responses in 'keystonemiddleware'
        val callMethod =
            middlewareClass.methods.firstOrNull { it.name.localName == "__call__" } ?: return null
        // Extract the 'X-Auth-Token' token from headers
        val token = getToken(t = t, callMethod = callMethod) ?: return null
        // The getter method (annotated with pythons `@property` decorator) holds the extracted
        // token
        val tokenProperty = token.firstParentOrNull<MethodDeclaration>() ?: return null

        // Validate the token by following its usage until `fetch_token` is called
        val tokenValidation =
            getTokenValidation(callMethod = callMethod, tokenProperty = tokenProperty)

        // Check the Keystone configuration to determine the token provider
        val keystoneConf = getConfigSourceByNameOrPath(t, "keystone.conf") ?: return null
        val tokenProvider =
            keystoneConf.groups
                .filter { it.name.localName == "token" }
                .flatMap { group -> group.options.filter { it.name.localName == "provider" } }
                .singleOrNull() ?: return null
        val tokenProviderField = tokenProvider.underlyingNode as? FieldDeclaration ?: return null
        val tokenProviderValue = getConfigOptionValue(conf = keystoneConf, optionName = "provider")

        return when (tokenProviderValue) {
            "fernet" -> {
                val tokenBasedAuth =
                    newTokenBasedAuth(tokenProviderField, tokenProperty, connect = true)
                if (tokenValidation != null) {
                    newAuthenticate(tokenValidation, tokenBasedAuth, tokenProperty, connect = true)
                    tokenBasedAuth
                } else null
            }

            "jws" -> TODO("Support for JWS not yet implemented")
            else -> null
        }
    }

    /**
     * Follows the argument `req` from the `__call__` method until `fetch_token` is called;
     * `fetch_token` validates the token through keystone.
     */
    private fun getTokenValidation(
        callMethod: MethodDeclaration,
        tokenProperty: MethodDeclaration,
    ): MemberCallExpression? {
        val tokenUsages =
            callMethod.parameters
                .firstOrNull()
                ?.followNextFullDFGEdgesUntilHit(
                    collectFailedPaths = false,
                    findAllPossiblePaths = false,
                ) {
                    it is MemberExpression && it.name.localName == tokenProperty.name.localName
                }
                ?.fulfilled
                ?.map { it.nodes.last() }

        return tokenUsages
            ?.singleOrNull() { it.astParent?.name?.localName?.contains("fetch_token") == true }
            ?.astParent as? MemberCallExpression
    }

    /**
     * Extracts the request class from the `__call__` methods `@wsgify` decorator. It returns the
     * [CallExpression] which reads the `X-Auth-Token` from the HTTP headers.
     */
    private fun getToken(t: TranslationResult, callMethod: MethodDeclaration): CallExpression? {
        // We need to extract the class from the method annotation:
        // `@webob.dec.wsgify(RequestClass=_request._AuthTokenRequest)`. The @wsgify decorator
        // converts the WSGI environ (a dict which holds the raw HTTP data) into a
        // _AuthTokenRequest, which is passed as 'req' to handle the incoming request.
        val annotation =
            callMethod.annotations
                .firstOrNull { it.name.localName == "wsgify" }
                ?.members
                ?.firstOrNull { it.name.localName == "RequestClass" }

        // TODO: check why `_request._AuthTokenRequest` is a MemberExpression. For now extract the
        // name of the class and do a manual search
        val authTokenRequestClass =
            t.records.firstOrNull { it.name.localName == annotation?.value?.name?.localName }

        return authTokenRequestClass?.calls?.firstOrNull {
            (it.arguments.firstOrNull()?.evaluate() as? String) == "X-Auth-Token" &&
                it.name.localName == "get"
        }
    }

    /**
     * Retrieves the value of a specified option with local name [optionName] from the
     * [ConfigurationSource] [conf].
     */
    private fun getConfigOptionValue(conf: ConfigurationSource, optionName: String): String? {
        val configOptionField =
            conf.groups
                .flatMap { group -> group.options.filter { it.name.localName == optionName } }
                .firstOrNull()
                ?.underlyingNode
        return if (configOptionField != null) {
            configOptionField.evaluate() as? String
        } else {
            warnWithFileLocation(
                conf,
                log,
                "Could not find option '{}' in configuration",
                optionName,
            )
            null
        }
    }

    /**
     * Retrieves the value of a specified option with local name [groupName] from the
     * [ConfigurationSource] [conf].
     */
    private fun getConfigOptionValueByGroupName(
        conf: ConfigurationSource,
        groupName: String,
    ): String? {
        val configOptionField =
            conf.groups
                .singleOrNull() { it.name.localName.endsWith(groupName) }
                ?.options
                ?.singleOrNull()
                ?.underlyingNode
        return if (configOptionField != null) {
            configOptionField.evaluate() as? String
        } else {
            warnWithFileLocation(
                conf,
                log,
                "Could not find option '{}' in configuration",
                groupName,
            )
            null
        }
    }

    /** Finds a [ConfigurationSource] by (full) name or path matching [value] */
    private fun getConfigSourceByNameOrPath(
        t: TranslationResult,
        value: String,
    ): ConfigurationSource? {
        val configSource =
            t.conceptNodes.filterIsInstance<ConfigurationSource>().firstOrNull {
                it.name.toString() == value ||
                    it.location?.artifactLocation?.uri?.path?.contains(value) == true
            }
        return if (configSource != null) {
            configSource
        } else {
            warnWithFileLocation(t, log, "Could not find configuration source for '{}'", value)
            null
        }
    }

    override fun cleanup() {
        // Nothing to do here
    }
}
