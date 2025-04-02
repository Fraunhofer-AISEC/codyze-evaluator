/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.auth

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.auth.newAuthenticate
import de.fraunhofer.aisec.cpg.graph.concepts.auth.newTokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.MethodDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.RecordDeclaration
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.ConstructExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.graph.types.recordDeclaration
import de.fraunhofer.aisec.cpg.helpers.Util.warnWithFileLocation
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.TranslationResultPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass

/**
 * This pass creates the authentication concepts and operations. It extracts the relevant settings
 * from the configuration files, identifies the middleware handling authentication.
 */
@DependsOn(SymbolResolver::class)
@DependsOn(IniFileConfigurationSourcePass::class)
@DependsOn(HttpPecanLibPass::class)
@DependsOn(HttpWsgiPass::class)
class AuthenticationPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun accept(t: TranslationResult) {
        handleCinderConfig(t = t)
        handleBarbicanConfig(t = t)
    }

    private fun handleCinderConfig(t: TranslationResult) {
        val cinderConfig = getConfigSourceByNameOrPath(t = t, value = "cinder.conf") ?: return
        val apiPasteConfigPath =
            getConfigOptionValue(conf = cinderConfig, optionName = "api_paste_config") ?: return
        val authStrategyValue =
            getConfigOptionValue(conf = cinderConfig, optionName = "auth_strategy") ?: return
        val apiPasteConfig =
            getConfigSourceByNameOrPath(t = t, value = apiPasteConfigPath) ?: return
        val authPipeline =
            getConfigOptionValue(conf = apiPasteConfig, optionName = authStrategyValue) ?: return
        applyAuthentication(
            t = t,
            configSource = apiPasteConfig,
            authPipeline = authPipeline,
            componentName = "cinder",
        )
    }

    private fun handleBarbicanConfig(t: TranslationResult) {
        val barbicanConfig =
            getConfigSourceByNameOrPath(t = t, value = "barbican-api-paste.ini") ?: return
        val authStrategyValue =
            getConfigOptionValue(conf = barbicanConfig, optionName = "/v1") ?: return
        val authPipeline =
            getConfigOptionValueByGroupName(conf = barbicanConfig, groupName = authStrategyValue)
                ?: return
        applyAuthentication(
            t = t,
            configSource = barbicanConfig,
            authPipeline = authPipeline,
            componentName = "barbican",
        )
    }

    /**
     * Processes the PasteDeploy pipeline for the given configuration source, registers token-based
     * authentication, and applies it to the HTTP endpoints of the corresponding component.
     */
    private fun applyAuthentication(
        t: TranslationResult,
        configSource: ConfigurationSource,
        authPipeline: String,
        componentName: String,
    ) {
        val authProtocol =
            extractMiddlewareFromPipeline(
                t = t,
                configSource = configSource,
                authPipeline = authPipeline,
            ) ?: return
        val tokenBasedAuth = registerTokenAuthentication(authProtocol = authProtocol, t = t)
        if (tokenBasedAuth != null) {
            val component = t.components.singleOrNull { it.name.localName == componentName }
            component?.allChildrenWithOverlays<HttpEndpoint>()?.forEach {
                it.authentication = tokenBasedAuth
            }
        }
    }

    /**
     * Extracts the middleware class from the PasteDeploy pipeline for `keystonemiddleware`. It
     * processes the pipeline (e.g.,"keystone = cors http_proxy_to_wsgi faultwrap sizelimit
     * authtoken keystonecontext apiv3"), where `authtoken` points to a `filter_factory` option
     * (e.g.,`keystonemiddleware.auth_token:filter_factory`). The method then searches for this
     * middleware function in 'keystonemiddleware' and returns the class which is instantiated from
     * it and handles incoming requests and responses via its `__call__` method.
     */
    private fun extractMiddlewareFromPipeline(
        t: TranslationResult,
        configSource: ConfigurationSource,
        authPipeline: String,
    ): RecordDeclaration? {
        val authTokenValue =
            authPipeline.split(" ").firstOrNull() { it == "authtoken" } ?: return null

        // Find config group which contains 'authtoken'. This specifies the middleware invocation.
        val authTokenGroupFilter =
            configSource.groups.firstOrNull { it.name.localName.contains(authTokenValue) }

        val middlewareFilterFactory =
            authTokenGroupFilter?.options?.firstOrNull {
                it.name.localName == "filter_factory" && it.name.parent?.localName == "paste"
            }
        val middlewareFunctionName =
            (middlewareFilterFactory?.evaluate() as? String)?.replace(":", ".")
        val middlewareFilterFunction =
            t.functions.firstOrNull { it.name.toString() == middlewareFunctionName } ?: return null

        return getAuthProtocol(middleWareFilterFunction = middlewareFilterFunction)
    }

    /**
     * Extracts the 'AuthProtocol' class from `keystonemiddleware` that contains the `__call__`
     * method handling the incoming requests and responses.
     */
    private fun getAuthProtocol(middleWareFilterFunction: FunctionDeclaration): RecordDeclaration? {
        val authProtocolConstruct =
            middleWareFilterFunction.followPrevDFG { it is ConstructExpression }?.lastOrNull()
                as? ConstructExpression
        val authProtocolRecord = authProtocolConstruct?.instantiates as? RecordDeclaration
        val record = authProtocolRecord?.superClasses?.firstOrNull()?.recordDeclaration
        return record
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
        authProtocol: RecordDeclaration,
        t: TranslationResult,
    ): TokenBasedAuth? {
        // The `__call__` method handles incoming requests and responses in 'keystonemiddleware'
        val authCallMethod =
            authProtocol.methods.firstOrNull { it.name.localName == "__call__" } ?: return null
        // Extract the 'X-Auth-Token' token from headers
        val token = getToken(t = t, callMethod = authCallMethod) ?: return null
        // The getter method (annotated with pythons `@property` decorator) holds the extracted
        // token
        val tokenProperty = token.firstParentOrNull<MethodDeclaration>() ?: return null

        // Validate the token by following its usage until `fetch_token` is called
        val tokenValidation =
            getTokenValidation(callMethod = authCallMethod, tokenProperty = tokenProperty)

        // Check the Keystone configuration to determine the token provider
        val keystoneConf = getConfigSourceByNameOrPath(t, "keystone.conf") ?: return null
        val tokenProvider =
            keystoneConf.groups
                .flatMap { group -> group.options.filter { it.name.localName == "provider" } }
                .firstOrNull()
                ?.underlyingNode
        val tokenProviderValue = getConfigOptionValue(conf = keystoneConf, optionName = "provider")

        if (tokenValidation != null && tokenProvider != null && tokenProviderValue == "fernet") {
            val tokenBasedAuth =
                newTokenBasedAuth(underlyingNode = tokenProvider, token = tokenProperty)
            newAuthenticate(
                underlyingNode = tokenValidation,
                concept = tokenBasedAuth,
                credential = token,
            )
            return tokenBasedAuth
        }
        return null
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
                ?.map { it.last() }

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
                .firstOrNull { it.name.localName.contains(groupName) }
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
