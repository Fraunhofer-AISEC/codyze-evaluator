/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.auth

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.newTokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.passes.TranslationResultPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.openstack.passes.OsloConfigPass
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass

@DependsOn(OsloConfigPass::class)
@DependsOn(IniFileConfigurationSourcePass::class)
@DependsOn(HttpPecanLibPass::class)
@DependsOn(HttpWsgiPass::class)
class AuthenticationPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun accept(t: TranslationResult) {
        val cinderConf =
            t.conceptNodes.filterIsInstance<ConfigurationSource>().firstOrNull {
                it.name.toString() == "cinder.conf"
            }
        if (cinderConf == null) {
            log.warn("Configuration 'cinder.conf' not found: {}", cinderConf)
            return
        }
        val authStrategyField =
            cinderConf.groups
                .flatMap { it.options.filter { it.name.localName == "auth_strategy" } }
                .firstOrNull()
                ?.underlyingNode

        val authStrategyValue = authStrategyField?.evaluate() as? String

        val apiPasteConfigField =
            cinderConf.groups
                .flatMap { it.options.filter { it.name.localName == "api_paste_config" } }
                .firstOrNull()
                ?.underlyingNode

        if (apiPasteConfigField == null) {
            log.warn("No 'api_paste_config' defined: {}", cinderConf)
            return
        }
        val apiPasteConfigPath = apiPasteConfigField.evaluate() as String

        val apiPasteConfig =
            t.conceptNodes.filterIsInstance<ConfigurationSource>().firstOrNull {
                it.name.localName.contains(apiPasteConfigPath)
            }

        val apiPasteConfigAuthStrategy =
            apiPasteConfig
                ?.groups
                ?.flatMap { it.options.filter { it.name.localName == authStrategyValue } }
                ?.firstOrNull()
                ?.underlyingNode

        val apiPasteConfigAuthPipeline = apiPasteConfigAuthStrategy?.evaluate() as? String
        val authTokenValue =
            apiPasteConfigAuthPipeline?.split(" ")?.firstOrNull() { it == "authtoken" }

        val keystoneConf =
            t.conceptNodes.filterIsInstance<ConfigurationSource>().firstOrNull {
                it.name.toString() == "keystone.conf"
            }
        val tokenProvider =
            keystoneConf
                ?.groups
                ?.flatMap { it.options.filter { it.name.localName == "provider" } }
                ?.firstOrNull()
                ?.underlyingNode
        val tokenProviderValue = tokenProvider?.evaluate() as? String

        if (authTokenValue != null && tokenProviderValue == "fernet") {
            newTokenBasedAuth(underlyingNode = authStrategyField!!, token = tokenProvider)
        }
    }

    override fun cleanup() {
        // Nothing to do here
    }
}
