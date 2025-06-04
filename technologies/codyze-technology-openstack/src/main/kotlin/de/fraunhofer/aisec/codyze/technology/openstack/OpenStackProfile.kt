/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.technology.openstack

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
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass

/**
 * The OpenStack profile for Codyze, which registers all necessary passes to analyze OpenStack
 * projects.
 */
val OpenStackProfile = { it: TranslationConfiguration.Builder ->
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
