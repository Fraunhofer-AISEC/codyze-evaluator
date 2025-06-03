/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.openstack

import de.fraunhofer.aisec.codyze.openstack.passes.DiskEncryptionPass
import de.fraunhofer.aisec.codyze.openstack.passes.MakeThingsWorkPrototypicallyPass
import de.fraunhofer.aisec.codyze.openstack.passes.OsloConfigPass
import de.fraunhofer.aisec.codyze.openstack.passes.PythonEntryPointPass
import de.fraunhofer.aisec.codyze.openstack.passes.PythonMemoryPass
import de.fraunhofer.aisec.codyze.openstack.passes.SecretPass
import de.fraunhofer.aisec.codyze.openstack.passes.SecureKeyRetrievalPass
import de.fraunhofer.aisec.codyze.openstack.passes.StevedoreDynamicLoadingPass
import de.fraunhofer.aisec.codyze.openstack.passes.auth.AuthenticationPass
import de.fraunhofer.aisec.codyze.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.codyze.openstack.passes.http.HttpWsgiPass
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass

/**
 * The OpenStack profile for Codyze, which registers all necessary passes to analyze OpenStack
 * projects.
 */
val OpenStackProfile = { it: TranslationConfiguration.Builder ->
    it.registerPass<SecretPass>()
    it.registerPass<DiskEncryptionPass>()
    it.registerPass<PythonMemoryPass>()
    it.registerPass<HttpPecanLibPass>()
    it.registerPass<HttpWsgiPass>()
    it.registerPass<AuthenticationPass>()
    it.registerPass<SecureKeyRetrievalPass>()
    it.registerPass<MakeThingsWorkPrototypicallyPass>()
    it.registerPass<OsloConfigPass>()
    it.registerPass<IniFileConfigurationSourcePass>()
    it.registerPass<PythonEntryPointPass>()
    it.registerPass<StevedoreDynamicLoadingPass>()
}
