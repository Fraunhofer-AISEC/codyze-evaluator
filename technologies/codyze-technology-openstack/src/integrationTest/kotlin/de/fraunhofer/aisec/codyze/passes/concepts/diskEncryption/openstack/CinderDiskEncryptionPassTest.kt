/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.diskEncryption.openstack

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.passes.concepts.crypto.encryption.openstack.CinderKeyManagerSecretPass
import de.fraunhofer.aisec.codyze.profiles.openstack.Cinder
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption
import kotlin.io.path.Path
import kotlin.test.*

/** This test suite contains tests for the [CinderDiskEncryptionPass]. */
class CinderDiskEncryptionPassTest {

    /**
     * Test case to see whether the disk encryption functionality in [Cinder] can be correctly
     * parsed and identified using the [CinderDiskEncryptionPass] and [CinderKeyManagerSecretPass].
     */
    @Test
    fun testDiskEncryption() {
        val topLevel = Path("external/cinder")
        val result =
            analyze(
                files =
                    listOf(
                        topLevel.resolve("cinder/volume/flows/manager/create_volume.py").toFile(),
                        topLevel.resolve("cinder/utils.py").toFile(),
                    ),
                topLevel = topLevel,
                usePasses = true,
            ) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<CinderDiskEncryptionPass>()
                it.registerPass<CinderKeyManagerSecretPass>()
            }

        assertNotNull(result)

        val diskEnc = result.conceptNodes.filterIsInstance<DiskEncryption>()
        assertTrue(diskEnc.isNotEmpty())
    }
}
