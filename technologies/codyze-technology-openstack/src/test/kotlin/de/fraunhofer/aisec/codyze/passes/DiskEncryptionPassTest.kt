/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes

import analyze
import de.fraunhofer.aisec.codyze.passes.openstack.CinderKeyManagerSecretPass
import de.fraunhofer.aisec.codyze.passes.openstack.DiskEncryptionPass
import de.fraunhofer.aisec.codyze.technology.openstack.Cinder
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption
import kotlin.io.path.Path
import kotlin.test.*

/** This test suite contains tests for the [DiskEncryptionPass]. */
class DiskEncryptionPassTest {

    /**
     * Test case to see whether the disk encryption functionality in [Cinder] can be correctly
     * parsed and identified using the [DiskEncryptionPass] and [CinderKeyManagerSecretPass].
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
                it.registerPass<DiskEncryptionPass>()
                it.registerPass<CinderKeyManagerSecretPass>()
            }

        assertNotNull(result)

        val diskEnc = result.conceptNodes.filterIsInstance<DiskEncryption>()
        assertTrue(diskEnc.isNotEmpty())
    }
}
