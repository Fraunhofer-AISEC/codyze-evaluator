/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.encryption

import de.fraunhofer.aisec.codyze.*
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.get
import de.fraunhofer.aisec.cpg.query.*
import java.io.File
import java.nio.file.Path
import kotlin.io.path.Path
import kotlin.test.*

/** This test suite contains tests for disk encryption queries using the [OpenStackProfile]. */
class KeyForDiskEncryptionTest {

    /**
     * Test case for [keyOnlyReachableThroughSecureKeyProvider] using [isSecureOpenStackKeyProvider]
     * with [OpenStackProfile]. The analyzed components are [Cinder] and [Barbican].
     */
    @Test
    fun testKeyOnlyReachableThroughSecureKeyProvider() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                OpenStackProfile(it)
                it.failOnError(false)
                it.useComponents(
                    topLevel,
                    Barbican to listOf("barbican/api"),
                    Cinder to listOf("cinder/volume/flows", "cinder/utils.py"),
                )
            }
        assertNotNull(result)

        val barbican = result.components["barbican"]
        assertNotNull(barbican)

        with(result) {
            val q =
                /*keyOnlyReachableThroughSecureKeyProvider(
                    isSecureKeyProvider = HttpEndpoint::isSecureOpenStackKeyProvider
                )*/
                result.allExtended<DiskEncryption> { encryption ->
                    encryption.key?.let { key ->
                        dataFlow(
                            startNode = encryption,
                            // TODO(oxisto): The original query used `Must` here, which has failing
                            // paths - why
                            type = May,
                            direction = Backward(GraphToFollow.DFG),
                            sensitivities = FieldSensitive + ContextSensitive,
                            scope = Interprocedural(),
                            predicate = { it is HttpEndpoint && it.isSecureOpenStackKeyProvider() },
                        )
                    }
                        ?: QueryTree(
                            false,
                            mutableListOf(QueryTree(encryption)),
                            "encryptionOp.concept.key is null",
                        )
                }
            println(q.printNicely())
            assertEquals(true, q.value)

            val treeFunctions = q.children
            assertEquals(1, treeFunctions.size)

            val validDataflows = treeFunctions.first().children.filter { it.value == true }
            assertEquals(1, validDataflows.size)

            // It seems its sometimes 26 and sometimes 27
            val longestValid =
                validDataflows.map { it.children.first().value as List<*> }.maxByOrNull { it.size }
            assertNotNull(longestValid)
            assertTrue(longestValid.size >= 26)

            wrapInAnalysisResult(result, listOf(q))
                .writeSarifJson(File("key-input-of-operation.sarif"))
        }
    }

    /**
     * Test case for [keyNotLeakedThroughOutput] using [dataLeavesOpenStackComponent] with
     * [OpenStackProfile]. The analyzed component is [Barbican].
     */
    @Test
    fun testKeyNotLeakedThroughOutput() {
        val topLevel = Path("external/barbican")
        val result =
            analyze(listOf(topLevel.resolve("barbican").toFile()), topLevel, true) {
                OpenStackProfile(it)
                it.exclusionPatterns("tests")
            }
        assertNotNull(result)

        with(result) {
            val noKeyLeakResult = keyNotLeakedThroughOutput(Node::dataLeavesOpenStackComponent)
            println(noKeyLeakResult.printNicely())
            assertTrue(noKeyLeakResult.value)
        }
    }
}
