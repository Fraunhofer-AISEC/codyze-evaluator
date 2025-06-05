/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.encryption

import de.fraunhofer.aisec.codyze.*
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.passes.concepts.*
import de.fraunhofer.aisec.cpg.passes.concepts.logging.python.PythonLoggingConceptPass
import kotlin.io.path.Path
import kotlin.test.*

/**
 * This test suite contains tests for key management and disk encryption queries.
 */
class KeyForDiskEncryptionTest {

    /**
     * Test case for [keyNotLeakedThroughOutput] using a Python file that encrypts a key and
     * logs it. The test checks that the query detects that the key is leaked through output.
     */
    @Test
    fun testKeyNotLeakedThroughOutput() {
        val topLevel = Path("src/test/resources/encryption")
        val result =
            analyze(
                listOf(topLevel.resolve("encrypt_and_log.py").toFile()),
                topLevel,
                usePasses = true,
            ) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<PythonLoggingConceptPass>()
                it.taggingProfiles {
                    each<CallExpression>("get_secret_from_keyserver").withMultiple {
                        val secret = Secret()
                        listOf(
                            secret,
                            GetSecret(concept = secret).also {
                                // TODO(oxisto): Remove once
                                //  https://github.com/Fraunhofer-AISEC/cpg/issues/2345 is merged
                                it.nextDFG += node
                            },
                        )
                    }
                }
            }
        assertNotNull(result)

        val logWrites = result.allChildrenWithOverlays<LogWrite>()
        assertTrue(logWrites.isNotEmpty(), "We expect log writes to be present")

        val getSecrets = result.allChildrenWithOverlays<GetSecret>()
        assertTrue(getSecrets.isNotEmpty(), "We expect GetSecret nodes to be present")

        val secrets = result.allChildrenWithOverlays<Secret>()
        assertTrue(secrets.isNotEmpty(), "We expect Secret nodes to be present")

        with(result) {
            val q = keyNotLeakedThroughOutput(isLeakyOutput = { this.hasOverlay<LogWrite>() })
            assertFalse(q.value, "We expect that the key is leaked through output")
        }
    }
}
