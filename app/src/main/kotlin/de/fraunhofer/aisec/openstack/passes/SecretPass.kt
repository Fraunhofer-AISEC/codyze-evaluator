/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.newGetSecret
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.newSecret
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteLate
import kotlin.collections.forEach

/**
 * Adds [de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret] concept nodes to the
 * OpenStack function:
 * - `cinder/volume/flows/manager/create_volume.py:_setup_encryption_keys()`
 *     - a [de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret] concept node is added to
 *       the [de.fraunhofer.aisec.cpg.graph.declarations.VariableDeclaration] of assignments from
 *       `keymgr.get` calls
 *     - a [de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.GetSecret] operation node is added
 *       to `keymgr.get` calls
 */
@ExecuteLate
class SecretPass(ctx: TranslationContext) : ComponentPass(ctx) {
    override fun cleanup() {
        // nop
    }

    override fun accept(comp: Component) {
        comp
            .mcalls { it.name.localName == "get" && it.base?.name?.localName == "keymgr" }
            .forEach { call ->
                call.nextDFG.forEach { nextDFG ->
                    val concept =
                        when (nextDFG) {
                            is Reference -> {
                                newSecret(underlyingNode = nextDFG, connect = true).apply {
                                    this.prevDFG += nextDFG
                                }
                            }
                            else -> {
                                TODO("Expected to find a Reference")
                            }
                        }
                    newGetSecret(underlyingNode = call, concept = concept, connect = true).apply {
                        this.nextDFG += call.nextDFG
                    }
                }
            }
    }
}
