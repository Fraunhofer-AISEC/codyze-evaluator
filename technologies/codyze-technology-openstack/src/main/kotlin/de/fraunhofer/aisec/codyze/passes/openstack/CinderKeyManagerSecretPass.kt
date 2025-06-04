/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.openstack

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.*
import de.fraunhofer.aisec.cpg.graph.declarations.VariableDeclaration
import de.fraunhofer.aisec.cpg.graph.invoke
import de.fraunhofer.aisec.cpg.graph.mcalls
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteLate

/**
 * Adds [Secret] concept nodes to the OpenStack function:
 * `cinder/volume/flows/manager/create_volume.py:_setup_encryption_keys()`
 * - a [Secret] concept node is added to the [VariableDeclaration] of assignments from `keymgr.get`
 *   calls
 * - a [GetSecret] operation node is added to `keymgr.get` calls
 */
@ExecuteLate
class CinderKeyManagerSecretPass(ctx: TranslationContext) : ComponentPass(ctx) {
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
