/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.GetSecret
import de.fraunhofer.aisec.cpg.graph.edges.*
import de.fraunhofer.aisec.cpg.graph.followDFGEdgesUntilHit
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Literal
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteLate
import de.fraunhofer.aisec.cpg.query.value

/**
 * Adds [de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption] concept nodes to the
 * OpenStack function:
 * - `cinder/volume/flows/manager/create_volume.py:_rekey_volume()`
 */
@ExecuteLate
@DependsOn(
    SecretPass::class
) // we are connecting the [DiskEncryption] key to the [Secret] created by the [SecretPass]
class DiskEncryptionPass(ctx: TranslationContext) : ComponentPass(ctx) {
    override fun cleanup() {
        // nop
    }

    override fun accept(comp: Component) {
        comp.calls
            .filter { it.name.lastPartsMatch("utils.execute") }
            .forEach { handleUtilsExecute(it) }
    }

    fun handleUtilsExecute(call: CallExpression) {
        val what = call.arguments.getOrNull(0)
        when (what) {
            is Literal<*> -> {
                when (what.value) {
                    "cryptsetup" -> handleCryptSetup(call)
                }
            }
        }
    }

    private fun handleCryptSetup(call: CallExpression) {
        val param1 = call.arguments.getOrNull(2)
        when (param1) {
            is Literal<*> -> {
                when (param1.value) {
                    "luksFormat" -> handleLuksFormat(call)
                }
            }
        }
    }

    private fun handleLuksFormat(call: CallExpression) {
        val cipherArg = getArgValue(call, "--cipher")
        val keySizeArg = getArgValue(call, "--key-size")
        val processInputArg = call.argumentEdges["process_input"]?.end

        // walk the prevDFG backwards until a [GetSecret] operation node is found
        val key =
            processInputArg
                ?.let {
                    processInputArg
                        .followDFGEdgesUntilHit(direction = Backward(GraphToFollow.DFG)) {
                            it is GetSecret
                        }
                        .fulfilled
                        .map { it.last() }
                }
                ?.firstOrNull() ?: TODO("Expected to find exactly one matching GetSecret node.")

        val cipher = cipherArg?.let { newCipher(underlyingNode = it) }
        val concept =
            newDiskEncryption(
                underlyingNode = call,
                cipher = cipher,
                key = (key as? GetSecret)?.concept,
            )
    }

    /**
     * Finds the argument with given name [what] and returns the next argument. Use-case
     * `foo.execute('bar', '--baz=', 42)` <- we want the value of `--baz=`
     */
    private fun getArgValue(call: CallExpression, what: String): Node? {
        val result =
            call.arguments
                .filter { it is Literal<*> && it.value == what }
                .map { call.arguments.indexOf(it) }
                .map { call.arguments.getOrNull(it + 1) }
        if (result.size > 1) {
            TODO()
        } else {
            return result.singleOrNull()
        }
    }
}
