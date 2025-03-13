/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.allChildren
import de.fraunhofer.aisec.cpg.graph.concepts.memory.*
import de.fraunhofer.aisec.cpg.graph.statements.expressions.DeleteExpression
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.ControlFlowSensitiveDFGPass
import de.fraunhofer.aisec.cpg.passes.EvaluationOrderGraphPass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn

/** This pass creates [Memory] */
@DependsOn(ControlFlowSensitiveDFGPass::class)
@DependsOn(EvaluationOrderGraphPass::class)
class PythonMemoryPass(ctx: TranslationContext) : ComponentPass(ctx) {
    override fun accept(comp: Component) {
        // Create one memory concept per component
        val memory = newMemory(comp, MemoryManagementMode.MANAGED_WITH_GARBAGE_COLLECTION)

        // We are only interested in delete expressions
        comp.allChildren<DeleteExpression>().forEach { deleteExpr ->
            deleteExpr.operands.forEach {
                newDeallocate(underlyingNode = deleteExpr, concept = memory, what = it).apply {
                    this.prevDFGEdges += it
                }
            }
        }
    }

    override fun cleanup() {
        // nothing to do
    }
}
