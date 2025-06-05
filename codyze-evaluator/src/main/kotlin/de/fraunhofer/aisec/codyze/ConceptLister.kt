/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.main
import de.fraunhofer.aisec.cpg.graph.OverlayNode
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation
import de.fraunhofer.aisec.cpg.graph.listOverlayClasses
import kotlin.reflect.full.memberProperties

/** The main `concept-lister` command. */
class ConceptListerCommand : CliktCommand() {
    override fun run() {
        println("# Concepts and Operations")
        println("")
        println("Concepts and operations serve as a representation of program semantics.")
        println(
            "Operations are used to model a certain behavior of the program whereas concepts represent a high-level abstraction of some program behavior, arguments or anything else."
        )
        println(
            "They mainly serve to simplify writing queries and to provide a more semantic view of the program."
        )
        println("Thus, they serve as a main entry-point for an analyst writing custom queries.")
        println(
            "This document aims to provide a list of all concepts and operations that are available in the OpenStack Checker."
        )
        println("")
        println("# Concepts")

        val overlayProperties = OverlayNode::class.memberProperties.map { it.name }
        val conceptClasses = listOverlayClasses<Concept>()
        for (conceptClass in conceptClasses) {
            println("## ${conceptClass.simpleName}")

            conceptClass.kotlin.constructors.forEach {
                println("### Constructor: ${conceptClass.simpleName}")
                println("Arguments:\n")
                it.parameters.forEach {
                    println("* `${it.name}: ${it.type}`" + if (it.isOptional) " (optional)" else "")
                }
            }
            println()
            println("### Properties:\n")
            conceptClass.kotlin.memberProperties.forEach {
                if (it.name !in overlayProperties) {
                    println("* `${it.name}: ${it.returnType}`")
                }
            }

            println()
        }

        println("# Operations")
        val operationClasses = listOverlayClasses<Operation>()
        for (operationClass in operationClasses) {
            println("## ${operationClass.simpleName}")

            operationClass.kotlin.constructors.forEach {
                println("### Constructor: ${operationClass.simpleName}")
                println("Arguments:\n")
                it.parameters.forEach {
                    println("* `${it.name}: ${it.type}`" + if (it.isOptional) " (optional)" else "")
                }
            }
            println()
            println("### Properties:\n")
            operationClass.kotlin.memberProperties.forEach {
                if (it.name !in overlayProperties) {
                    println("* `${it.name}: ${it.returnType}`")
                }
            }

            println()
        }
    }
}

fun main(args: Array<String>) {
    ConceptListerCommand().main(args)
}
