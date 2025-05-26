/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with

tagging { tag { each<CallExpression>().with { Secret() } } }
