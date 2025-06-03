/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.Secret
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression

tagging { tag { each<CallExpression>().with { Secret() } } }
