/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack

import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.boolean
import de.fraunhofer.aisec.codyze.AnalysisProject
import de.fraunhofer.aisec.codyze.compliance.*
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.persistence.persist
import de.fraunhofer.aisec.openstack.passes.*
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass
import java.io.File
import org.neo4j.driver.GraphDatabase
import org.neo4j.driver.Session

/** The main `openstack-checker` command. */
class OpenstackCheckerCommand : ProjectCommand() {
    val neo4j by option("--neo4j", help = "Persist to Neo4J").boolean().default(false)

    override fun run() {
        val result =
            AnalysisProject.fromOptions(projectOptions, translationOptions) {
                    it.registerPass<SecretPass>()
                    it.registerPass<DiskEncryptionPass>()
                    it.registerPass<PythonMemoryPass>()
                    it.registerPass<HttpPecanLibPass>()
                    it.registerPass<SecureKeyRetrievalPass>()
                    it.registerPass<MakeThingsWorkPrototypicallyPass>()
                    it.registerPass<OsloConfigPass>()
                    it.registerPass<IniFileConfigurationSourcePass>()
                    it.registerPass<PythonEntryPointPass>()
                    // TODO: Add include path for libraries
                    it.registerPass<StevedoreDynamicLoadingPass>()
                    // Causes problems with python in general and with the include loading feature
                    it.useParallelFrontends(false)
                }
                .analyzeWithGoals()
        result.writeSarifJson(File("findings.sarif"))

        if (neo4j) {
            println("Connecting to Neo4J")

            val session = connect()
            with(session) {
                use {
                    executeWrite { tx -> tx.run("MATCH (n) DETACH DELETE n").consume() }
                    result.translationResult.persist()
                }
            }
        }
    }
}

fun main(args: Array<String>) {
    OpenstackCheckerCommand().main(args)
}

fun connect(): Session {
    val driver =
        GraphDatabase.driver(
            "neo4j://localhost:7687",
            org.neo4j.driver.AuthTokens.basic("neo4j", "password"),
        )
    driver.verifyConnectivity()
    return driver.session()
}
