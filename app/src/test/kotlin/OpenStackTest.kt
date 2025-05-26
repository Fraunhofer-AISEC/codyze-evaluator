/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.evaluation.MultiValueEvaluator
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration
import de.fraunhofer.aisec.cpg.graph.concepts.config.LoadConfiguration
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import de.fraunhofer.aisec.cpg.graph.concepts.memory.DeAllocate
import de.fraunhofer.aisec.cpg.graph.concepts.memory.Memory
import de.fraunhofer.aisec.cpg.graph.edges.get
import de.fraunhofer.aisec.cpg.graph.get
import de.fraunhofer.aisec.cpg.graph.invoke
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.ConstructExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.concepts.config.ProvideConfigPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.query.*
import de.fraunhofer.aisec.openstack.passes.*
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.openstack.queries.encryption.isSecureKeyProvider
import de.fraunhofer.aisec.openstack.queries.encryption.keyNotLeakedThroughOutput
import de.fraunhofer.aisec.openstack.queries.keymanagement.deleteSecretOnEOGPaths
import java.io.File
import kotlin.io.path.Path
import kotlin.test.*

class OpenStackTest {
    @Test
    fun testKeyInputOfOperation() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<SecretPass>()
                it.registerPass<DiskEncryptionPass>()
                it.registerPass<MakeThingsWorkPrototypicallyPass>()
                it.failOnError(false)
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to
                            listOf(
                                topLevel.resolve("cinder/cinder/volume/flows").toFile(),
                                topLevel.resolve("cinder/cinder/utils.py").toFile(),
                            ),
                        "barbican" to listOf(topLevel.resolve("barbican/barbican/api").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "barbican" to topLevel.resolve("barbican").toFile(),
                    )
                )
            }
        assertNotNull(result)

        val barbican = result.components["barbican"]
        assertNotNull(barbican)

        val evaluationResult =
            result.allExtended<DiskEncryption> { encryption ->
                encryption.key?.let { key ->
                    dataFlow(
                        startNode = encryption,
                        type = May,
                        direction = Backward(GraphToFollow.DFG),
                        sensitivities = FieldSensitive + ContextSensitive,
                        scope = Interprocedural(),
                        predicate = { it is HttpEndpoint && it.isSecureKeyProvider() },
                    )
                }
                    ?: QueryTree(
                        false,
                        mutableListOf(QueryTree(encryption)),
                        "encryptionOp.concept.key is null",
                    )
            }
        println(evaluationResult.printNicely())
        assertEquals(true, evaluationResult.value)

        val treeFunctions = evaluationResult.children
        assertEquals(1, treeFunctions.size)

        val validDataflows = treeFunctions.first().children.filter { it.value == true }
        assertEquals(1, validDataflows.size)

        // It seems its sometimes 26 and sometimes 27
        val longestValid =
            validDataflows.map { it.children.first().value as List<Node> }.maxByOrNull { it.size }
        assertNotNull(longestValid)
        assertTrue(longestValid.size >= 26)

        wrapInAnalysisResult(result, listOf(evaluationResult))
            .writeSarifJson(File("key-input-of-operation.sarif"))
    }

    @Test
    fun testBarbicanConstructor() {
        val topLevel3 = Path("../external/barbican")
        val config =
            TranslationConfiguration.builder()
                .sourceLocations(
                    listOf(
                        topLevel3.resolve("barbican/api/controllers/versions.py").toFile(),
                        topLevel3.resolve("barbican/api/controllers/secrets.py").toFile(),
                    )
                )
                .topLevel(topLevel3.toFile())
                .defaultPasses()
                .registerLanguage<PythonLanguage>()
                // .registerPass<ApiExtractionPass>()
                .exclusionPatterns("test")
                .useParallelFrontends(true)
                .build()

        val translationManager = TranslationManager.builder().config(config).build()
        val result = translationManager.analyze().get()
        val secretsController = result.calls["SecretsController"]
        assertNotNull(secretsController)
        assertIs<ConstructExpression>(secretsController)
    }

    @Test
    fun testSecretNeverLeavesBarbicanWithoutAPI() {
        val topLevel = Path("../external/barbican")
        val result =
            analyze(listOf(topLevel.resolve("barbican").toFile()), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<MakeThingsWorkPrototypicallyPass>()
                it.exclusionPatterns("tests")
            }
        assertNotNull(result)

        /*fun Node.dataLeavesComponent(): Boolean {
            val whitelist =
                listOf<String>(
                    "barbican.api.controllers.secrets.SecretController.payload.HttpEndpoint",
                    "barbican.api.controllers.secrets.SecretController.on_get.HttpEndpoint",
                )

            // TODO: This should be replaced with the respective operations (writing to a file,
            //  printing, executing commands, logging)
            return ((this is CallExpression) &&
                (this.name.localName == "write" ||
                    this.name.localName == "println" ||
                    this.name.localName == "execute" ||
                    this.name.localName == "log")) ||
                (this is HttpEndpoint && this.name.toString() !in whitelist)
        }*/

        val noKeyLeakResult = keyNotLeakedThroughOutput(result)
        println(noKeyLeakResult.printNicely())
        assertTrue(noKeyLeakResult.value)
    }

    @Test
    fun testDeleteKey() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(listOf(), topLevel, true, persistNeo4j = false) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<PythonMemoryPass>()
                it.registerPass<SecretPass>()
                it.registerPass<MakeThingsWorkPrototypicallyPass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to
                            listOf(
                                topLevel.resolve("cinder/cinder/volume/flows").toFile(),
                                topLevel.resolve("cinder/cinder/utils.py").toFile(),
                            )
                    )
                )
                it.topLevels(mapOf("cinder" to topLevel.resolve("cinder").toFile()))
            }
        assertNotNull(result)
        result.benchmarkResults.print()

        val memory = result.allChildrenWithOverlays<Memory>().singleOrNull()
        assertNotNull(memory)
        assertTrue(memory.ops.isNotEmpty())

        val secrets = result.conceptNodes.filterIsInstance<Secret>()
        assertEquals(2, secrets.size)

        val deleteKey =
            result.allExtended<DiskEncryption> {
                val processInput =
                    (it.underlyingNode as? CallExpression)?.argumentEdges?.get("process_input")?.end
                if (processInput == null) {
                    QueryTree(true)
                } else {
                    executionPath(it) { to ->
                        to is DeAllocate &&
                            (to.what as? Reference)?.refersTo ==
                                (processInput as? Reference)?.refersTo
                    }
                }
            }
        assertNotNull(deleteKey)
        assertEquals(true, deleteKey.value)

        wrapInAnalysisResult(result, listOf(deleteKey))
            .writeSarifJson(File("cinder-volume-flows.sarif"))
    }

    @Test
    fun testCinderApiNoCrash() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(listOf(), topLevel, true, persistNeo4j = false) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<PythonMemoryPass>()
                it.registerPass<SecretPass>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<MakeThingsWorkPrototypicallyPass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf("cinder" to listOf(topLevel.resolve("cinder/cinder/api").toFile()))
                )
                it.topLevels(mapOf("cinder" to topLevel.resolve("cinder").toFile()))
            }
        assertNotNull(result)
        result.benchmarkResults.print()
    }

    @Test
    fun testSecureCommunication() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(files = listOf(), topLevel = topLevel, usePasses = true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<SecureKeyRetrievalPass>()
                it.registerPass<StevedoreDynamicLoadingPass>()
                it.includePath("../external/oslo.config")
                it.includePath("../external/stevedore")
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        "castellan" to listOf(topLevel.resolve("castellan/castellan").toFile()),
                        "cinder" to
                            listOf(
                                topLevel.resolve("cinder/cinder/volume/flows").toFile(),
                                topLevel.resolve("cinder/cinder/utils.py").toFile(),
                                topLevel.resolve("cinder/cinder/common").toFile(),
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "castellan" to topLevel.resolve("castellan").toFile(),
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }

        assertNotNull(result)

        val request = result.allExtended<HttpRequest> { QueryTree(it.concept.isTLS) eq true }
        assertNotNull(request)

        assertEquals(true, request.value)

        val keyManagerAPICalls = result.calls("castellan.key_manager.API")
        keyManagerAPICalls.forEach {
            assertEquals(
                "castellan.key_manager.barbican_key_manager.BarbicanKeyManager",
                it.type.name.toString(),
                "$it's type should have the name 'castellan.key_manager.barbican_key_manager.BarbicanKeyManager'",
            )
        }

        val keyManagerAPI = result.functions["castellan.key_manager.API"]
        assertNotNull(keyManagerAPI)
        assertEquals(
            "castellan.key_manager.barbican_key_manager.BarbicanKeyManager",
            keyManagerAPI.returnTypes.singleOrNull()?.name.toString(),
            "The return type of $keyManagerAPI should be 'castellan.key_manager.barbican_key_manager.BarbicanKeyManager'",
        )
    }

    @Test
    // TODO: test "passes" but takes 1 hour
    @Ignore
    fun testEverythingDerivedFromSecretMustBeDeletedOnAllPaths() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(files = listOf(), topLevel = topLevel, usePasses = true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<SecureKeyRetrievalPass>()
                it.registerPass<PythonMemoryPass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to
                            listOf(
                                topLevel.resolve("cinder/cinder/volume/flows").toFile(),
                                topLevel.resolve("cinder/cinder/utils.py").toFile(),
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }

        assertNotNull(result)

        // For all data which originate from a GetSecret operation, all execution paths must flow
        // through a DeAllocate operation of the respective value

        val allSecretsDeletedOnEOGPaths = deleteSecretOnEOGPaths(result)

        println(allSecretsDeletedOnEOGPaths.printNicely())
        assertFalse(allSecretsDeletedOnEOGPaths.value)
        // There are 2 correct and 1 failing paths
    }

    /**
     * This test verifies correct functioning of the [OsloConfigPass], [IniFileConfigurationPass]
     * and [StevedoreDynamicLoadingPass] by analyzing the way cinder access the barbican key manager
     * API through castellan.
     *
     * It aims to include as little files as possible (and only specific files, not directories), to
     * keep it easily debuggable.
     */
    @Test
    fun testConfigAndLoadingMinimal() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<ProvideConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<StevedoreDynamicLoadingPass>()
                it.exclusionPatterns("tests")
                it.includePath("../external/oslo.config")
                it.includePath("../external/stevedore")
                it.softwareComponents(
                    mutableMapOf(
                        "castellan" to
                            listOf(
                                topLevel
                                    .resolve("castellan/castellan/key_manager/__init__.py")
                                    .toFile(),
                                topLevel
                                    .resolve("castellan/castellan/key_manager/key_manager.py")
                                    .toFile(),
                                topLevel
                                    .resolve(
                                        "castellan/castellan/key_manager/barbican_key_manager.py"
                                    )
                                    .toFile(),
                            ),
                        "cinder" to
                            listOf(
                                topLevel
                                    .resolve("cinder/cinder/volume/flows/manager/create_volume.py")
                                    .toFile(),
                                topLevel.resolve("cinder/cinder/utils.py").toFile(),
                                topLevel.resolve("cinder/cinder/common/config.py").toFile(),
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "castellan" to topLevel.resolve("castellan").toFile(),
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }
        assertNotNull(result)

        val configs = result.conceptNodes.filterIsInstance<Configuration>()
        assertEquals(
            2,
            configs.size,
            "There should be 2 configurations: castellan.conf, cinder.conf for accessing oslo.config directly",
        )

        val cinderConf = configs("cinder.conf").getOrNull(0)
        assertNotNull(cinderConf)

        val groups = cinderConf.groups
        assertTrue(groups.isNotEmpty())

        val options = groups.flatMap { it.options }
        assertTrue(options.isNotEmpty())

        val backend = options["key_manager.backend"]
        assertNotNull(backend)
        assertEquals(
            setOf("barbican"),
            backend.evaluate(MultiValueEvaluator()),
            "The evaluated value of the 'backend' option should be 'barbican'",
        )

        val keyManagerAPICalls = result.calls("castellan.key_manager.API")
        keyManagerAPICalls.forEach {
            assertEquals(
                "castellan.key_manager.barbican_key_manager.BarbicanKeyManager",
                it.type.name.toString(),
                "$it's type should have the name 'castellan.key_manager.barbican_key_manager.BarbicanKeyManager'",
            )
        }

        val keyManagerAPI = result.functions["castellan.key_manager.API"]
        assertNotNull(keyManagerAPI)
        assertEquals(
            "castellan.key_manager.barbican_key_manager.BarbicanKeyManager",
            keyManagerAPI.returnTypes.singleOrNull()?.name.toString(),
            "The return type of $keyManagerAPI should be 'castellan.key_manager.barbican_key_manager.BarbicanKeyManager'",
        )

        val keyManagerGetCall =
            result.calls("castellan.key_manager.barbican_key_manager.BarbicanKeyManager.get")
        assertEquals(
            2,
            keyManagerGetCall.size,
            "There should be 2 calls to the get method of BarbicanKeyManager that we can resolve",
        )
    }

    @Test
    fun testOsloConfig() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<ProvideConfigPass>()
                it.exclusionPatterns("tests")
                it.includePath("../external/oslo.config")
                it.softwareComponents(
                    mutableMapOf(
                        "castellan" to listOf(topLevel.resolve("castellan/castellan").toFile()),
                        "cinder" to
                            listOf(
                                topLevel.resolve("cinder/cinder/volume/flows").toFile(),
                                topLevel.resolve("cinder/cinder/utils.py").toFile(),
                                topLevel.resolve("cinder/cinder/common/").toFile(),
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "castellan" to topLevel.resolve("castellan").toFile(),
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }
        assertNotNull(result)

        val configs = result.conceptNodes.filterIsInstance<Configuration>()
        assertEquals(
            4,
            configs.size,
            "There should be 4 configurations: castellan.conf, cinder.conf for accessing oslo.config directly " +
                "and one conf and cinder.conf for accessing the barbican config source",
        )

        val loadConfigs = result.operationNodes.filterIsInstance<LoadConfiguration>()
        assertEquals(
            configs.size,
            loadConfigs.size,
            "There should be as many LoadConfiguration operations as Configuration nodes",
        )

        // Let's look at the 2nd cinder.conf (should be the one from cfg.py)
        val cinderConf = configs("cinder.conf").getOrNull(1)
        assertNotNull(cinderConf)

        val groups = cinderConf.groups
        assertTrue(groups.isNotEmpty())

        val options = groups.flatMap { it.options }
        assertTrue(options.isNotEmpty())

        val backend = options["key_manager.backend"]
        assertNotNull(backend)
        assertEquals(
            setOf("barbican"),
            backend.evaluate(MultiValueEvaluator()),
            "The evaluated value of the 'backend' option should be 'barbican'",
        )

        // This is a little bit flakey, it seems that not all paths are correctly resolved
        val meBackends = result.memberExpressions { it.code == "conf.key_manager.backend" }
        assertEquals(4, meBackends.size)
        assertEquals(
            setOf("barbican"),
            meBackends
                .map { it.evaluate(MultiValueEvaluator()) }
                .filterIsInstance<Collection<*>>()
                .flatten()
                .toSet(),
            "The evaluated value of access to 'conf.key_manager.backend' should be 'barbican'",
        )
    }
}
