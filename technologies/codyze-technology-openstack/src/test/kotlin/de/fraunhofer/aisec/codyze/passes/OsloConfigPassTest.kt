/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes

import analyze
import de.fraunhofer.aisec.codyze.openstack.passes.OsloConfigPass
import de.fraunhofer.aisec.codyze.openstack.passes.SecureKeyRetrievalPass
import de.fraunhofer.aisec.codyze.openstack.passes.StevedoreDynamicLoadingPass
import de.fraunhofer.aisec.cpg.evaluation.MultiValueEvaluator
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.config.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import de.fraunhofer.aisec.cpg.passes.concepts.config.*
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.*
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.eq
import kotlin.io.path.Path
import kotlin.test.*

/**
 * This test suite tests the [OsloConfigPass] and its interaction with the
 * [IniFileConfigurationSourcePass] and [StevedoreDynamicLoadingPass].
 */
class OsloConfigPassTest {
    /**
     * This test verifies correct functioning of the [OsloConfigPass],
     * [IniFileConfigurationSourcePass] and [StevedoreDynamicLoadingPass] by analyzing the way
     * cinder access the barbican key manager API through castellan.
     *
     * It aims to include as little files as possible (and only specific files, not directories), to
     * keep it easily debuggable.
     */
    @Test
    fun testConfigAndLoadingMinimal() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<ProvideConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<StevedoreDynamicLoadingPass>()
                it.exclusionPatterns("tests")
                it.includePath("external/oslo.config")
                it.includePath("external/stevedore")
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

    /**
     * This test verifies correct functioning of the [OsloConfigPass] and
     * [IniFileConfigurationSourcePass] by analyzing the way cinder accesses the barbican key
     * manager API through castellan, but this time it uses the oslo.config configuration source.
     */
    @Test
    fun testOsloConfig() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<ProvideConfigPass>()
                it.exclusionPatterns("tests")
                it.includePath("external/oslo.config")
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

    /**
     * This test verifies that the [OsloConfigPass] correctly identifies that secure communication
     * is used to Barbican through the Castellan API.
     */
    @Test
    fun testSecureCommunication() {
        val topLevel = Path("external")
        val result =
            analyze(files = listOf(), topLevel = topLevel, usePasses = true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<SecureKeyRetrievalPass>()
                it.registerPass<StevedoreDynamicLoadingPass>()
                it.includePath("external/oslo.config")
                it.includePath("external/stevedore")
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
}
