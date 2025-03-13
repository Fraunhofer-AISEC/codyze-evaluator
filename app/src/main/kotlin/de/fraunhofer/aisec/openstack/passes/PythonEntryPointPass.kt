/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.frontends.MultipleLanguages
import de.fraunhofer.aisec.cpg.frontends.python.JepSingleton
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.Name
import de.fraunhofer.aisec.cpg.graph.concepts.arch.Agnostic
import de.fraunhofer.aisec.cpg.graph.concepts.flows.LocalEntryPoint
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.RecordDeclaration
import de.fraunhofer.aisec.cpg.graph.parseName
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.ControlFlowSensitiveDFGPass
import de.fraunhofer.aisec.cpg.passes.EvaluationOrderGraphPass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import java.io.File

/**
 * An entry point into a Python module.
 *
 * Entry points are identified by a [group], a [name] and an [objectReference]. We're tracking them
 * to better match them at invocations.
 */
class PythonEntryPoint(
    underlyingNode: FunctionDeclaration,
    val group: String,
    val objectReference: String,
) :
    LocalEntryPoint(
        underlyingNode = underlyingNode,
        os = Agnostic(underlyingNode = underlyingNode),
    )

/** Pass to extract Python entry points from components. */
@DependsOn(ControlFlowSensitiveDFGPass::class)
@DependsOn(EvaluationOrderGraphPass::class)
class PythonEntryPointPass(ctx: TranslationContext) : ComponentPass(ctx) {

    /** Accept a [component] for further processing. */
    override fun accept(component: Component) {
        val pyLang =
            // ensure that we have Python code
            when (val lang = component.language) {
                is PythonLanguage -> lang
                is MultipleLanguages ->
                    lang.languages.filterIsInstance<PythonLanguage>().firstOrNull()
                else -> null
            }

        // process only components with Python code
        if (pyLang != null) {
            handle(component, pyLang)
        }
    }

    /**
     * Processes a [component] containing Python code for Python entry points.
     *
     * It's assumed that the [component] represents a Python project with packaging and distribution
     * files.
     */
    private fun handle(component: Component, pythonLanguage: PythonLanguage) {
        val componentRoot = component.topLevel
        if (componentRoot == null) {
            log.debug("Component {} does not have a root directory. Skipping ...", component)
            return
        }

        // currently parse only `setup.cfg`
        val setupCfg = componentRoot.resolve("setup.cfg")
        if (setupCfg.exists() && setupCfg.isFile && setupCfg.canRead()) {
            extractEntryPoints(setupCfg).forEach {
                val group = it.key
                val namedObjRefs =
                    it.value // Format: `name = object reference`, where object reference is
                // `importable.module:object.attr`

                namedObjRefs.forEach {
                    val (name, objRef) = it.split("=").map { it.trim() }
                    // CPG fq-names use dot `.`
                    val reference = objRef.replace(":", ".")

                    ctx.scopeManager
                        .lookupSymbolByName(pythonLanguage.parseName(reference), pythonLanguage)
                        .forEach { decl ->
                            val funDecl =
                                when (decl) {
                                    is RecordDeclaration ->
                                        decl.constructors.firstOrNull {
                                            it.name.localName == "__init__" || it.name == decl.name
                                        }
                                    is FunctionDeclaration -> decl
                                    else ->
                                        TODO(
                                            "Unhandled object reference for entry point: $objRef"
                                        ) // TODO: check OS packages of what else to expect
                                }

                            if (funDecl != null) {
                                component.incomingInteractions +=
                                    PythonEntryPoint(
                                            underlyingNode = funDecl,
                                            group = group,
                                            objectReference = objRef,
                                        )
                                        .also { it.name = Name(name) }
                            } else {
                                log.warn(
                                    "Couldn't find function declaration for entry point: {}",
                                    objRef,
                                )
                            }
                        }
                }
            }
        }
    }

    /**
     * Extracts entry points from Python packaging and configuration file [setupCfg].
     *
     * May work only with Setuptools `setup.cfg` configuration files.
     */
    private fun extractEntryPoints(setupCfg: File): Map<String, List<String>> {
        JepSingleton.getInterp().use {
            it.set("filename", setupCfg.absolutePath)

            it.exec("import configparser as cp")
            it.exec("config = cp.ConfigParser()")
            it.exec("config.read(filename)")
            it.exec(
                "entry_points = {group: named_objref.strip().splitlines() for group,named_objref in config['entry_points'].items()} if config.has_section('entry_points') else dict()"
            )

            @Suppress("UNCHECKED_CAST")
            return it.getValue("entry_points") as Map<String, List<String>>
        }
    }

    override fun cleanup() {
        // nothing to do
    }
}
