/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze

import de.fraunhofer.aisec.codyze.profiles.openstack.OpenStackComponent
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import java.io.File
import java.nio.file.Path

/**
 * This utility function is used to set up the translation configuration for OpenStack components.
 * It allows specifying the top-level directory and the components that are used, with an additional
 * filter which paths should be included for each component (relative to the components' directory).
 *
 * It expects that the components are placed in the [topLevel] folder in a directory that matches
 * the component's [OpenStackComponent.name].
 */
fun TranslationConfiguration.Builder.useComponents(
    topLevel: Path,
    vararg components: Pair<OpenStackComponent, List<String>>,
) {
    // Build top-level based on the provided components' name
    val topLevels =
        components.associate { Pair(it.first.name, topLevel.resolve(it.first.name).toFile()) }
    this.topLevels(topLevels)

    // Build software components based on the provided components' paths
    val softwareComponents = mutableMapOf<String, List<File>>()
    components.forEach { (component, paths) ->
        softwareComponents[component.name] =
            paths.map { topLevel.resolve(component.name).resolve(it).toFile() }
    }
    this.softwareComponents(softwareComponents)
}
