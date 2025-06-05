/*
 * This file is part of the OpenStack Checker
 */
package example

import de.fraunhofer.aisec.codyze.evaluateWithCodyze
import de.fraunhofer.aisec.codyze.profiles.openstack.OpenStackProfile

fun main() {
    val result = evaluateWithCodyze("project.codyze.kts", profile = OpenStackProfile)
}
