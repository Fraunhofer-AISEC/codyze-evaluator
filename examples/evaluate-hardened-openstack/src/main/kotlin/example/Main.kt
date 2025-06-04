/*
 * This file is part of the OpenStack Checker
 */
package example

import de.fraunhofer.aisec.codyze.technology.openstack.OpenStackProfile
import de.fraunhofer.aisec.openstack.evaluateWithCodyze

fun main() {
    val result = evaluateWithCodyze("project.codyze.kts", profile = OpenStackProfile)
    println(result)
}
