
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept

//Some generic properties of variables and functions

open class ImmutableObject(un: Node?) : Concept(un)
open class InjectiveFunction(un: Node?) : Concept(un)
