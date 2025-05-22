package de.bund.bsi.catalgoue.logging

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.query.QueryTree


/*
Let this class be open to enable the evaluator to differentiate between different kind of logs and their expected destination
 */
open class LoggableEvent(un: Node?) : Concept(un)

/*
   A module of a system (possibly instantiated multiple times) that generates (security relevant) logs
*/
open class LogGenerator(un: Node?) : Concept(un){

    fun generate(event: LoggableEvent) : LogObject {
        TODO()
    }
}

/*
    An object containing multiple data fields to be logged
*/
open class LogObject(un: Node?) : Concept(un)

open class LogConsumer(un: Node?) : Concept(un)



/*
    Tags
*/
//LogObjects must be immutable



/*
    Queries
*/
// Log objects must be created by LogGenerators
// LogObjects must be consumed by LogConsumers
// Make sure that a LogObject actually contains the information that it is supposted to contain
// by making an "abstract" query to be completed by the definition of a TOE-specific lambda expression
abstract class LogQueries{

    fun query_LogObjectsContainSpecifiedInformation(tr: TranslationResult) : QueryTree<Boolean>  {

        var event : LoggableEvent
        event = TODO() //extract the event from the nodes flowing into a LogGenerator
        var logObject : LogObject //extract the LogObject from the nodes flowing out of a LogGenerator
        logObject = TODO()

        toeSpecific_EventContainedInLogObject(event, logObject)


        return TODO()
    }

    abstract fun toeSpecific_EventContainedInLogObject(event: LoggableEvent, logObject: LogObject) : Boolean

}

/*
In this class, we can instantiate LogQueries multiple times to address different types of logs (security, user-facing, informative,..., subsytems)
 */
class SpecificLogQueries{



}
