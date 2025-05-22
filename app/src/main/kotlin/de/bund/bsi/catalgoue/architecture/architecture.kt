


/**
 * The module that orchestrates self tests
 */
open class SelfTestModule()

/**
 * A module that participates in the self tests orchestrated by the SelfTestModule
 */
open class TestedModule()

/**
 * A port of a toe internal domain that potentially allows toe internal data (or user data) to leave the domain
 * Depending on the TOE design, this port might require additional protection. For example, if data is transported over an untrusted network, such a port must apply cryptographic mechanisms on the user data.
 */
open class ToeInternalPort()