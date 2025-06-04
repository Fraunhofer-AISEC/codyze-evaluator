/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.technology.openstack

/** Represents an OpenStack component. */
sealed class OpenStackComponent(var name: String)

/** Keystone is the OpenStack Identity service, which provides authentication and authorization. */
object Keystone : OpenStackComponent("keystone")

/** Nova is the OpenStack Compute service, which provides virtual machine management. */
object Nova : OpenStackComponent("nova")

/** Cinder is the OpenStack Block Storage service, which provides persistent block storage. */
object Cinder : OpenStackComponent("cinder")

/** Neutron is the OpenStack Networking service, which provides network connectivity. */
object Neutron : OpenStackComponent("neutron")

/**
 * Magnum is the OpenStack Container Infrastructure Management service, which provides container
 * orchestration.
 */
object Magnum : OpenStackComponent("magnum")

/**
 * Glance is the OpenStack Image service, which provides discovery, registration, and delivery
 * services for disk and server images.
 */
object Glance : OpenStackComponent("glance")

/**
 * Barbican is the OpenStack Key Manager service, which provides secure storage and management of
 * secrets.
 */
object Barbican : OpenStackComponent("barbican")

/**
 * Conf is a virtual component that represents the configuration files and settings used in
 * OpenStack services, typically managed by [OsloConfig] and stored in `/etc`.
 */
object Conf : OpenStackComponent("conf")

/** Represents a library that is part of the OpenStack ecosystem. */
sealed class OpenStackLibrary(name: String) : OpenStackComponent(name)

/**
 * Castellan is a wrapper API for accessing secret manager services (e.g., [Barbican]) in OpenStack.
 */
object Castellan : OpenStackLibrary("castellan")

/** Oslo Config is a library for configuration management in OpenStack services. */
object OsloConfig : OpenStackLibrary("oslo.config")

/** Oslo Policy is a library for policy management in OpenStack services. */
object OsloPolicy : OpenStackLibrary("oslo.policy")

/** Barbican Client is a Python library for interacting with the [Barbican] Key Manager service. */
object PythonBarbicanClient : OpenStackLibrary("python-barbicanclient")

/** Cinder Client is a Python library for interacting with the [Cinder] Block Storage service. */
object PythonCinderClient : OpenStackLibrary("python-cinderclient")

/** Keystone Auth is a library for authentication in OpenStack services. */
object KeystoneAuth : OpenStackLibrary("keystoneauth")

/** Keystone Middleware is a library for interacting with [Keystone]. */
object KeystoneMiddleware : OpenStackLibrary("keystonemiddleware")

/** SQLAlchemy is a SQL toolkit and Object-Relational Mapping (ORM) system for Python. */
object SqlAlchemy : OpenStackLibrary("sqlalchemy")
