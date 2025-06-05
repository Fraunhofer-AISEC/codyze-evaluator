# Assumptions Tradeoff

Modern TOEs can be highly complex systems, so that several assumptions need to be made in order to avoid a complexity overload.
The following examples will illustrate the tradeoffs assumptions present between a more precise analysis and a more usable analysis experience for the evaluator on the example TOE OpenStack.

## Scenario: Retrieving Encryption Key from Barbican

The scenario we are using in the following describes the way OpenStack handles retrieving an encryption key inside Cinder from a key manager, such as Barbican.
The following lines are responsible for doing so inside Cinder.

```python
# https://github.com/openstack/cinder/blob/stable/2024.2/cinder/volume/flows/manager/create_volume.py#L508-L509
# License: Apache 2.0
        keymgr = key_manager.API(CONF)
        key = keymgr.get(context, encryption['encryption_key_id'])
```

Through the documentation we can assume that this call ends up in Barbican at the end-point `/v1/secrets/{encryption_key_id}` -- if Barbican is configured as key manager, which is the default.

### Manual Analysis

However, this is a very strong assumption, and we want to challenge this assumption in real code to possibly reduce the weight of the assumption.
In the following, we will manually trace the contents of this call.
We also present the current automated implementation using our passes system in the chapter [Automated Analysis](#automated-analysis) below.

#### Enter Castellan

First, we discover that `key_manager.API` is not a call directly to Barbican, but instead another component is involved: Castellan.
Castellan is not a standalone service, but rather it is a library that proxies requests to a possible "key manager".
In the current (as of writing this document) release, two key managers are supported: Vault and Barbican.

```python
# https://github.com/openstack/castellan/blob/stable/2024.2/castellan/key_manager/__init__.py#L36-L45
# License: Apache 2.0
def API(configuration=None):
    conf = configuration or cfg.CONF
    conf.register_opts(key_manager_opts, group='key_manager')

    try:
        mgr = driver.DriverManager("castellan.drivers",
                                   conf.key_manager.backend,
                                   invoke_on_load=True,
                                   invoke_args=[conf])
        key_mgr = mgr.driver
```

The actual key manager used is derived from a configuration value `backend` in the group `key_manager`.
Important to note is that the configuration (file) from which is derived is also not static, but it depends on the configuration file used by the caller of the `API` function.
In our example case, this is Cinder and therefore the values are taken from `cinder.conf`.
In order to evaluate which configuration value is used, the inter-procedural DFG can be used.

#### Enter Stevedore

Once the config value has been evaluated, it is passed into the constructor of the `driver.DriverManager` class.
This class belongs to Stevedore, which is another library that allows OpenStack to dynamically invoke so-called "drivers" at runtime, depending on a configuration value.
The list of drivers are chosen from a list of [Entry Points](https://setuptools.pypa.io/en/latest/userguide/entry_point.html) -- in this case from `castellan.drivers`.
This list is part of the Castellan package, and it clearly shows the supported key manager classes.

```ini
# https://github.com/openstack/castellan/blob/stable/2024.2/setup.cfg#L37-L39
# License: Apache 2.0
castellan.drivers =
    barbican = castellan.key_manager.barbican_key_manager:BarbicanKeyManager
    vault = castellan.key_manager.vault_key_manager:VaultKeyManager
```

If we assume the following Cinder configuration:
```ini
# cinder.conf
[key_manager]
backend = barbican

[barbican]
verify_ssl = true
```

We can then proceed to analyse the `BarbicanKeyManager` class:

```python
# https://github.com/openstack/castellan/blob/stable/2024.2/castellan/key_manager/barbican_key_manager.py#L105-L112
# License: Apache 2.0
class BarbicanKeyManager(key_manager.KeyManager):
    """Key Manager Interface that wraps the Barbican client API."""

    def __init__(self, configuration):
        self._barbican_client = None
        self._base_url = None
        self.conf = configuration
        self.conf.register_opts(_barbican_opts, group=_BARBICAN_OPT_GROUP)
```

In the initialisation of this class, several new configuration options are defined (remember: in the caller's configuration, e.g., `cinder.conf`).
For example, the option to enable or disable TLS verification, we have observed in our `cinder.conf`:

```python
# https://github.com/openstack/castellan/blob/stable/2024.2/castellan/key_manager/barbican_key_manager.py#L64-L68
# License: Apache 2.0
    cfg.BoolOpt('verify_ssl',
                default=True,
                help='Specifies if insecure TLS (https) requests. If False, '
                     'the server\'s certificate will not be validated, if '
                     'True, we can set the verify_ssl_path config meanwhile.'),
```

#### Returning to Cinder

If we return to Cinder, we now know that the `keymgr` variable contains an instance of `castellan.key_manager.barbican_key_manager.BarbicanKeyManager`.
If we follow the call to `get` inside this class, we discover several calls in the Barbican client package, that finally assembles the GET request to `/v1/secrets/{encryption_key_id}`.

## Automated Analysis

Even though we did not show all the calls in detail, one can already see that the analysis of this request in detail puts a high strain on the evaluator, following several components and libraries.
Therefore, we need two things:

-  Concepts and passes need to be used to abstract certain operations in the code that are commonly found, e.g., loading a configuration
-  Necessary reasonable assumptions can be made about how certain (third-party) libraries work. This can for example be done manually and then taken as an assumption in the automated process.

In the current implementation, passes exist to extract the behavior of loading configuration values from files as well as dynamically instantiating objects from a list of entry points.
The following assumptions are currently made:

- We assume that Stevedore loads an entry from the Python entry points supplied by key/value and instantiates it. We do NOT analyze the `stevedore` package itself.
- We assume that the Barbican client follows the [HATEOAS](https://en.wikipedia.org/wiki/HATEOAS) pattern in order to construct URLs from class controllers and function names. We do NOT analyze the `barbicanclient` package itself.

Both assumptions were manually verified.