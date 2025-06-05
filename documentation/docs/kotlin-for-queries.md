
# Hints on Kotlin for Writing Sleek Queries

## Context receivers

The `requirement` block contains a `TranslationResult` in the object `this`.
Thus, within this block, the query can access the `TranslationResult` directly without having to pass it as a parameter (simply call `this.query()` or `query()`).
To allow this, there are two options: Extension functions (see below) and context receivers (described here).

Context receivers allow you to define a function which requires several context objects (which are passed there in different `this` objects).
To make use of this, simply write `context(Class)` before the function definition.
In the case of the queries, this could look like this:
```kotlin
context(TranslationResult)
fun goodCryptoFunc(): QueryTree<Boolean> {
    return allExtended<CallExpression> { it.name.localName eq "encryptSecurely" }
}
```

While this is mainly syntactic sugar for passing multiple parameters, it allows you to write more concise code and you can benefit from a nicer syntax highlighting in your IDE.

## Using extensions

To keep the actual query small, we recommend getting familiar with [Kotlin Extensions](https://kotlinlang.org/docs/extensions.html) which can be used to extend existing classes with new functionality without having to inherit from the class.
They can be used to add functions or properties.
This can be used to add project-specific functionality to the Codyze Evaluator and simply calling this function in the queries.
An example for an extension function could look like this:
```kotlin
fun CallExpression.isSecureEncryptionCall(): Boolean {
    return this.name.localName == "encryptSecurely"
}
```

## Handling of `null` values

Kotlin differentiates between `null` and non-null values. To work with nullable values, use the `?` syntax/operator and
implement checks using the `?.let` or `?:` operator rather than enforcing non-null values with `!!`. This ensures that
all your queries will be evaluated even in the presence of null-values whereas using `!!` would immediately crash the
execution. Keep in mind that the missing information in the check should likely result in a warning, which means you
probably want to generate a failing result in this case (e.g. by creating a `QueryTree(false, ...)`).

## Using variables

Some data are likely to change frequently. Rather than hardcoding this information in the queries, you can use a
variable. This makes it easier to update the information in subsequent usages of the same security statement or
objectives.

