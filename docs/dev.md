Development
===========
This page contains information for developers about how to contribute to this project.


Requirements
------------

* Java 11
* Maven

Running tests and code quality checks
-------------------------------------

Inside the bagit-java root directory, run `mvn verify`.

General
-------

* When extending the library follow the established patterns, to keep it easy to understand for any
  new user.

JavaDoc
-------
Since this is a library, the JavaDocs should be relatively extensive, although there is no need to go overboard with this. At a minimum:

* The JavaDocs must be generated successfully. As of today this is a standard part of the build; the build will fail if doc generation fails.
* [Run the documentation site locally](https://dans-knaw.github.io/dans-datastation-architecture/dev/#documentation-with-mkdocs){:target=_blank} to check how it renders.

