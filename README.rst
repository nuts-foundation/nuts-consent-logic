Nuts Consent Logic Service
##################

.. image:: https://circleci.com/gh/nuts-foundation/nuts-consent-logic.svg?style=svg
    :target: https://circleci.com/gh/nuts-foundation/nuts-consent-logic
    :alt: Build Status

.. image:: https://codecov.io/gh/nuts-foundation/nuts-proxy/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/nuts-foundation/nuts-consent-logic
    :alt: Test coverage

.. image:: https://godoc.org/github.com/nuts-foundation/nuts-consent-logic?status.svg
    :target: https://godoc.org/github.com/nuts-foundation/nuts-consent-logic
    :alt: GoDoc

.. image:: https://api.codeclimate.com/v1/badges/a96e5a12e2fcc618a525/maintainability
   :target: https://codeclimate.com/github/nuts-foundation/nuts-consent-logic/maintainability
   :alt: Maintainability

This module is written in Go and should be part of nuts-go as an engine.

Running tests
*************

Tests can be run by executing

.. code-block:: shell

    go test ./...

Generating code
***************

.. code-block:: shell

    oapi-codegen -generate server,types -package api docs/_static/nuts-consent-logic.yaml > api/generated.go


Building
********

This project is part of https://github.com/nuts-foundation/nuts-go. If you do however would like a binary, just use ``go build``.

README
******

The readme is auto-generated from a template and uses the documentation to fill in the blanks.

.. code-block:: shell

    ./generate_readme.sh

This script uses ``rst_include`` which is installed as part of the dependencies for generating the documentation.

Documentation
*************

To generate the documentation, you'll need python3, sphinx and a bunch of other stuff. See :ref:`nuts-documentation-development-documentation`
The documentation can be build by running

.. code-block:: shell

    /docs $ make html

The resulting html will be available from ``docs/_build/html/index.html``

