.. _contribution-guide:

Contributing
============

.. image:: https://cdn-images-1.medium.com/max/800/1*J31AEMsTP6o_E5QOohn0Hw.png
    :target: https://cdn-images-1.medium.com/max/800/1*J31AEMsTP6o_E5QOohn0Hw.png

Development Installation
------------------------

Additional dependencies and setup steps are required to perform a "developer installation".
You do not need to perform these steps unless you intend to contribute a code or documentation change to
the nucypher codebase.

Before continuing, ensure you have ``git`` installed (\ `Git Documentation <https://git-scm.com/doc>`_\ ).

.. _acquire_codebase:

Acquire NuCypher Codebase
^^^^^^^^^^^^^^^^^^^^^^^^^

.. _`NuCypher GitHub`: https://github.com/nucypher/nucypher

In order to contribute new code or documentation changes, you will need a local copy
of the source code which is located on the `NuCypher GitHub`_.

.. note::

   NuCypher uses ``git`` for version control. Be sure you have it installed.

Here is the recommended procedure for acquiring the code in preparation for
contributing proposed changes:


1. Use GitHub to fork the ``nucypher/nucypher`` repository

2. Clone your fork's repository to your local machine

.. code-block:: bash

   $ git clone https://github.com/<YOUR-GITHUB-USERNAME>/nucypher.git

3. Change directory to ``nucypher``

.. code-block:: bash

   $ cd nucypher

4. Add ``nucypher/nucypher`` as an upstream remote

.. code-block:: bash

   $ git remote add upstream https://github.com/nucypher/nucypher.git

5. Update your remote tracking branches

.. code-block:: bash

   $ git remote update


Ensure Rust is Installed
^^^^^^^^^^^^^^^^^^^^^^^^^

Instruction for installing Rust can be found (\ `here <https://rustup.rs/>`_\ ).

After acquiring a local copy of the application code and installing rust, you will need to
install the project dependencies, we recommend using either ``pip`` or ``pipenv``.


Pip Development Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Alternately, you can install the development dependencies with pip:

.. code-block:: bash

    $ pip3 install -e .[dev]


Running the Tests
-----------------

.. note::

  A development installation including the solidity compiler is required to run the tests


.. _Pytest Documentation: https://docs.pytest.org/en/latest/

There are several test implementations in ``nucypher``, however, the vast majority
of test are written for execution with ``pytest``.
For more details see the `Pytest Documentation`_.

To run the tests, use the following commands:

.. code:: bash

  (nucypher)$ pytest -s tests/unit
  (nucypher)$ pytest -s tests/integration

Optionally, to run the full, slow, verbose test suite run:

.. code:: bash

  (nucypher)$ pytest

Setup Commit & Push Hooks
--------------------------

`Pre-commit <https://pre-commit.com/>`_ and pre-push are used for quality control to identify and prevent the inclusion of problematic code changes. They may prevent a commit that will fail
if passed along to CI servers or make small formatting changes directly to source code files.

If it's not already installed in your virtual environment, install pre-commit:

.. code:: bash

  (nucypher)$ pip install pre-commit

To enable pre-commit checks:

.. code:: bash

  (nucypher)$ pre-commit install

To enable pre-push checks:

.. code:: bash

  (nucypher)$ pre-commit install -t pre-push

For convenience, here is a one-liner to enable both:

.. code:: bash

  (nucypher)$ pre-commit install && pre-commit install -t pre-push


GitHub Actions CI Guide
-----------------------

As part of our CI/CD process, we use GitHub Actions to automate testing and linting on all pull requests. After you submit a PR, you can check the status of the GitHub Actions runs in the "Checks" tab of your pull request page.

If you encounter a CI failure, here's what you can do:

1. Click on the "Details" link next to the failed step to view the logs.
2. Look for the error messages and identify the test case or linting rule that failed.
3. Make the necessary changes to your code to fix the issues.
4. Commit and push your changes. GitHub Actions will automatically re-run the tests on your updated PR.

Before submitting your PR, it's a good practice to run linting and tests locally to reduce the likelihood of CI failures. This not only saves time but also streamlines the review process. To run linting and tests locally, you can use the following commands:

.. code-block:: bash

  (nucypher)$ flake8 nucypher/
  (nucypher)$ pytest -s tests/unit
  (nucypher)$ pytest -s tests/integration


Making a Commit
---------------

NuCypher takes pride in its commit history.

When making a commit that you intend to contribute, keep your commit descriptive and succinct.
Commit messages are best written in full sentences that make an attempt to accurately
describe what effect the changeset represents in the simplest form.  (It takes practice!)

Imagine you are the one reviewing the code, commit-by-commit as a means of understanding
the thinking behind the PRs history. Does your commit history tell an honest and accurate story?

We understand that different code authors have different development preferences, and others
are first-time contributors to open source, so feel free to join our `Discord <https://discord.gg/7rmXa3S>`_ and let us know
how we can best support the submission of your proposed changes.


Opening a Pull Request
----------------------

When considering including commits as part of a pull request into ``nucypher/nucypher``,
we *highly* recommend opening the pull request early, before it is finished with
the mark "[WIP]" prepended to the title.  We understand PRs marked "WIP" to be subject to change,
history rewrites, and CI failures. Generally we will not review a WIP PR until the "[WIP]" marker
has been removed from the PR title, however, this does give other contributors an opportunity
to provide early feedback and assists in facilitating an iterative contribution process.


Pull Request Conflicts
----------------------

As an effort to preserve authorship and a cohesive commit history, we prefer if proposed contributions
are rebased over ``main`` (or appropriate branch) when a merge conflict arises,
instead of making a merge commit back into the contributors fork.

Generally speaking the preferred process of doing so is with an `interactive rebase`:

.. important::

   Be certain you do not have uncommitted changes before continuing.

1. Update your remote tracking branches

.. code-block:: bash

   $ git remote update
   ...  (some upstream changes are reported)

2. Initiate an interactive rebase over ``nucypher/nucypher@main``

.. note::

   This example specifies the remote name ``upstream`` for the NuCypher organizational repository as
   used in the `Acquire NuCypher Codebase`_ section.

.. code-block:: bash

   $ git rebase -i upstream/main
   ...  (edit & save rebase TODO list)

3. Resolve Conflicts

.. code-block:: bash

   $ git status
   ... (resolve local conflict)
   $ git add path/to/resolved/conflict/file.py
   $ git rebase --continue
   ... ( repeat as needed )


4. Push Rebased History

After resolving all conflicts, you will need to force push to your fork's repository, since the commits
are rewritten.

.. warning::

   Force pushing will override any changes on the remote you push to, proceed with caution.

.. code-block:: bash

   $ git push origin my-branch -f


Building Docker
---------------

Docker builds are automated as part of the publication workflow and pushed to docker cloud.
However you may want to build a local version of docker for development.

We provide both a ``docker-compose.yml`` and a ``Dockerfile`` which can be used as follows:

*Docker Compose:*

.. code:: bash

  (nucypher)$ docker-compose -f deploy/docker/docker-compose.yml build .


Release Cycle
-------------

Versioning
^^^^^^^^^^

The versioning scheme used is inspired by `semantic versioning 2.0 <https://semver.org/>`_, but adds development stage and release candidate tags. The basic idea:

- MAJOR version when you make incompatible API changes
- MINOR version when you add functionality in a backwards compatible manner
- PATCH version when you make backwards compatible bug fixes

Two additional tags are used: ``-dev`` and ``-rc.x`` (i.e. ``v1.2.3-dev`` or ``v4.5.6-rc.0``)

Upstream Branches
^^^^^^^^^^^^^^^^^

- ``main`` is the stable and released version published to PyPI and docker cloud (``v6.0.0``).
- ``development`` is the default upstream base branch containing new changes ahead of ``main`` and tagged with ``-dev`` (``v6.1.0-dev``).

Major/Minor Release Cycle
^^^^^^^^^^^^^^^^^^^^^^^^^

- New pull requests are made into ``development``.
- When a commit from ``development`` is selected as a release candidate the version tag is changed from ``-dev`` to ``rc.0`` (``v6.1.0-rc.0``).  Selecting a release candidate implies a feature freeze.
- The release candidate is deployed to beta testers, staging, and testnet environments for QA.
- If the candidate is suitable, it is tagged, merged into ``main``, and published:
    - All version tags are removed (``v6.1.0-dev`` -> ``v6.1.0``)
    - A new upstream git version tag is pushed (triggering publication on CI) (``v6.1.0``)
    - ``development`` is merged into ``main``
- `development` version is bumped and the `-dev` tag is appended (``v6.2.0-dev`` or ``v7.0.0-dev``)

Release Blockers
^^^^^^^^^^^^^^^^

Sometimes changes are needed to fix a release blocker after a release candidate has already been selected. Normally the best course of action is to open a pull request into ``development``.

- Merge the pull request into ``development``
- Bump the release candidate's development number (``v7.0.0-rc.0`` -> ``v7.0.0-rc.1``)
- Redeploy beta testing environments, experimental nodes, staging, testnets, etc.
- Rinse & repeat until a suitable release candidate is found.

In the event that a release blocker's fix introduces unexpected backwards incompatibility during a minor release, bump the major version instead skipping directly to ``-rc.0``.

Patches (bugfixes, security patches, "hotfixes")
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sometimes urgent changes need to be made outside of a planned minor or major release.  If the required changes are backwards compatible open a pull request into ``main``.  Once the changes are reviewed and merged, ``development`` must be rebased over ``main``

- Pull request is merged into ``main``
- The version's patch number is bumped (``v6.1.0`` -> ``v6.1.1``)
- A new upstream tag is pushed, triggering the publication build on CI (``v6.1.1``)
- ``development`` is rebased over ``main``, amending the existing bumpversion commit with the new patch (this will be a merge conflict).
- Rinse & repeat


Release Automation
--------------------

.. note::

  This process uses ``towncrier`` and ``bumpversion``, which can be installed by running ``pip install -e .[deploy]`` or ``pip install towncrier bumpversion``.
  Also note that it requires you have git commit signing properly configured.

.. important::

   Ensure your local tree is based on ``main`` and has no uncommitted changes.

1. Decide what part of the version to bump.
The version string follows the format ``{major}.{minor}.{patch}-{stage}.{devnum}``,
so the options are ``major``, ``minor``, ``patch``, ``stage``, or ``devnum``.
We usually issue new releases increasing the ``patch`` version.

2. Use the ``make release`` script, specifying the version increment with the ``bump`` parameter.
For example, for a new ``patch`` release, we would do:

.. code:: bash

  (nucypher)$ make release bump=patch

3. The previous step triggers the publication webhooks.
Monitor the triggered deployment build for manual approval.
