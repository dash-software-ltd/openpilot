#!/usr/bin/env python3

import ast
import datetime
import logging
import os
import pprint
import markdown

logging.basicConfig(level=logging.INFO, format="%(message)s")


API_HOST = "https://retropilot.app"
ATHENA_HOST = "wss://athena.retropilot.app"

BRANCHES = ["master-ci", "release3", "release2"]


def prepare_op_repo():
    """
    Prepare the openpilot repo
    """
    logging.info("Setting up openpilot repo.")

    os.system("git remote add commaai https://github.com/commaai/openpilot.git")

    logging.info("Done setting up openpilot repo.")


def generate_branch(branch_name):
    """
    Make a new branch using the RetroPilot API
    """

    logging.info("Generating branch %s", branch_name)

    # Make sure branch is clean
    os.system(f"git fetch commaai {branch_name}")
    os.system(f"git checkout -B {branch_name} FETCH_HEAD")

    # Get date of current commit
    commit_date = os.popen("git log -1 --format=%cd --date=iso-strict").read()
    author_date = os.popen("git log -1 --format=%ad --date=iso-strict").read()

    # Customise launch_env.sh
    os.system(f"echo 'export API_HOST=\"{API_HOST}\"' >> launch_env.sh")
    os.system(f"echo 'export ATHENA_HOST=\"{API_HOST}\"' >> launch_env.sh")

    # Commit the changes
    os.system("git add -A")
    os.system(f"GIT_AUTHOR_DATE='{author_date}' GIT_COMMITTER_DATE='{commit_date}' git commit -m 'Use RetroPilot API'")

    return branch_name


def generate_html(branches):
    # Restore docs branch
    os.system("git checkout --force docs")

    # Generate a date for the page
    now = datetime.datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    header = """
<html>
<head>
<title>RetroPilot Fork Generator</title>
<style>
body {
    font-family: sans-serif;
}
code {
    background: lightgray;
    border-radius: 4px;
    padding: 2px;
}
</style>
</head>
<body>
"""

    with open("README.md") as f:
        header += markdown.markdown(f.read())
        header += "\n"

    body = "<hr><h2>Branches</h2>\n"
    for branch in branches:
        body += f"<h3>{branch}</h3>"
        body += f"<ul>"
        body += f"<li>Custom Software URL: <code>installer.comma.ai/dash-software-ltd/{branch}</code></li>"
        body += f'<li><a href="https://github.com/dash-software-ltd/openpilot/tree/{branch}">View on GitHub</a></li>'
        body += f"</ul>\n"

    footer = f"""<hr>
<p>
This page was generated at {now_str}.
</p>
</body>
</html>
"""
    # Make pages directory if it doesn't exist
    os.system("mkdir -p pages")
    with open("pages/index.html", "w") as f:
        f.write(header + body + footer)


def main(push=True):
    prepare_op_repo()

    logging.info("branches:")
    logging.info(pprint.pformat(BRANCHES))

    # Generate branches
    for branch in BRANCHES:
        generate_branch(branch)

    # Generate HTML output
    generate_html(BRANCHES)

    if push:
        # Push branches
        logging.info("Pushing branches to origin")
        for branch in BRANCHES:
            os.system(f"git fetch origin {branch}")
            os.system(f"git push --no-verify --force --set-upstream origin {branch}")


if __name__ == "__main__":
    # Check if args has dry run, if so, don't push
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--no-dry-run":
        main()
    else:
        main(push=False)
