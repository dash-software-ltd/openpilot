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


def patch_retropilot_api():
    os.system(f"echo 'export API_HOST=\"{API_HOST}\"' >> launch_env.sh")
    os.system(f"echo 'export ATHENA_HOST=\"{API_HOST}\"' >> launch_env.sh")
    return "Use RetroPilot API"


def patch_max_time_offroad():
    os.system(f"sed -i 's/MAX_TIME_OFFROAD_S = 30*3600/MAX_TIME_OFFROAD_S = 3*3600/g' selfdrive/thermald/power_monitoring.py")
    return "Change MAX_TIME_OFFROAD_S to 3 hours"


BRANCHES = [
    # local branch, remote branch, patches
    ("master-ci", "master-ci", [patch_retropilot_api]),
    ("release3", "release3", [patch_retropilot_api]),
    ("release2", "release2", [patch_retropilot_api]),
    ("master-ci-3h", "master-ci", [patch_retropilot_api, patch_max_time_offroad]),
]


def prepare_op_repo():
    """
    Prepare the openpilot repo
    """
    logging.info("Setting up openpilot repo.")

    os.system("git remote add commaai https://github.com/commaai/openpilot.git")

    logging.info("Done setting up openpilot repo.")


def generate_branch(local, remote, patches):
    """
    Make a new branch from remote with patches applied
    """

    logging.info("Generating branch %s", local)

    # Make sure branch is clean
    os.system(f"git fetch commaai {remote}")
    os.system(f"git checkout -B {local} FETCH_HEAD")

    # Get date of current commit
    commit_date = os.popen("git log -1 --format=%cd --date=iso-strict").read()
    author_date = os.popen("git log -1 --format=%ad --date=iso-strict").read()

    # Apply patches to the branch
    for patch in patches:
        message = patch()

        # Commit the patch
        os.system("git add -A")
        os.system(f"GIT_AUTHOR_DATE='{author_date}' GIT_COMMITTER_DATE='{commit_date}' git commit -m '{message}'")


def generate_html(branch_names):
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
    for branch in branch_names:
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

    branch_names = [branch[0] for branch in BRANCHES]

    logging.info("branches:")
    logging.info(pprint.pformat(branch_names))

    # Generate branches
    for local, remote, patches in BRANCHES:
        generate_branch(local, remote, patches)

    # Generate HTML output
    generate_html(branch_names)

    if push:
        # Push branches
        logging.info("Pushing branches to origin")
        for branch in branch_names:
            os.system(f"git fetch origin {branch}")
            os.system(f"git push --no-verify --force --set-upstream origin {branch}")


if __name__ == "__main__":
    # Check if args has dry run, if so, don't push
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--no-dry-run":
        main()
    else:
        main(push=False)
