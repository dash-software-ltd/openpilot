#!/usr/bin/env python3

import ast
import datetime
import logging
import markdown
import os
import pprint
import shutil

logging.basicConfig(level=logging.INFO, format="%(message)s")


API_HOST = "https://api.retropilot.app"
ATHENA_HOST = "wss://ws.retropilot.app"
MAPS_HOST = "https://maps.retropilot.app"


def append(path: str, content: str, end_of_line="\n"):
    with open(path, "a") as f:
        f.write(content + end_of_line)


def replace(path: str, old: str, new: str):
    with open(path) as f:
        content = f.read()

    content = content.replace(old, new)

    with open(path, "w") as f:
        f.write(content)


def delete(path: str):
    shutil.rmtree(path)


def patch_assignment(path: str, variable_name: str, value: str):
    with open(path) as f:
        content = f.read()

    tree = ast.parse(content)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == variable_name:
                    node.value = ast.parse(value).body[0].value

    with open(path, "w") as f:
        f.write(ast.unparse(tree))


def patch_retropilot_api() -> str:
    append("launch_env.sh", f"export API_HOST=\"{API_HOST}\"")
    append("launch_env.sh", f"export ATHENA_HOST=\"{ATHENA_HOST}\"")
    return "Use RetroPilot API"


def patch_max_time_offroad() -> str:
    replace("selfdrive/thermald/power_monitoring.py", "MAX_TIME_OFFROAD_S = 3*3600", "MAX_TIME_OFFROAD_S = 3*3600")
    return "Change MAX_TIME_OFFROAD_S to 3 hours"


def patch_mapbox_api():
    # NOTE: openpilot doesn't support this as an environment variable, only setting the token directly
    replace("selfdrive/navd/navd.py", "https://maps.comma.ai", MAPS_HOST)
    return "Use custom Mapbox host"


def patch_fix_ford() -> str:
    patch_assignment("selfdrive/car/nissan/values.py", "FW_QUERY_CONFIG", "FwQueryConfig(requests=[])")
    return "Fix Ford fingerprinting by removing Nissan fingerprinting"


BRANCHES = [
    # local branch, remote branch, patches
    ("master-ci", "master-ci", [patch_retropilot_api, patch_mapbox_api]),
    ("release3", "release3", [patch_retropilot_api, patch_mapbox_api]),
    ("release2", "release2", [patch_retropilot_api]),
    ("master-ci-3h", "master-ci", [patch_retropilot_api, patch_mapbox_api, patch_max_time_offroad]),
    ("incognitojam", "master-ci", [patch_retropilot_api, patch_mapbox_api, patch_max_time_offroad, patch_fix_ford]),
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
