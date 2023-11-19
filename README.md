# RetroPilot Fork Generator

| Branch | Installer URL |
| --- | --- |
| `master-ci` | `installer.comma.ai/dash-software-ltd/master-ci` |
| `release3` | `installer.comma.ai/dash-software-ltd/release3` |

<details>
  <summary>
    Show comma two branches:
  </summary>

  | Branch | Installer URL |
  | --- | --- |
  | `commatwo_master` | `installer.comma.ai/dash-software-ltd/commatwo_master` |
  | `release2` | `installer.comma.ai/dash-software-ltd/release2` |

</details>


This GitHub repository periodically continuously generates openpilot branches off of openpilot's `master-ci`, `release2` and `release3` branches with the API host set to `retropilot.app`.

https://dash-software-ltd.github.io/openpilot/

## FAQ

### How often are the branches generated?

Every day. If the base commits haven't changed, the generated commits have a stable hash and will not change.

### Custom Forks?

Please talk to the fork maintainer about adding an option to use the RetroPilot API server. Feel free to add a toggle to your own fork, however it is recommended to give users a choice between the comma and RetroPilot API servers.

### Why not dynamically generate the installer and inject the fingerprint?

Injecting the fingerprint with the installer may produce non-pushed commits and/or non-commited code that can only be found on the device itself. By producing these branches periodically with GitHub, the commit on the device will have a commit in GitHub that can be referenced if help is sought.
