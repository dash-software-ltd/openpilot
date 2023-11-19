# RetroPilot Fork Generator

## What's this?

This GitHub repository periodically generates openpilot branches from comma's openpilot with the API host set to `retropilot.app`.

https://dash-software-ltd.github.io/openpilot/

## Installer URLs

| Branch | Installer URL |
| --- | --- |
| `master-ci` | `installer.comma.ai/dash-software-ltd/master-ci` |
| `release3` | `installer.comma.ai/dash-software-ltd/release3` |

<details>
  <summary>
    Show comma two branches:
  </summary>
  <table>
    <thead>
      <tr>
        <th>Branch</th>
        <th>Installer URL</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>master-ci</td>
        <td>installer.comma.ai/dash-software-ltd/master-ci</td>
      </tr>
      <tr>
        <td>release2</td>
        <td>installer.comma.ai/dash-software-ltd/release2</td>
      </tr>
    </tbody>
  </table>
</details>

## FAQ

### How often are the branches generated?

Every day. If the base commits haven't changed, the generated commits have a stable hash and will not change.

### Custom Forks?

Please talk to the fork maintainer about adding an option to use the RetroPilot API server. Feel free to add a toggle to your own fork, however it is recommended to give users a choice between the comma and RetroPilot API servers.

### Why not dynamically generate the installer and inject the fingerprint?

Injecting the fingerprint with the installer may produce non-pushed commits and/or non-commited code that can only be found on the device itself. By producing these branches periodically with GitHub, the commit on the device will have a commit in GitHub that can be referenced if help is sought.
