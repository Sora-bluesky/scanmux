[English](web-interface.md) | [日本語](web-interface.ja.md)

# Use the local Web interface

Use this guide to acquire a public GitHub repository, review its scope, scan it and download results in a browser.

## Supported repositories

The page accepts `https://github.com/owner/repository` and acquires its current HEAD.
Other hosts, private repositories, arbitrary refs, URL credentials and query strings are unsupported.
Tool and configuration paths cannot be changed from the browser.

## Start a local session

Start the server with trusted controller configuration.

```sh
node bin/scanmux.mjs serve --config /absolute/controller.json
```

Open the private session URL printed once by the command.
The server listens only on `127.0.0.1` at an available port.
The URL fragment holds a session credential.
The page moves it into session storage and removes it from the address bar.

Keep the terminal running. Ctrl+C requests cancellation and closes the server after owned work settles.
Refreshing the browser reconnects to the current job in that server process.
Restarting the server creates a new session without old jobs.

## Acquire a repository and review its scope

Enter the public GitHub URL, then choose **取得して範囲を確認** to acquire its current HEAD.
Acquisition uses trusted Git without credentials, checkout, hooks, redirects or submodules.
Review the fixed commit, exclusions and dependency inputs, then explicitly start the scan.
Only one job runs at a time.
Repeating execution of the same plan does not start another scan.

## Cancel a job

During acquisition, cancellation prevents further work and waits for the current Git command to exit naturally.
The existing preparation deadline still applies.
Scanning uses the existing process-tree cancellation mechanism.
The screen shows cancellation as pending until termination and output checks settle.

> Q. Why does the page refuse a replacement job after cancellation?
>
> A. If termination cannot be verified, the job slot is retained. The source copy is still removed, and it is kept only if removal fails. Confirm that owned processes stopped before removing data or restarting work.

## Save results

JSON download returns the secret-checked bytes saved in the private run directory.
After confirmed completion or cancellation, source objects and snapshots are removed.
Reports remain under the OS temporary directory in `scanmux-*` directories protected for the current user.

Download any result you need before starting another plan.
A download-start message does not mean the browser finished saving the file.

> Q. Are source data and job history recovered after a server or OS crash?
>
> A. Abnormal termination may leave source data in the temporary directory. There is no automatic crash cleanup or durable job history.

## Use an owner-private Site

Allow one exact origin, then use the local page's **Sitesで開く** button.

```sh
node bin/scanmux.mjs serve --config /absolute/controller.json --site-origin https://your-site.example
```

Only static UI assets are hosted.
Git acquisition, scans and results stay on the same PC.
Keep the PC and original local page open.

> Q. What if the browser denies local access or the API versions differ?
>
> A. Use the local page.

D1/R2 and external AI APIs are not required.
This is not a guarantee of free Sites hosting.

## Security

- Keep the session URL private and out of shared logs.
- The local page uses session storage for its session credential.
- The Sites token is not put in URLs or browser storage.
- Keep saved reports private.
- Do not remove retained source data or restart work until owned-process termination is confirmed.

## Related docs

- [Get started](getting-started.md)
- [Read, save and check results](results.md)
- [Urgent advisories](urgent-advisories.md)
- [ScanMux](../README.md)
