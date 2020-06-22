# Testing openssi-websdk

A mocha test suite is provided for integration testing as well as to document common self-sovereign identity steps.

## Configuration

1. To execute the tests, manually create agents for the following roles: holder, issuer, verifier.
2. Inside the `nodejs` directory, run `npm install` to install the packages required to run the tests.
3. Inside the `nodejs` directory, create a `.env` file with the following properties related to the agents you created.

```env
AGENCY_URL=
ADMIN_ID=
ADMIN_NAME=
ADMIN_PASSWORD=
ISSUER_AGENT_NAME=
HOLDER_AGENT_NAME=
VERIFIER_AGENT_NAME=
```

The `AGENCY_URL` can be obtained from the **General** page of your agent's UI or in your welcome email.  It will appear similar to `https://agency.ibmsecurity.verify-creds.com`.

The `ADMIN_ID`, `ADMIN_NAME` and `ADMIN_PASSWORD` variables need to be those values associated with your account agent, which is created when your account is created.  Click on the **Account** item from the dropdown available on your agency dashboard to retrieve this information.

Agent names and passwords can be seen on the **Add Device** -> **Manual Entry** panel in your agent's UI.

## Running

From the `nodejs` directory, execute `npm test`.

## Debugging

### Environment Variables

There are optional environment variables that can be helpful when trying to debug failures as you develop more testcases and can be added to your .env file.

* _LOG_LEVEL_: The typical string values that can be use when logging.  Listed in sdk.js.
* _PURGE_: Acceptable values are (true|false).  Setting PURGE to `true` will cleanup connections, credentials, and invitations from the test agents prior to a test run. 

### Attach a debugger

You may also choose to attach a Node debugger to debug a test run.  If you execute `npm run remote-debug` and run a Node debugger (like chrome://inspect in a Chrome browser window or VS Code) attached to the port mentioned in `package.json`, then the debugger should break when the testcases are loaded.  From there you can set break points in test.js to expedite debugging.