const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const tls = require('tls');
const { spawn } = require('child_process');
const { chromium } = require(process.env.FLEETORY_PLAYWRIGHT_MODULE || 'playwright');

const lab = path.resolve(__dirname, '..', '..', 'work', 'security-lab');
const certs = path.join(lab, 'certs');
const repoRoot = path.resolve(__dirname, '..');
const redirectUri = 'http://127.0.0.1:4173/auth/callback';
const clientId = 'fleetory-admin-lab';

function newAuthorization(prompt) {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const url = new URL('http://localhost:8088/realms/fleetory/protocol/openid-connect/auth');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', 'openid');
  url.searchParams.set('code_challenge',
    crypto.createHash('sha256').update(verifier).digest('base64url'));
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', crypto.randomBytes(16).toString('hex'));
  if (prompt) url.searchParams.set('prompt', prompt);
  return { url, verifier };
}

async function exchangeCode(callback, authorization) {
  if (!callback || callback.searchParams.get('state') !== authorization.url.searchParams.get('state')) {
    throw new Error('OIDC authorization callback is invalid.');
  }
  const code = callback.searchParams.get('code');
  if (!code) throw new Error('OIDC authorization code is missing.');
  const response = await fetch('http://localhost:8088/realms/fleetory/protocol/openid-connect/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId,
      redirect_uri: redirectUri, code, code_verifier: authorization.verifier })
  });
  if (!response.ok) throw new Error(`OIDC token exchange failed: ${response.status}`);
  return (await response.json()).access_token;
}

function readClaims(token, personId) {
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.sub !== personId || claims.azp !== clientId ||
      !audiences.includes('fleetory-admin-api')) {
    throw new Error('OIDC token is not bound to the Admin identity and API.');
  }
  return claims;
}

async function enterPassword(page, password) {
  if (await page.locator('#username').isVisible()) {
    await page.locator('#username').fill('lab-admin-person');
  }
  if (await page.locator('#password').isVisible()) {
    await page.locator('#password').fill(password);
    await page.locator('#kc-login').click();
    await page.waitForLoadState('domcontentloaded');
  }
}

async function resetLabPasskey() {
  const envLine = fs.readFileSync(path.join(lab, 'lab.env'), 'utf8').split(/\r?\n/)
    .find(line => line.startsWith('FLEETORY_LAB_KEYCLOAK_ADMIN_PASSWORD='));
  if (!envLine) throw new Error('Lab admin credential missing.');
  const adminPassword = envLine.slice(envLine.indexOf('=') + 1);
  const tokenReply = await fetch('http://localhost:8088/realms/master/protocol/openid-connect/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli',
      username: 'lab-admin', password: adminPassword })
  });
  if (!tokenReply.ok) throw new Error('Lab admin authentication failed.');
  const adminToken = (await tokenReply.json()).access_token;
  const headers = { Authorization: `Bearer ${adminToken}` };
  const base = 'http://localhost:8088/admin/realms/fleetory/users';
  const users = await (await fetch(`${base}?username=lab-admin-person&exact=true`, { headers })).json();
  const user = users.find(entry => entry.username === 'lab-admin-person');
  if (!user) throw new Error('Lab OIDC user missing.');
  const credentials = await (await fetch(`${base}/${user.id}/credentials`, { headers })).json();
  for (const credential of credentials.filter(entry => entry.type.startsWith('webauthn'))) {
    const reply = await fetch(`${base}/${user.id}/credentials/${credential.id}`,
      { method: 'DELETE', headers });
    if (!reply.ok) throw new Error('Could not reset lab passkey.');
  }
  const update = await fetch(`${base}/${user.id}`, {
    method: 'PUT', headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requiredActions: ['webauthn-register'],
      firstName: 'Lab', lastName: 'Admin', email: 'lab-admin@localhost' })
  });
  if (!update.ok) throw new Error('Could not reset lab required action.');
}

(async () => {
  await resetLabPasskey();
  let callbackUrl = null;
  const callbackServer = http.createServer((req, res) => {
    const requestedUrl = new URL(req.url, 'http://127.0.0.1:4173');
    if (requestedUrl.pathname === '/auth/callback') callbackUrl = requestedUrl;
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Fleetory OIDC lab callback received.');
  });
  await new Promise(resolve => callbackServer.listen(4173, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({
      ...(process.env.FLEETORY_CHROME_PATH ? { executablePath: process.env.FLEETORY_CHROME_PATH } : {}),
      headless: true,
      args: ['--no-sandbox']
    });
    const context = await browser.newContext();
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2', transport: 'usb', hasResidentKey: true,
        hasUserVerification: true, isUserVerified: true,
        automaticPresenceSimulation: true
      }
    });
    const registration = newAuthorization();
    await page.goto(registration.url.toString(), { waitUntil: 'domcontentloaded' });
    const password = fs.readFileSync(path.join(certs, 'admin-user-password'), 'utf8').trim();
    await enterPassword(page, password);
    if (await page.locator('#registerWebAuthn').isVisible()) {
      await page.locator('#registerWebAuthn').click();
    }
    await page.waitForTimeout(1500);
    const personId = fs.readFileSync(path.join(certs, 'admin-person-id'), 'utf8').trim();
    const registrationClaims = readClaims(
      await exchangeCode(callbackUrl, registration), personId);
    if (registrationClaims.amr?.includes('webauthn')) {
      throw new Error('Passkey registration must not satisfy the WebAuthn login requirement.');
    }
    callbackUrl = null;
    const reauthentication = newAuthorization('login');
    await page.goto(reauthentication.url.toString(), { waitUntil: 'domcontentloaded' });
    await enterPassword(page, password);
    if (await page.locator('#authenticateWebAuthnButton').isVisible()) {
      await page.locator('#authenticateWebAuthnButton').click();
    }
    await page.waitForTimeout(1000);
    const webAuthnToken = await exchangeCode(callbackUrl, reauthentication);
    const secondClaims = readClaims(webAuthnToken, personId);
    if (!Array.isArray(secondClaims.amr) || !secondClaims.amr.includes('webauthn')) {
      throw new Error('Signed access token lacks WebAuthn AMR.');
    }
    const dotnet = process.platform === 'win32'
      ? 'C:/Program Files/dotnet/dotnet.exe'
      : '/usr/share/dotnet/dotnet';
    const server = spawn(dotnet, [path.join(repoRoot, 'src/Fleetory.Server/bin/Debug/net10.0/Fleetory.Server.dll'),
      '--environment=Development'], {
      cwd: repoRoot, windowsHide: true, stdio: 'ignore',
      env: { ...process.env,
        FLEETORY_Fleetory__Secrets__Provider: 'OpenBao',
        FLEETORY_Fleetory__Secrets__Address: 'http://127.0.0.1:8200/',
        FLEETORY_Fleetory__Secrets__TokenDirectory: lab,
        FLEETORY_Fleetory__Web__Port: '5088',
        FLEETORY_Fleetory__AdminGateway__Enabled: 'true',
        FLEETORY_Fleetory__AdminGateway__Port: '5444',
        FLEETORY_Fleetory__AdminGateway__Oidc__Enabled: 'true',
        FLEETORY_Fleetory__AdminGateway__Oidc__Authority: 'http://localhost:8088/realms/fleetory',
        FLEETORY_Fleetory__AdminGateway__Oidc__Audience: 'fleetory-admin-api',
        FLEETORY_Fleetory__AdminGateway__Oidc__ClientId: 'fleetory-admin-lab'
      }
    });
    try {
      let ready = false;
      for (let attempt = 0; attempt < 30; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 300));
        if (server.exitCode !== null) throw new Error('Fleetory Server exited.');
        try {
          const response = await fetch('http://127.0.0.1:5088/health/ready');
          if (response.status === 200) { ready = true; break; }
        } catch {}
      }
      if (!ready) throw new Error('Fleetory Server did not become ready.');
      let rootOnlyTrustValid = false;
      await new Promise((resolve, reject) => {
        const socket = tls.connect({ host: '127.0.0.1', port: 5444,
          key: fs.readFileSync(path.join(certs, 'admin-client.key')),
          cert: fs.readFileSync(path.join(certs, 'admin-client.crt'), 'utf8') +
            fs.readFileSync(path.join(certs, 'admin-intermediate.crt'), 'utf8'),
          ca: fs.readFileSync(path.join(certs, 'admin-root.crt')),
          rejectUnauthorized: false }, () => {
          let certificate = socket.getPeerCertificate(true);
          let count = 0;
          while (certificate && count < 5) {
            count++;
            if (certificate.issuerCertificate === certificate) break;
            certificate = certificate.issuerCertificate;
          }
          rootOnlyTrustValid = count >= 2 && socket.authorizationError === null;
          console.log('server TLS chain:', { count, authorizationError: socket.authorizationError });
          if (count < 2) {
            console.warn('Windows Kestrel did not send the intermediate CA; the request check supplies it explicitly.');
          }
          socket.end(); resolve();
        });
        socket.on('error', reject);
      });
      const agent = new https.Agent({
        key: fs.readFileSync(path.join(certs, 'admin-client.key')),
        cert: fs.readFileSync(path.join(certs, 'admin-client.crt'), 'utf8') +
          fs.readFileSync(path.join(certs, 'admin-intermediate.crt'), 'utf8'),
        ca: fs.readFileSync(path.join(certs, 'admin-root.crt'), 'utf8') +
          fs.readFileSync(path.join(certs, 'admin-intermediate.crt'), 'utf8')
      });
      const deviceId = fs.readFileSync(path.join(certs, 'agent-device-id'), 'utf8').trim();
      const requestPath = `/admin/devices/${deviceId}/certificates/${'0'.repeat(64)}/revoke`;
      const callAdmin = token => new Promise((resolve, reject) => {
        const request = https.request({ hostname: '127.0.0.1', port: 5444,
          path: requestPath, method: 'POST', agent,
          headers: token ? { Authorization: `Bearer ${token}` } : {} }, response => {
          response.resume(); response.on('end', () => resolve(response.statusCode));
        });
        request.on('error', reject);
        request.end();
      });
      const withoutToken = await callAdmin(null);
      const withToken = await callAdmin(webAuthnToken);
      console.log(`Admin mTLS: no token ${withoutToken}; WebAuthn token ${withToken}.`);
      if (withoutToken !== 401 || withToken !== 403) {
        throw new Error('Admin OIDC/RBAC boundary did not return 401 then 403.');
      }
      if (process.argv.includes('--require-server-chain') && !rootOnlyTrustValid) {
        throw new Error('Admin server did not present a chain trusted by the root CA alone.');
      }
    } finally { server.kill(); }
    console.log('OIDC PKCE and virtual WebAuthn lab check passed.');
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => callbackServer.close(resolve));
    await resetLabPasskey();
  }
})().catch(err => { console.error(err.message); process.exitCode = 1; });
