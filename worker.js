// VLESS Protocol Implementation
// Based on: https://github.com/FoolVPN-ID/Nautica
// Enhanced with KV storage and Web UI

import { connect } from 'cloudflare:sockets';

let userID = '';
let proxyIP = '';

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get('Upgrade');

      // Set userID from environment or use default
      userID = env.UUID || '550e8400-e29b-41d4-a716-446655440000';
      proxyIP = env.PROXYIP || '';

      // WebSocket VLESS handler
      if (upgradeHeader === 'websocket') {
        return await vlessOverWSHandler(request, env);
      }

      // API Routes
      if (url.pathname === '/api/accounts') {
        return handleGetAccounts(env);
      }

      if (url.pathname === '/api/create') {
        return handleCreateAccount(request, env);
      }

      if (url.pathname === '/api/delete') {
        return handleDeleteAccount(request, env);
      }

      // Serve Web UI
      return new Response(getIndexHTML(), {
        headers: { 'Content-Type': 'text/html;charset=utf-8' }
      });

    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  }
};

// ============================================
// VLESS over WebSocket Handler
// ============================================
async function vlessOverWSHandler(request, env) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let addressLog = '';
  let portLog = '';
  let currentVlessVersion = new Uint8Array([0, 0]);
  
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || '');
  };

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWapper = {
    value: null,
  };

  let udpStreamWrite = null;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (udpStreamWrite) {
        const resp = await udpStreamWrite(chunk);
        if (resp) {
          return resp;
        }
      }

      if (remoteSocketWapper.value) {
        const writer = remoteSocketWapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const {
        hasError,
        message,
        addressRemote = '',
        portRemote = 80,
        rawDataIndex,
        vlessVersion = currentVlessVersion,
        isUDP,
      } = processVlessHeader(chunk, userID, env);

      addressLog = addressRemote;
      portLog = `${portRemote}`;
      currentVlessVersion = vlessVersion;

      if (hasError) {
        throw new Error(message);
      }

      if (isUDP) {
        if (portRemote === 53) {
          throw new Error('UDP DNS not supported');
        }
        return;
      }

      // Handle TCP
      handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawDataIndex, chunk, webSocket, log);
    },
    close() {
      log(`readableWebSocketStream closed`);
    },
    abort(reason) {
      log(`readableWebSocketStream aborted`, reason);
    },
  })).catch((err) => {
    log('readableWebSocketStream pipeTo error', err);
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

// ============================================
// Process VLESS Header
// ============================================
function processVlessHeader(vlessBuffer, userID, env) {
  if (vlessBuffer.byteLength < 24) {
    return {
      hasError: true,
      message: 'invalid data',
    };
  }

  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;

  if (stringify(new Uint8Array(vlessBuffer.slice(1, 17))) === userID) {
    isValidUser = true;
  }

  // Validate UUID from KV if available
  if (env.VLESS_KV) {
    const uuidFromBuffer = stringify(new Uint8Array(vlessBuffer.slice(1, 17)));
    validateUUIDFromKV(uuidFromBuffer, env).then(valid => {
      if (valid) isValidUser = true;
    });
  }

  if (!isValidUser) {
    return {
      hasError: true,
      message: 'invalid user',
    };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  if (command === 1) {
    // TCP
  } else if (command === 2) {
    // UDP
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} not supported`,
    };
  }

  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
    case 2:
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(':');
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType: ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: 'addressValue is empty',
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

// ============================================
// Handle TCP Outbound
// ============================================
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });

    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);

    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();

    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
    tcpSocket.closed.catch((error) => {
      console.log('retry tcpSocket closed error', error);
    }).finally(() => {
      safeCloseWebSocket(webSocket);
    });
    remoteSocketToWS(tcpSocket, webSocket, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

// ============================================
// Pipe Remote Socket to WebSocket
// ============================================
async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
  let hasIncomingData = false;

  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error('webSocket connection is not open');
          }
          webSocket.send(chunk);
        },
        close() {
          log(`remoteSocket.readable closed`);
        },
        abort(reason) {
          console.error('remoteSocket.readable abort', reason);
        },
      })
    )
    .catch((error) => {
      console.error('remoteSocketToWS error', error);
    });

  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

// ============================================
// Make Readable WebSocket Stream
// ============================================
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;

  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        const message = event.data;
        controller.enqueue(message);
      });

      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });

      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer error');
        controller.error(err);
      });

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(controller) {},
    cancel(reason) {
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

// ============================================
// Helper Functions
// ============================================
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error', error);
  }
}

function stringify(arr) {
  return arr.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = (4 - (base64Str.length % 4)) % 4;
    base64Str += '='.repeat(padding);
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

async function validateUUIDFromKV(uuid, env) {
  try {
    const account = await env.VLESS_KV.get(uuid);
    return account !== null;
  } catch (error) {
    console.error('UUID validation error:', error);
    return false;
  }
}

// ============================================
// API Handlers
// ============================================
async function handleGetAccounts(env) {
  try {
    if (!env.VLESS_KV) {
      return jsonResponse({ accounts: [] });
    }

    const list = await env.VLESS_KV.list();
    const accounts = [];

    for (const key of list.keys) {
      const data = await env.VLESS_KV.get(key.name);
      if (data) accounts.push(JSON.parse(data));
    }

    return jsonResponse({ accounts });
  } catch (error) {
    return jsonResponse({ error: error.message }, 500);
  }
}

async function handleCreateAccount(request, env) {
  try {
    const data = await request.json();
    const account = {
      uuid: data.uuid,
      server: data.server,
      port: data.port,
      path: data.path,
      wsHost: data.wsHost,
      sni: data.sni,
      security: data.security || 'tls',
      created: new Date().toISOString(),
    };

    if (env.VLESS_KV) {
      await env.VLESS_KV.put(account.uuid, JSON.stringify(account));
    }

    return jsonResponse({ success: true, account });
  } catch (error) {
    return jsonResponse({ success: false, error: error.message }, 500);
  }
}

async function handleDeleteAccount(request, env) {
  try {
    const { uuid } = await request.json();
    if (env.VLESS_KV) {
      await env.VLESS_KV.delete(uuid);
    }
    return jsonResponse({ success: true });
  } catch (error) {
    return jsonResponse({ success: false, error: error.message }, 500);
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

// ============================================
// HTML Interface
// ============================================
function getIndexHTML() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VLESS VPN Generator</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 min-h-screen">
  <div id="app"></div>
  
  <script type="module">
    const { signal, effect } = await import('https://cdn.jsdelivr.net/npm/@preact/signals-core@1.5.1/+esm');
    
    const config = signal({
      server: location.hostname,
      port: '443',
      path: '/',
      wsHost: location.hostname,
      sni: '',
      security: 'tls'
    });
    
    const accounts = signal([]);
    const result = signal(null);
    const status = signal('');
    const copied = signal('');

    async function loadAccounts() {
      try {
        const res = await fetch('/api/accounts');
        const data = await res.json();
        accounts.value = data.accounts || [];
      } catch (e) {
        console.error(e);
      }
    }

    function genUUID() {
      return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
      });
    }

    async function createAccount() {
      const cfg = config.value;
      if (!cfg.server || !cfg.sni) {
        status.value = 'error';
        setTimeout(() => status.value = '', 3000);
        return;
      }

      status.value = 'loading';

      try {
        const uuid = genUUID();
        const payload = {
          uuid,
          server: cfg.server,
          port: cfg.port,
          path: cfg.path,
          wsHost: cfg.wsHost,
          sni: cfg.sni,
          security: cfg.security
        };

        const res = await fetch('/api/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        if (res.ok) {
          const vlessLink = \`vless://\${uuid}@\${cfg.server}:\${cfg.port}?type=ws&security=\${cfg.security}&path=\${encodeURIComponent(cfg.path)}&host=\${cfg.wsHost}&sni=\${cfg.sni}&alpn=h2,http/1.1&fp=chrome#VLESS-\${Date.now()}\`;
          
          result.value = { ...payload, vlessLink };
          status.value = 'success';
          await loadAccounts();
        } else {
          status.value = 'error';
        }
      } catch (e) {
        status.value = 'error';
        console.error(e);
      }
    }

    function copy(text, field) {
      navigator.clipboard.writeText(text);
      copied.value = field;
      setTimeout(() => copied.value = '', 2000);
    }

    async function deleteAccount(uuid) {
      if (!confirm('Delete this account?')) return;
      try {
        await fetch('/api/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ uuid })
        });
        await loadAccounts();
      } catch (e) {
        console.error(e);
      }
    }

    function render() {
      const app = document.getElementById('app');
      const cfg = config.value;
      const res = result.value;
      const accs = accounts.value;
      const st = status.value;
      const cp = copied.value;

      app.innerHTML = \`
        <div class="container mx-auto px-4 py-8 max-w-4xl">
          <div class="text-center mb-8">
            <div class="inline-flex items-center justify-center w-20 h-20 bg-purple-500/20 rounded-full mb-4">
              <svg class="w-10 h-10 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
              </svg>
            </div>
            <h1 class="text-4xl font-bold text-white mb-2">VLESS VPN Generator</h1>
            <p class="text-purple-300">Advanced SNI Routing + Bug Hosting</p>
          </div>

          \${st === 'loading' ? \`
            <div class="mb-6 bg-blue-500/20 border border-blue-400 rounded-xl p-4">
              <div class="flex items-center gap-3">
                <div class="animate-spin rounded-full h-5 w-5 border-2 border-blue-400 border-t-transparent"></div>
                <span class="text-white">Creating VLESS account...</span>
              </div>
            </div>
          \` : ''}

          \${st === 'success' ? \`
            <div class="mb-6 bg-green-500/20 border border-green-400 rounded-xl p-4">
              <span class="text-white font-semibold">✅ Account created successfully!</span>
            </div>
          \` : ''}

          \${st === 'error' ? \`
            <div class="mb-6 bg-red-500/20 border border-red-400 rounded-xl p-4">
              <span class="text-white">❌ Failed. Check your configuration.</span>
            </div>
          \` : ''}

          \${!res ? \`
            <div class="bg-white/5 backdrop-blur-xl rounded-2xl p-8 border border-white/10">
              <div class="space-y-6">
                <div class="bg-purple-500/10 border border-purple-400/30 rounded-xl p-4">
                  <h3 class="text-white font-semibold mb-2">📖 Contoh Konfigurasi</h3>
                  <div class="text-sm text-purple-200 space-y-2">
                    <p><strong>Bug Hosting (Facebook):</strong></p>
                    <p class="ml-4 text-xs">Server: \${location.hostname}<br>WS Host: \${location.hostname}<br>SNI: graph.facebook.com</p>
                  </div>
                </div>

                <div>
                  <label class="block text-sm font-medium text-purple-200 mb-2">Target Server *</label>
                  <input
                    type="text"
                    value="\${cfg.server}"
                    oninput="config.value = {...config.value, server: this.value}"
                    placeholder="developer.mixpanel.com atau \${location.hostname}"
                    class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-purple-400"
                  />
                </div>

                <div class="grid grid-cols-2 gap-4">
                  <div>
                    <label class="block text-sm font-medium text-purple-200 mb-2">Port</label>
                    <select
                      value="\${cfg.port}"
                      onchange="config.value = {...config.value, port: this.value, security: this.value === '443' ? 'tls' : 'none'}"
                      class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400"
                    >
                      <option value="443">443 (TLS)</option>
                      <option value="80">80</option>
                      <option value="8080">8080</option>
                      <option value="8443">8443</option>
                    </select>
                  </div>
                  <div>
                    <label class="block text-sm font-medium text-purple-200 mb-2">Path</label>
                    <input
                      type="text"
                      value="\${cfg.path}"
                      oninput="config.value = {...config.value, path: this.value}"
                      class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400"
                    />
                  </div>
                </div>

                <div>
                  <label class="block text-sm font-medium text-purple-200 mb-2">WebSocket Host</label>
                  <input
                    type="text"
                    value="\${cfg.wsHost}"
                    oninput="config.value = {...config.value, wsHost: this.value}"
                    class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400"
                  />
                </div>

                <div>
                  <label class="block text-sm font-medium text-purple-200 mb-2">SNI (Server Name Indication) *</label>
                  <input
                    type="text"
                    value="\${cfg.sni}"
                    oninput="config.value = {...config.value, sni: this.value}"
                    placeholder="graph.facebook.com"
                    class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-purple-400"
                  />
                </div>

                <button
                  onclick="createAccount()"
                  class="w-full py-4 bg-gradient-to-r from-purple-500 to-pink-600 hover:from-purple-600 hover:to-pink-700 text-white font-semibold rounded-lg transition-all"
                >
                  🚀 Create VLESS Account
                </button>
              </div>
            </div>
          \` : \`
            <div class="bg-white/5 backdrop-blur-xl rounded-2xl p-8 border border-white/10">
              <h2 class="text-2xl font-bold text-white mb-6">✅ VLESS Configuration</h2>
              <div class="space-y-4">
                <div class="bg-white/5 rounded-xl p-4">
                  <label class="block text-sm font-medium text-purple-200 mb-2">UUID</label>
                  <div class="flex items-center gap-2">
                    <code class="flex-1 bg-black/30 px-3 py-2 rounded text-green-400 text-sm break-all">\${res.uuid}</code>
                    <button onclick="copy('\${res.uuid}', 'uuid')" class="px-4 py-2 bg-purple-500 hover:bg-purple-600 rounded-lg text-white">
                      \${cp === 'uuid' ? '✓' : '📋'}
                    </button>
                  </div>
                </div>

                <div class="bg-white/5 rounded-xl p-4">
                  <label class="block text-sm font-medium text-purple-200 mb-2">VLESS Link</label>
                  <div class="flex items-center gap-2">
                    <code class="flex-1 bg-black/30 px-3 py-2 rounded text-green-400 text-xs break-all max-h-24 overflow-y-auto">\${res.vlessLink}</code>
                    <button onclick="copy('\${res.vlessLink}', 'link')" class="px-4 py-2 bg-purple-500 hover:bg-purple-600 rounded-lg text-white">
                      \${cp === 'link' ? '✓' : '📋'}
                    </button>
                  </div>
                </div>

                <button onclick="result.value = null; status.value = ''" class="w-full py-3 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-lg">
                  Create New Account
                </button>
              </div>
            </div>
          \`}

          \${accs.length > 0 ? \`
            <div class="mt-6 bg-white/5 backdrop-blur-xl rounded-2xl p-8 border border-white/10">
              <h2 class="text-xl font-bold text-white mb-4">Saved Accounts (\${accs.length})</h2>
              <div class="space-y-3">
                \${accs.map((acc, i) => \`
                  <div class="bg-white/5 rounded-xl p-4 flex justify-between items-start">
                    <div class="flex-1">
                      <p class="text-white font-mono text-xs">\${acc.uuid}</p>
                      <p class="text-purple-300 text-xs">Server: \${acc.server} | SNI: \${acc.sni}</p>
                    </div>
                    <div class="flex gap-2">
                      <button onclick="copy('\${acc.uuid}', 'acc-\${i}')" class="px-3 py-1 bg-purple-500/50 hover:bg-purple-500 rounded text-white text-sm">
                        \${cp === \`acc-\${i}\` ? '✓' : '📋'}
                      </button>
                      <button onclick="deleteAccount('\${acc.uuid}')" class="px-3 py-1 bg-red-500/50 hover:bg-red-500 rounded text-white text-sm">
                        🗑️
                      </button>
                    </div>
                  </div>
                \`).join('')}
              </div>
            </div>
          \` : ''}

          <div class="text-center mt-8">
            <p class="text-gray-400 text-sm">Based on Nautica Implementation</p>
          </div>
        </div>
      \`;
    }

    window.createAccount = createAccount;
    window.copy = copy;
    window.deleteAccount = deleteAccount;

    effect(() => {
      config.value;
      accounts.value;
      result.value;
      status.value;
      copied.value;
      render();
    });

    loadAccounts();
    render();
  </script>
</body>
</html>`;
}
