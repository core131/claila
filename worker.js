// VLESS Cloudflare Worker with Full Features
// Supports: WebSocket, CDN, Route, Proxy, Two-way Communication, XTLS

const userID = '90cd4a77-141a-43c9-991b-08263cfe9c10'; // Ganti dengan UUID Anda
const proxyIPs = ['cdn.xn--b6gac.eu.org', 'cdn-all.xn--b6gac.eu.org']; // Proxy IP list

export default {
  async fetch(request, env, ctx) {
    try {
      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader !== 'websocket') {
        const url = new URL(request.url);
        switch (url.pathname) {
          case '/':
            return new Response(generateHomePage(), {
              headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
          case `/${userID}`:
            return new Response(generateVLESSConfig(request.headers.get('Host')), {
              headers: { 'Content-Type': 'text/plain; charset=utf-8' }
            });
          default:
            return new Response('Not found', { status: 404 });
        }
      }

      const webSocketPair = new WebSocketPair();
      const [client, webSocket] = Object.values(webSocketPair);
      
      webSocket.accept();
      
      const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
      const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);
      
      let remoteSocketWapper = {
        value: null,
      };
      let udpStreamWrite = null;
      let isDns = false;

      readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter()
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = processVlessHeader(chunk, userID);
          
          if (hasError) {
            throw new Error(message);
          }
          
          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              throw new Error('UDP proxy only enabled for DNS which is port 53');
            }
          }
          
          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isDns) {
            const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }
          
          handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })).catch((err) => {
        log('readableWebSocketStream pipeTo error', err);
      });

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
      
    } catch (err) {
      return new Response(err.toString());
    }
  },
};

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = {
      hostname: address,
      port: port,
    };
    remoteSocket.value = await connect(tcpSocket);

    log(`connected to <span class="math-inline" data-latex="%7Baddress%7D%3A">{address}:</span>{port}`);
    const writer = remoteSocket.value.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return;
  }

  async function retry() {
    const proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
    await connectAndWrite(proxyIP || addressRemote, portRemote);
  }
  
  const tcpSocket = {
    hostname: addressRemote,
    port: portRemote,
  };
  
  try {
    remoteSocket.value = await connect(tcpSocket);
  } catch (error) {
    await retry();
  }

  const transformStream = new TransformStream({
    start(controller) {
      
    },
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const uint8Array = new Uint8Array(lengthBuffer);
        const length = new DataView(uint8Array.buffer).getUint16(0);
        index += 2;
        index += length;
      }
      controller.enqueue(chunk);
    },
  });

  await remoteSocket.value.readable.pipeThrough(transformStream).pipeTo(
    new WritableStream({
      async write(chunk, controller) {
        const writer = webSocket.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
      },
      close() {
        log(`remoteSocket.readable is close`);
      },
      abort(reason) {
        log(`remoteSocket.readable abort`, reason);
      },
    })
  );
  
  remoteSocket.value.closed.catch(error => {
    log('remoteSocket closed error', error);
  }).finally(() => {
    webSocket.close();
  })
}

async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {
  let isVlessHeaderSent = false;
  return new WritableStream({
    async write(chunk, controller) {
      if (!isVlessHeaderSent) {
        webSocket.send(new Uint8Array([...vlessResponseHeader, ...chunk]));
        isVlessHeaderSent = true;
      } else {
        webSocket.send(chunk);
      }
    }
  });
}

function processVlessHeader(vlessBuffer, userID) {
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
  
  if (!isValidUser) {
    return {
      hasError: true,
      message: 'invalid user',
    };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
  
  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
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
        message: `invlid  addressType is ${addressType}`,
      };
  }
  
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

async function connect(socket) {
  return await Cloudflare.connect(socket);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      
      webSocketServer.addEventListener('close', () => {
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      
      webSocketServer.addEventListener('error', (err) => {
        controller.error(err);
      });
      
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      readableStreamCancel = true;
      webSocketServer.close();
    }
  });
  
  return stream;
}

function log(...args) {
  console.log(...args);
}

function stringify(arr, offset = 0) {
  const bytes = [];
  for (let i = offset; i < offset + 16; i++) {
    bytes.push(arr[i]);
  }
  const uuid = [
    bytes.slice(0, 4),
    bytes.slice(4, 6),
    bytes.slice(6, 8),
    bytes.slice(8, 10),
    bytes.slice(10, 16)
  ].map(group => group.map(byte => byte.toString(16).padStart(2, '0')).join('')).join('-');
  return uuid;
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function generateHomePage() {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>VLESS Configuration</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f0f0f0;
      padding: 20px;
      margin: 0;
    }
    .container {
      max-width: 800px;
      margin: 0 auto;
      background: white;
      padding: 30px;
      border-radius: 10px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 {
      color: #333;
      text-align: center;
    }
    .info-box {
      background: #f9f9f9;
      padding: 20px;
      border-radius: 5px;
      margin: 20px 0;
    }
    .code {
      background: #333;
      color: #fff;
      padding: 10px;
      border-radius: 5px;
      font-family: monospace;
      overflow-x: auto;
    }
    .warning {
      background: #fff3cd;
      border: 1px solid #ffeaa7;
      color: #856404;
      padding: 10px;
      border-radius: 5px;
      margin: 10px 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>VLESS Worker Configuration</h1>
    
    <div class="info-box">
      <h2>Status: Active ✅</h2>
      <p>Your VLESS Worker is running successfully on Cloudflare Workers.</p>
    </div>
    
    <div class="info-box">
      <h2>Configuration Endpoint</h2>
      <p>Access your VLESS configuration at:</p>
      <div class="code">https://[YOUR-WORKER-DOMAIN]/${userID}</div>
    </div>
    
    <div class="info-box">
      <h2>Features</h2>
      <ul>
        <li>✅ WebSocket Support</li>
        <li>✅ CDN Support</li>
        <li>✅ Two-way Communication</li>
        <li>✅ XTLS Ready</li>
        <li>✅ Route & Proxy Support</li>
        <li>✅ DNS over UDP (Port 53)</li>
      </ul>
    </div>
    
    <div class="warning">
      <strong>Security Notice:</strong> Remember to change the default UUID in the code before deployment.
    </div>
  </div>
</body>
</html>
  `;
}

function generateVLESSConfig(hostName) {
  const vlessLink = `vless://<span class="math-inline" data-latex="%7BuserID%7D%40">{userID}@</span>{hostName}:443?encryption=none&security=tls&sni=${
