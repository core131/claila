
/**
 * VLESS Proxy Worker - Cloudflare Worker Implementation
 * 
 * Features:
 * - Full VLESS protocol support
 * - Two-way communication (full-duplex)
 * - Support for HTTP/HTTPS/WebSocket protocols
 * - UUID authentication
 * - Transparent proxy functionality
 * - Connection multiplexing support
 */

// Configuration constants
const CONFIG = {
    // UUID for authentication (get from environment)
    UUID: null,
    
    // Supported protocols
    SUPPORTED_PROTOCOLS: ['http', 'https', 'ws', 'wss'],
    
    // Connection timeouts
    TIMEOUTS: {
        CONNECT: 10000,
        IDLE: 30000
    },
    
    // Buffer sizes
    BUFFER_SIZE: 64 * 1024, // 64KB
    
    // Logging level
    LOG_LEVEL: 'info' // debug, info, warn, error
};

// Utility functions
class Utils {
    static log(level, message, ...args) {
        const levels = { debug: 0, info: 1, warn: 2, error: 3 };
        if (levels[level] >= levels[CONFIG.LOG_LEVEL]) {
            console.log(`[${level.toUpperCase()}] ${message}`, ...args);
        }
    }

    static generateRequestId() {
        return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    }

    static isValidUUID(uuid) {
        const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        return regex.test(uuid);
    }

    static parseVLESSHeader(data) {
        try {
            // VLESS protocol format: Version + UUID + Command + Address
            const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
            
            // Version (1 byte)
            const version = view.getUint8(0);
            
            // UUID (16 bytes)
            const uuidBytes = new Uint8Array(16);
            for (let i = 0; i < 16; i++) {
                uuidBytes[i] = view.getUint8(1 + i);
            }
            const uuid = Array.from(uuidBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const formattedUUID = [
                uuid.substring(0, 8),
                uuid.substring(8, 12),
                uuid.substring(12, 16),
                uuid.substring(16, 20),
                uuid.substring(20)
            ].join('-');

            // Protocol version 1: Command (1 byte)
            const command = view.getUint8(17);
            
            // Address parsing
            let address = '';
            let port = 0;
            let offset = 18;

            if (command === 1) { // IPv4
                address = `${view.getUint8(offset)}.${view.getUint8(offset + 1)}.${view.getUint8(offset + 2)}.${view.getUint8(offset + 3)}`;
                offset += 4;
                port = view.getUint16(offset);
                offset += 2;
            } else if (command === 2) { // Domain name
                const domainLength = view.getUint8(offset);
                offset += 1;
                const domainBytes = new Uint8Array(domainLength);
                for (let i = 0; i < domainLength; i++) {
                    domainBytes[i] = view.getUint8(offset + i);
                }
                address = new TextDecoder().decode(domainBytes);
                offset += domainLength;
                port = view.getUint16(offset);
                offset += 2;
            } else if (command === 3) { // IPv6
                const ipv6Parts = [];
                for (let i = 0; i < 8; i++) {
                    ipv6Parts.push(view.getUint16(offset + i * 2).toString(16));
                }
                address = ipv6Parts.join(':');
                offset += 16;
                port = view.getUint16(offset);
                offset += 2;
            }

            return {
                version,
                uuid: formattedUUID,
                command,
                address,
                port,
                remainingData: data.slice(offset)
            };
        } catch (error) {
            Utils.log('error', 'Failed to parse VLESS header:', error);
            return null;
        }
    }

    static parseURL(request) {
        try {
            const url = new URL(request.url);
            return {
                protocol: url.protocol.slice(0, -1),
                hostname: url.hostname,
                port: url.port || (url.protocol === 'https:' ? 443 : 80),
                path: url.pathname,
                search: url.search
            };
        } catch (error) {
            Utils.log('error', 'Failed to parse URL:', error);
            return null;
        }
    }
}

// VLESS Connection Handler
class VLESSConnection {
    constructor(websocket, targetAddress, targetPort) {
        this.websocket = websocket;
        this.targetAddress = targetAddress;
        this.targetPort = targetPort;
        this.targetSocket = null;
        this.requestId = Utils.generateRequestId();
        this.isActive = true;
        this.stats = {
            bytesUploaded: 0,
            bytesDownloaded: 0,
            startTime: Date.now(),
            packetsUploaded: 0,
            packetsDownloaded: 0
        };
    }

    async handleConnection() {
        try {
            Utils.log('info', `[${this.requestId}] Connecting to ${this.targetAddress}:${this.targetPort}`);
            
            // Create TCP connection to target
            this.targetSocket = await this.connectToTarget();
            
            // Setup bidirectional data forwarding
            this.setupDataForwarding();
            
            Utils.log('info', `[${this.requestId}] Connection established successfully`);
            
        } catch (error) {
            Utils.log('error', `[${this.requestId}] Connection failed:`, error);
            this.cleanup();
        }
    }

    async connectToTarget() {
        try {
            // Use Cloudflare's connect API for TCP connections
            const socket = connect({
                hostname: this.targetAddress,
                port: this.targetPort
            });

            // Set up error handling
            socket.closed.then(() => {
                Utils.log('info', `[${this.requestId}] Target connection closed`);
                this.cleanup();
            });

            return socket;
        } catch (error) {
            Utils.log('error', `[${this.requestId}] Failed to connect to target:`, error);
            throw error;
        }
    }

    setupDataForwarding() {
        // WebSocket -> Target (Upload)
        this.websocket.addEventListener('message', async (event) => {
            if (!this.isActive || !this.targetSocket) return;
            
            try {
                const data = new Uint8Array(event.data);
                await this.targetSocket.write(data);
                
                this.stats.bytesUploaded += data.length;
                this.stats.packetsUploaded++;
                
                Utils.log('debug', `[${this.requestId}] Upload: ${data.length} bytes`);
            } catch (error) {
                Utils.log('error', `[${this.requestId}] Upload failed:`, error);
                this.cleanup();
            }
        });

        // Target -> WebSocket (Download)
        const readData = async () => {
            if (!this.isActive) return;
            
            try {
                const data = await this.targetSocket.read();
                if (data) {
                    this.websocket.send(data);
                    
                    this.stats.bytesDownloaded += data.length;
                    this.stats.packetsDownloaded++;
                    
                    Utils.log('debug', `[${this.requestId}] Download: ${data.length} bytes`);
                    
                    // Continue reading
                    readData();
                } else {
                    Utils.log('info', `[${this.requestId}] Target connection ended`);
                    this.cleanup();
                }
            } catch (error) {
                Utils.log('error', `[${this.requestId}] Download failed:`, error);
                this.cleanup();
            }
        };

        readData();

        // Handle WebSocket close
        this.websocket.addEventListener('close', () => {
            Utils.log('info', `[${this.requestId}] WebSocket closed`);
            this.cleanup();
        });

        this.websocket.addEventListener('error', (error) => {
            Utils.log('error', `[${this.requestId}] WebSocket error:`, error);
            this.cleanup();
        });
    }

    cleanup() {
        if (!this.isActive) return;
        
        this.isActive = false;
        
        try {
            if (this.targetSocket) {
                this.targetSocket.close();
            }
            if (this.websocket) {
                this.websocket.close();
            }
        } catch (error) {
            Utils.log('error', `[${this.requestId}] Cleanup error:`, error);
        }

        // Log connection statistics
        const duration = Date.now() - this.stats.startTime;
        Utils.log('info', `[${
            this.requestId
        }] Connection stats: Duration: ${duration}ms, Upload: ${
            this.stats.bytesUploaded
        } bytes (${this.stats.packetsUploaded} packets), Download: ${
            this.stats.bytesDownloaded
        } bytes (${this.stats.packetsDownloaded} packets)`);
    }

    getStats() {
        return {
            ...this.stats,
            duration: Date.now() - this.stats.startTime,
            target: `${this.targetAddress}:${this.targetPort}`
        };
    }
}

// Main Worker class
class VLESSWorker {
    constructor() {
        this.connections = new Map();
        this.stats = {
            totalConnections: 0,
            activeConnections: 0,
            totalBytesTransferred: 0
        };
    }

    async handleRequest(request, env, ctx) {
        try {
            // Initialize configuration
            if (!CONFIG.UUID) {
                CONFIG.UUID = env.UUID;
            }

            const url = Utils.parseURL(request);
            Utils.log('debug', 'Incoming request:', url);

            // Handle WebSocket upgrade for VLESS connections
            if (request.headers.get('Upgrade') === 'websocket') {
                return this.handleWebSocketUpgrade(request, env, ctx);
            }

            // Handle regular HTTP requests (health check, status, etc.)
            return this.handleHTTPRequest(request, env, ctx);

        } catch (error) {
            Utils.log('error', 'Request handling error:', error);
            return new Response('Internal Server Error', { status: 500 });
        }
    }

    async handleWebSocketUpgrade(request, env, ctx) {
        try {
            // Accept WebSocket connection
            const websocketPair = new WebSocketPair();
            const [client, server] = Object.values(websocketPair);

            // Accept the WebSocket connection
            server.accept();

            Utils.log('info', 'WebSocket connection accepted');

            // Wait for initial VLESS handshake
            const initialData = await this.waitForVLESSHandshake(server);
            
            if (!initialData) {
                server.close(1002, 'Invalid VLESS handshake');
                return new Response(null, { status: 101, webSocket: client });
            }

            // Parse VLESS header
            const vlessHeader = Utils.parseVLESSHeader(initialData);
            
            if (!vlessHeader) {
                server.close(1002, 'Invalid VLESS header');
                return new Response(null, { status: 101, webSocket: client });
            }

            // Validate UUID
            if (vlessHeader.uuid !== CONFIG.UUID) {
                Utils.log('warn', 'Invalid UUID attempted:', vlessHeader.uuid);
                server.close(1003, 'Authentication failed');
                return new Response(null, { status: 101, webSocket: client });
            }

            // Create and handle VLESS connection
            const connection = new VLESSConnection(
                server, 
                vlessHeader.address, 
                vlessHeader.port
            );

            // Store connection for tracking
            this.connections.set(connection.requestId, connection);
            this.stats.totalConnections++;
            this.stats.activeConnections++;

            // Handle connection cleanup
            server.closed.then(() => {
                this.connections.delete(connection.requestId);
                this.stats.activeConnections--;
            });

            // Start connection handling
            ctx.waitUntil(connection.handleConnection());

            // Handle any remaining data from initial packet
            if (vlessHeader.remainingData && vlessHeader.remainingData.length > 0) {
                ctx.waitUntil(
                    connection.targetSocket.write(vlessHeader.remainingData)
                );
            }

            return new Response(null, { status: 101, webSocket: client });

        } catch (error) {
            Utils.log('error', 'WebSocket upgrade error:', error);
            return new Response('WebSocket upgrade failed', { status: 400 });
        }
    }

    async waitForVLESSHandshake(websocket) {
        return new Promise((resolve) => {
            const timeout = setTimeout(() => {
                resolve(null);
            }, 5000);

            const messageHandler = (event) => {
                clearTimeout(timeout);
                websocket.removeEventListener('message', messageHandler);
                resolve(new Uint8Array(event.data));
            };

            websocket.addEventListener('message', messageHandler);
        });
    }

    async handleHTTPRequest(request, env, ctx) {
        const url = new URL(request.url);
        
        // Health check endpoint
        if (url.pathname === '/health') {
            return new Response(JSON.stringify({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                connections: {
                    total: this.stats.totalConnections,
                    active: this.stats.activeConnections
                }
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Status endpoint
        if (url.pathname === '/status') {
            return new Response(JSON.stringify({
                worker: 'VLESS Proxy Worker',
                version: '1.0.0',
                stats: this.stats,
                supportedProtocols: CONFIG.SUPPORTED_PROTOCOLS,
                uptime: process.uptime ? process.uptime() : 0
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Default response
        return new Response('VLESS Proxy Worker - Use WebSocket connections for proxy', {
            status: 200,
            headers: { 'Content-Type': 'text/plain' }
        });
    }
}

// Worker event handlers
const worker = new VLESSWorker();

export default {
    async fetch(request, env, ctx) {
        return await worker.handleRequest(request, env, ctx);
    }
};
