import { WebSocket } from 'ws';
import * as crypto from 'crypto';
import { MessageTypesToSent, MessageTypesToReceive } from './enums';
import { HqcWrapper } from '../lib/hqc';
import { authProof } from '../lib/auth-proof';

const PORT = 8080;

// NOTE: this is a legacy standalone demo (superseded by test/helpers/test-client.ts,
// which also negotiates the transport SESSION_KEY). Migrated to the IND-CCA2 KEM
// (§KM-1): auth is a decapsulate→HKDF proof, the per-friend handshake is a mutual
// encapsulation, and messages are AES-GCM only (no per-message HQC).

/**
 * Test Client Factory
 */
export function createTestClient(hexSeed: string, myHandle: string, targetHandle: string, isInitiator: boolean) {
    const SERVER_URL = `ws://localhost:${PORT}`;
    const keys = HqcWrapper.keypairFromSeed(Buffer.from(hexSeed, 'hex'));
    const MY_PK = keys.pk.toString('hex');
    const MY_SK = Buffer.from(keys.sk);

    const friendsMap = new Map<string, any>();
    const ws = new WebSocket(SERVER_URL);

    const deriveKey = (s1: Buffer, s2: Buffer) =>
        Buffer.from(crypto.hkdfSync('sha256', Buffer.concat([s1, s2].sort((a, b) => a.compare(b))), Buffer.from('salt'), Buffer.from('info'), 32));

    const encryptAES = (text: string, key: Buffer) => {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
        return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString('base64');
    };

    const decryptAES = (b64: string, key: Buffer) => {
        const buf = Buffer.from(b64, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
        decipher.setAuthTag(buf.subarray(12, 28));
        return decipher.update(buf.subarray(28)) + decipher.final('utf8');
    };

    ws.on('open', () => {
        console.log(`[${myHandle}] Connecting...`);
        ws.send(JSON.stringify({ type: MessageTypesToSent.AUTH_INIT, payload: MY_PK }));
    });

    ws.on('message', async (data) => {
        const msg = JSON.parse(data.toString());

        switch (msg.type) {
            case MessageTypesToReceive.AUTH_CHALLENGE: {
                const ss = HqcWrapper.decapsulate(MY_SK, Buffer.from(msg.payload, 'base64'));
                ws.send(JSON.stringify({ type: MessageTypesToSent.AUTH_VERIFY, payload: authProof(ss).toString('base64') }));
                break;
            }

            case MessageTypesToReceive.AUTH_SUCCESS:
                console.log(`[${myHandle}] Auth Success. Setting handle...`);
                ws.send(JSON.stringify({ type: MessageTypesToSent.SET_USERNAME, payload: myHandle }));
                break;

            case MessageTypesToReceive.USERNAME_UPDATED:
                if (isInitiator) {
                    console.log(`[${myHandle}] Triggering /add ${targetHandle}`);
                    setTimeout(() => {
                        ws.send(JSON.stringify({ type: MessageTypesToSent.ADD_FRIEND, payload: targetHandle }));
                    }, 1000);
                }
                break;

            case MessageTypesToReceive.DIRECT_MESSAGE:
                if (msg.payload.includes('new invite')) {
                    console.log(`[${myHandle}] Accepting invite from ${targetHandle}`);
                    ws.send(JSON.stringify({ type: MessageTypesToSent.ACCEPT_INVITE, payload: targetHandle }));
                } else {
                    const friend = friendsMap.get(msg.sender);
                    if (friend?.aes?.sharedKey) {
                        // §KM-1 step 5: payload is the AES-GCM base64 directly.
                        const inner = decryptAES(msg.payload, friend.aes.sharedKey);
                        console.log(`[${myHandle}] 📩 RECEIVED: "${inner}"`);
                        if (!isInitiator) console.log(`[${myHandle}] Test Complete.`);
                    }
                }
                break;

            case MessageTypesToReceive.FRIEND_ADDED: {
                const { username, pk } = msg.payload || msg;
                friendsMap.set(username, { pk, aes: {} });

                console.log(`[${myHandle}] Social Bonded with ${username}. Exchanging KEM secrets...`);
                const { ct, ss } = HqcWrapper.encapsulate(Buffer.from(pk, 'hex'));
                friendsMap.get(username).aes.mySeed = ss;
                ws.send(JSON.stringify({ type: MessageTypesToSent.AES, targetPk: username, payload: ct.toString('base64') }));
                break;
            }

            case MessageTypesToReceive.AES: {
                const f = friendsMap.get(msg.sender);
                f.aes.peerSeed = HqcWrapper.decapsulate(MY_SK, Buffer.from(msg.payload, 'base64'));

                if (!f.aes.mySeed) {
                    const enc = HqcWrapper.encapsulate(Buffer.from(f.pk, 'hex'));
                    f.aes.mySeed = enc.ss;
                    ws.send(JSON.stringify({ type: MessageTypesToSent.AES, targetPk: msg.sender, payload: enc.ct.toString('base64') }));
                }

                f.aes.sharedKey = deriveKey(f.aes.mySeed, f.aes.peerSeed);
                console.log(`[${myHandle}] 🔐 AES shared key established with ${msg.sender}`);

                if (isInitiator) {
                    const secretText = `Hello ${targetHandle}, this is a post-quantum encrypted message!`;
                    console.log(`[${myHandle}] 📤 SENDING: "${secretText}"`);
                    // §KM-1 step 5: AES-GCM only, no per-message HQC.
                    const payload = encryptAES(secretText, f.aes.sharedKey);
                    ws.send(JSON.stringify({ type: MessageTypesToSent.MESSAGE, targetPk: targetHandle, payload }));
                }
                break;
            }
        }
    });
}

// Start the Test
createTestClient('4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a', 'martin', 'hugo', true);
createTestClient('1a5e6a2a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a', 'hugo', 'martin', false);
