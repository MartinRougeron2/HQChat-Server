import { WebSocket } from 'ws';
import * as crypto from 'crypto';
import { MessageTypesToSent, MessageTypesToReceive } from './enums';
import { HqcWrapper, HQC_CONSTANTS } from './lib/hqc';

const PORT = 8080;

/**
 * HQC Block Encryption Helpers
 */
function HqcEncrypt(publicKey: string, encryptedAESBase64: string): string {
    const K = HQC_CONSTANTS.PARAM_K;
    const bufferPk = Buffer.from(publicKey, 'hex');
    const dataToHide = Buffer.from(encryptedAESBase64, 'utf8');
    const chunks: Buffer[] = [];

    for (let i = 0; i < dataToHide.length; i += K) {
        let chunk = dataToHide.subarray(i, i + K);
        if (chunk.length < K) {
            const padded = Buffer.alloc(K, 0);
            chunk.copy(padded);
            chunk = padded;
        }
        const theta = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
        chunks.push(HqcWrapper.encrypt(bufferPk, chunk, theta));
    }
    return Buffer.concat(chunks).toString('base64');
}

function HqcDecrypt(privateKey: string, hqcPayloadBase64: string): string {
    const bufferSk = Buffer.from(privateKey, 'hex');
    const fullCt = Buffer.from(hqcPayloadBase64, 'base64');
    const CT_SIZE = HQC_CONSTANTS.CIPHERTEXT_SIZE_BYTES;
    const decryptedChunks: Buffer[] = [];

    for (let i = 0; i < fullCt.length; i += CT_SIZE) {
        const block = fullCt.subarray(i, i + CT_SIZE);
        decryptedChunks.push(HqcWrapper.decrypt(bufferSk, block));
    }
    return Buffer.concat(decryptedChunks).toString('utf8').replace(/\0+$/, '');
}

/**
 * Test Client Factory
 */
export function createTestClient(hexSeed: string, myHandle: string, targetHandle: string, isInitiator: boolean) {
    const SERVER_URL = `ws://localhost:${PORT}`;
    const keys = HqcWrapper.generateKeypair(Buffer.from(hexSeed, 'hex'));
    const MY_PK = keys.pk.toString('hex');
    const MY_SK = keys.sk.toString('hex');

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
            case MessageTypesToReceive.AUTH_CHALLENGE:
                const sol = HqcWrapper.decrypt(Buffer.from(MY_SK, 'hex'), Buffer.from(msg.payload, 'base64'));
                ws.send(JSON.stringify({ type: MessageTypesToSent.AUTH_VERIFY, payload: sol.toString('base64') }));
                break;

            case MessageTypesToReceive.AUTH_SUCCESS:
                console.log(`[${myHandle}] Auth Success. Setting handle...`);
                ws.send(JSON.stringify({ type: MessageTypesToSent.SET_USERNAME, payload: myHandle }));
                break;

            case MessageTypesToReceive.USERNAME_UPDATED:
                if (isInitiator) {
                    console.log(`[${myHandle}] Triggering /add ${targetHandle}`);
                    // Wait a moment to ensure Bob has registered his name
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
                        const outer = HqcDecrypt(MY_SK, msg.payload);
                        const inner = decryptAES(outer, friend.aes.sharedKey);
                        console.log(`[${myHandle}] 📩 RECEIVED: "${inner}" (Decrypted via HQC+AES)`);
                        if (!isInitiator) {
                            console.log(`[${myHandle}] Test Complete.`);
                        }
                    }
                }
                break;

            case MessageTypesToReceive.FRIEND_ADDED:
                const { username, pk } = msg.payload || msg;
                friendsMap.set(username, { pk, aes: {} });

                console.log(`[${myHandle}] Social Bonded with ${username}. Exchanging PQC Seeds...`);
                const mySeed = crypto.randomBytes(HQC_CONSTANTS.PARAM_K);
                const ct = HqcWrapper.encrypt(Buffer.from(pk, 'hex'), mySeed, crypto.randomBytes(32));
                friendsMap.get(username).aes.mySeed = mySeed;

                ws.send(JSON.stringify({ type: MessageTypesToSent.AES, targetPk: username, payload: ct.toString('base64') }));
                break;

            case MessageTypesToReceive.AES:
                const f = friendsMap.get(msg.sender);
                const peerSeed = HqcWrapper.decrypt(Buffer.from(MY_SK, 'hex'), Buffer.from(msg.payload, 'base64'));
                f.aes.peerSeed = peerSeed;

                if (!f.aes.mySeed) {
                    const s = crypto.randomBytes(HQC_CONSTANTS.PARAM_K);
                    const ct = HqcWrapper.encrypt(Buffer.from(f.pk, 'hex'), s, crypto.randomBytes(32));
                    f.aes.mySeed = s;
                    ws.send(JSON.stringify({ type: MessageTypesToSent.AES, targetPk: msg.sender, payload: ct.toString('base64') }));
                }

                f.aes.sharedKey = deriveKey(f.aes.mySeed, f.aes.peerSeed);
                console.log(`[${myHandle}] 🔐 AES Shared Key established with ${msg.sender}`);

                if (isInitiator) {
                    const secretText = `Hello ${targetHandle}, this is a Post-Quantum Double-Encrypted message!`;
                    console.log(`[${myHandle}] 📤 SENDING: "${secretText}"`);
                    const payload = HqcEncrypt(f.pk, encryptAES(secretText, f.aes.sharedKey));
                    ws.send(JSON.stringify({ type: MessageTypesToSent.MESSAGE, targetPk: targetHandle, payload }));
                }
                break;
        }
    });
}

// Start the Test
createTestClient('4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a', 'martin', 'hugo', true);
createTestClient('1a5e6a2a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a4a5e6b1a', 'hugo', 'martin', false);