import { WebSocket } from "ws";
import * as readline from "readline";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { exec } from "child_process";
import { MessageTypesToSent, MessageTypesToReceive } from "./enums";
import { HqcWrapper, HQC_CONSTANTS } from "./lib/hqc";

const PORT = 8080;

interface FriendInfo {
  pk: string;
  aes?: AESState;
}

interface AESState {
  mySeed?: Buffer;
  peerSeed?: Buffer;
  sharedKey?: Buffer;
}

interface AudioStream {
  streamId: string;
  sender: string;
  chunks: Map<number, Buffer>;
  totalChunks: number;
  receivedChunks: Set<number>;
  startTime: Date;
}

/**
 * OUTER LAYER: HQC Encryption
 * Takes the AES ciphertext string and wraps it in HQC blocks.
 */
function HqcEncrypt(publicKey: string, encryptedAESBase64: string): string {
  const K = HQC_CONSTANTS.PARAM_K; // 24 bytes
  const bufferPk = Buffer.from(publicKey, "hex");
  // We treat the AES Base64 string as the plaintext for HQC
  const dataToHide = Buffer.from(encryptedAESBase64, "utf8");

  const chunks: Buffer[] = [];

  for (let i = 0; i < dataToHide.length; i += K) {
    let chunk = dataToHide.subarray(i, i + K);

    // Pad the last chunk with zeros if it's less than 24 bytes
    if (chunk.length < K) {
      const padded = Buffer.alloc(K, 0);
      chunk.copy(padded);
      chunk = padded;
    }

    const theta = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
    const encryptedBlock = HqcWrapper.encrypt(bufferPk, chunk, theta);
    chunks.push(encryptedBlock);
  }

  return Buffer.concat(chunks).toString("base64");
}

/**
 * OUTER LAYER: HQC Decryption
 * Slices the incoming HQC stream and recovers the AES ciphertext string.
 */
function HqcDecrypt(privateKey: string, hqcPayloadBase64: string): string {
  const bufferSk = Buffer.from(privateKey, "hex");
  const fullCt = Buffer.from(hqcPayloadBase64, "base64");
  const CT_SIZE = HQC_CONSTANTS.CIPHERTEXT_SIZE_BYTES; // 14416

  if (fullCt.length % CT_SIZE !== 0) throw new Error("Malformed HQC payload");

  const decryptedChunks: Buffer[] = [];

  for (let i = 0; i < fullCt.length; i += CT_SIZE) {
    const block = fullCt.subarray(i, i + CT_SIZE);
    const decryptedBlock = HqcWrapper.decrypt(bufferSk, block);
    decryptedChunks.push(decryptedBlock);
  }

  // Join chunks and remove trailing null padding characters
  return Buffer.concat(decryptedChunks).toString("utf8").replace(/\0+$/, "");
}

export function createClient(hexSeed: string) {
  const SERVER_URL = `wss://chat.martinrougeron.me/ws`;
  const seed = Buffer.from(hexSeed, "hex");
  const keys = HqcWrapper.generateKeypair(seed);
  const MY_PK = keys.pk.toString("hex");
  const MY_SK = keys.sk.toString("hex");

  // LOCAL STORAGE
  // Map<Username, FriendData>
  const friendsMap = new Map<string, FriendInfo>();
  // Map<StreamId, AudioStream>
  const activeStreams = new Map<string, AudioStream>();

  // --- CRYPTO UTILS ---

  function deriveSharedKey(seedA: Buffer, seedB: Buffer): Buffer {
    const sorted = [seedA, seedB].sort((a, b) => a.compare(b));
    return Buffer.from(
      crypto.hkdfSync(
        "sha256",
        Buffer.concat(sorted),
        Buffer.from("salt"),
        Buffer.from("info"),
        32
      )
    );
  }

  function encryptAES(text: string, key: Buffer): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
    // Format: [IV (12 bytes)][Tag (16 bytes)][Ciphertext]
    return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString("base64");
  }

  function decryptAES(b64: string, key: Buffer): string {
    const buf = Buffer.from(b64, "base64");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ciphertext = buf.subarray(28);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(ciphertext) + decipher.final("utf8");
  }

  // --- AUDIO STREAM HANDLERS ---

  function handleAudioStreamStart(sender: string, payload: string) {
    const senderData = friendsMap.get(sender);
    if (!senderData || !senderData.aes?.sharedKey) {
      console.log(
        `\n🎵 [${sender}]: (Locked Audio Stream - No Shared AES Key)`
      );
      return;
    }

    try {
      // Decrypt stream start
      const recoveredAESString = HqcDecrypt(MY_SK, payload);
      const streamId = decryptAES(recoveredAESString, senderData.aes.sharedKey);

      console.log(
        `\n🎵 [${sender}]: Audio stream started (ID: ${streamId.substring(
          0,
          8
        )}...)`
      );

      const stream: AudioStream = {
        streamId,
        sender,
        chunks: new Map(),
        totalChunks: 0,
        receivedChunks: new Set(),
        startTime: new Date(),
      };

      activeStreams.set(streamId, stream);
    } catch (e) {
      console.log(`\n🎵 [${sender}]: (Stream Start Decryption Failed)`);
    }
  }

  function handleAudioStreamChunk(sender: string, payload: string) {
    const senderData = friendsMap.get(sender);
    if (!senderData || !senderData.aes?.sharedKey) {
      return;
    }

    try {
      // OPTIMIZATION: Chunks are now AES-only (no HQC layer) for performance
      // Decrypt AES-only chunk
      const chunkJson = decryptAES(payload, senderData.aes.sharedKey);
      const chunkData = JSON.parse(chunkJson);

      const streamId = chunkData.streamId;
      const seq = chunkData.seq;
      const total = chunkData.total;
      const chunkBytes = Buffer.from(chunkData.data, "base64");

      const stream = activeStreams.get(streamId);
      if (!stream) {
        console.log(
          `\n🎵 [${sender}]: Received chunk for unknown stream: ${streamId.substring(
            0,
            8
          )}...`
        );
        return;
      }

      stream.totalChunks = total;
      stream.chunks.set(seq, chunkBytes);
      stream.receivedChunks.add(seq);

      console.log(
        `\n🎵 [${sender}]: Chunk ${seq + 1}/${total} received (${stream.receivedChunks.size
        }/${total} total)`
      );

      // Check if stream is complete
      if (stream.receivedChunks.size === stream.totalChunks) {
        reconstructAndPlayAudio(stream);
      }
    } catch (e) {
      console.log(`\n🎵 [${sender}]: (Chunk Decryption Failed)`);
    }
  }

  function handleAudioStreamEnd(sender: string, payload: string) {
    const senderData = friendsMap.get(sender);
    if (!senderData || !senderData.aes?.sharedKey) {
      return;
    }

    try {
      // Decrypt stream end
      const recoveredAESString = HqcDecrypt(MY_SK, payload);
      const streamId = decryptAES(recoveredAESString, senderData.aes.sharedKey);

      console.log(
        `\n🎵 [${sender}]: Audio stream ended (ID: ${streamId.substring(
          0,
          8
        )}...)`
      );

      const stream = activeStreams.get(streamId);
      if (!stream) {
        return;
      }

      // Wait a bit for any late packets, then reconstruct
      setTimeout(() => {
        if (activeStreams.has(streamId)) {
          const currentStream = activeStreams.get(streamId)!;
          if (currentStream.receivedChunks.size < currentStream.totalChunks) {
            console.log(
              `\n🎵 [${sender}]: Stream incomplete (${currentStream.receivedChunks.size}/${currentStream.totalChunks} chunks), reconstructing anyway...`
            );
          }
          reconstructAndPlayAudio(currentStream);
        }
      }, 1000);
    } catch (e) {
      console.log(`\n🎵 [${sender}]: (Stream End Decryption Failed)`);
    }
  }

  function reconstructAndPlayAudio(stream: AudioStream) {
    console.log(`\n🎵 [${stream.sender}]: Reconstructing audio stream...`);

    // Sort chunks by sequence number
    const sortedChunks: Buffer[] = [];
    const missingChunks: number[] = [];

    for (let i = 0; i < stream.totalChunks; i++) {
      const chunk = stream.chunks.get(i);
      if (chunk) {
        sortedChunks.push(chunk);
      } else {
        missingChunks.push(i);
        // Insert silence for missing chunks (50ms at 44.1kHz, 1 channel, 16-bit = 4410 bytes)
        // Format matches Swift: 16-bit, little-endian, 44100 Hz, 1 channel
        const sampleRate = 44100;
        const channels = 1;
        const bytesPerSample = 2; // 16-bit PCM
        const chunkSize =
          ((sampleRate * 50) / 1000) * channels * bytesPerSample; // 4410 bytes per 50ms chunk
        sortedChunks.push(Buffer.alloc(chunkSize, 0));
      }
    }

    if (missingChunks.length > 0) {
      console.log(
        `\n🎵 [${stream.sender}]: Missing chunks: ${missingChunks.join(
          ", "
        )} (filled with silence)`
      );
    }

    // Reconstruct PCM data (16-bit, little-endian, 44100 Hz, 1 channel)
    // Format matches Swift: kAudioFormatLinearPCM, 16-bit, little-endian, 44100 Hz, 1 channel
    const pcmData = Buffer.concat(sortedChunks);

    // Create WAV file from PCM (matches Swift's PCM format)
    const wavData = createWAVFile(pcmData, 44100, 1, 16);

    // Save to temporary file
    const tempDir = path.join(process.cwd(), "temp");
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    const tempFile = path.join(
      tempDir,
      `audio_stream_${stream.streamId.substring(0, 8)}_${Date.now()}.wav`
    );
    fs.writeFileSync(tempFile, wavData);

    console.log(
      `\n🎵 [${stream.sender}]: Playing reconstructed audio stream...`
    );

    // Play audio using system command
    const platform = process.platform;
    let playCommand: string;

    if (platform === "darwin") {
      playCommand = `afplay "${tempFile}"`;
    } else if (platform === "linux") {
      playCommand = `paplay "${tempFile}" || aplay "${tempFile}"`;
    } else if (platform === "win32") {
      playCommand = `start "" "${tempFile}"`;
    } else {
      console.log(`\n⚠️ Audio playback not supported on ${platform}`);
      activeStreams.delete(stream.streamId);
      return;
    }

    exec(playCommand, (error) => {
      if (error) {
        console.log(`\n⚠️ Failed to play audio: ${error.message}`);
      } else {
        console.log(`\n✅ Audio stream played successfully`);
      }
      // Clean up
      setTimeout(() => {
        try {
          fs.unlinkSync(tempFile);
        } catch (e) {
          // Ignore cleanup errors
        }
      }, 5000);
    });

    // Remove stream from active streams
    activeStreams.delete(stream.streamId);
  }

  /**
   * Create WAV file from PCM data
   * Format matches Swift: 16-bit, little-endian, 44100 Hz, 1 channel
   */
  function createWAVFile(
    pcmData: Buffer,
    sampleRate: number,
    channels: number,
    bitsPerSample: number
  ): Buffer {
    const dataSize = pcmData.length;
    const fileSize = 36 + dataSize;

    const wav = Buffer.alloc(44 + dataSize);
    let offset = 0;

    // RIFF header
    wav.write("RIFF", offset);
    offset += 4;
    wav.writeUInt32LE(fileSize, offset);
    offset += 4;
    wav.write("WAVE", offset);
    offset += 4;

    // fmt chunk
    wav.write("fmt ", offset);
    offset += 4;
    wav.writeUInt32LE(16, offset);
    offset += 4; // fmt chunk size
    wav.writeUInt16LE(1, offset);
    offset += 2; // audio format (PCM)
    wav.writeUInt16LE(channels, offset);
    offset += 2;
    wav.writeUInt32LE(sampleRate, offset);
    offset += 4;
    const byteRate = (sampleRate * channels * bitsPerSample) / 8;
    wav.writeUInt32LE(byteRate, offset);
    offset += 4;
    const blockAlign = (channels * bitsPerSample) / 8;
    wav.writeUInt16LE(blockAlign, offset);
    offset += 2;
    wav.writeUInt16LE(bitsPerSample, offset);
    offset += 2;

    // data chunk
    wav.write("data", offset);
    offset += 4;
    wav.writeUInt32LE(dataSize, offset);
    offset += 4;
    pcmData.copy(wav, offset);

    return wav;
  }

  // --- NETWORKING ---
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: ">> ",
  });
  const ws = new WebSocket(SERVER_URL);

  ws.on("open", () => {
    console.log(`Verifying Identity...`);
    ws.send(
      JSON.stringify({ type: MessageTypesToSent.AUTH_INIT, payload: MY_PK })
    );
  });

  ws.on("message", (data: Buffer) => {
    const msg = JSON.parse(data.toString());

    switch (msg.type) {
      case MessageTypesToReceive.AUTH_CHALLENGE:
        const sol = HqcWrapper.decrypt(
          Buffer.from(MY_SK, "hex"),
          Buffer.from(msg.payload, "base64")
        );
        ws.send(
          JSON.stringify({
            type: MessageTypesToSent.AUTH_VERIFY,
            payload: sol.toString("base64"),
          })
        );
        break;

      case MessageTypesToReceive.AUTH_SUCCESS:
        console.log(`\n✅ Online. Use /name <id> to set handle.`);
        rl.prompt();
        break;
      case MessageTypesToReceive.PAYMENT_REQUIRED:
        console.log(msg);
        rl.prompt();
        break;
      case MessageTypesToReceive.USERNAME_UPDATED:
        console.log(`\n🏷️  You are now known as: ${msg.payload}`);
        rl.prompt();
        break;

      case MessageTypesToReceive.FRIEND_REQUEST:
        console.log(`\n👋 Request from '${msg.sender}': ${msg.payload}`);
        console.log(`   Type: /accept ${msg.sender}`);
        rl.prompt();
        break;

      case MessageTypesToReceive.FRIEND_ADDED:
        // Server sends { username: string, pk: string }
        // This is the CRITICAL step where we bind Username -> PK
        const { username, pk } = msg;
        console.log(`\n🤝 Friend Added: ${username}`);

        // 1. Store locally
        friendsMap.set(username, { pk: pk, aes: {} });
        console.log("set: ", pk);

        // 2. Initiate HQC-to-AES Handshake
        // Generate my seed
        const mySeed = crypto.randomBytes(HQC_CONSTANTS.PARAM_K);
        const theta = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);

        // Encrypt seed with THEIR PK
        const ct = HqcWrapper.encrypt(Buffer.from(pk, "hex"), mySeed, theta);

        // Update local state
        friendsMap.get(username)!.aes!.mySeed = mySeed;

        // Send to server (routed by Username)
        ws.send(
          JSON.stringify({
            type: MessageTypesToSent.AES,
            targetPk: username, // Using username field
            payload: ct.toString("base64"),
          })
        );
        rl.prompt();
        break;

      case MessageTypesToReceive.USER_LIST_RESPONSE:
        console.log("\n🌎 Global User Directory:");
        msg.payload.forEach((u: any) =>
          console.log(
            ` @${u.username.padEnd(15)} | PK: ${u.pk.substring(0, 12)}...`
          )
        );
        rl.prompt();
        break;

      case MessageTypesToReceive.AES:
        // msg.sender is a USERNAME
        const friend = friendsMap.get(msg.sender);
        if (!friend) return; // Unknown sender or not in friends list

        const cipherSeed = Buffer.from(msg.payload, "base64");
        try {
          // Decrypt their seed with MY SK
          const peerSeed = HqcWrapper.decrypt(
            Buffer.from(MY_SK, "hex"),
            cipherSeed
          );
          friend.aes!.peerSeed = peerSeed;

          // If I haven't sent mine, send it now
          if (!friend.aes!.mySeed) {
            const newSeed = crypto.randomBytes(HQC_CONSTANTS.PARAM_K);
            const newTheta = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
            const newCt = HqcWrapper.encrypt(
              Buffer.from(friend.pk, "hex"),
              newSeed,
              newTheta
            );

            friend.aes!.mySeed = newSeed;
            ws.send(
              JSON.stringify({
                type: MessageTypesToSent.AES,
                targetPk: msg.sender,
                payload: newCt.toString("base64"),
              })
            );
          }

          // Derive Key
          friend.aes!.sharedKey = deriveSharedKey(
            friend.aes!.mySeed!,
            friend.aes!.peerSeed!
          );
          console.log(`\n🔐 Secure Channel Established with ${msg.sender}`);
        } catch (e) {
          console.log("AES Handshake Failed");
        }
        rl.prompt();
        break;

      case MessageTypesToReceive.DIRECT_MESSAGE:
        if (msg.sender === "SYSTEM") {
          console.log(`\n📢 ${msg.payload}`);
        } else {
          const senderData = friendsMap.get(msg.sender);
          if (senderData && senderData.aes?.sharedKey) {
            try {
              // Step 1: Decrypt Outer HQC Layer using YOUR Secret Key
              // msg.payload is already a base64 string
              const recoveredAESString = HqcDecrypt(MY_SK, msg.payload);

              // Step 2: Decrypt Inner AES Layer using the Shared Key
              const plainText = decryptAES(
                recoveredAESString,
                senderData.aes.sharedKey
              );

              console.log(`\n📩 [${msg.sender}]: ${plainText}`);
            } catch (e) {
              console.log(
                `\n📩 [${msg.sender}]: (Decryption Failed: ${e instanceof Error ? e.message : String(e)
                })`
              );
            }
          } else {
            console.log(
              `\n📩 [${msg.sender}]: (Locked Message - No Shared AES Key)`
            );
          }
        }
        rl.prompt();
        break;

      case MessageTypesToReceive.AUDIO_MESSAGE:
        const audioSenderData = friendsMap.get(msg.sender);
        if (audioSenderData && audioSenderData.aes?.sharedKey) {
          try {
            // Step 1: Decrypt Outer HQC Layer using YOUR Secret Key
            const recoveredAESString = HqcDecrypt(MY_SK, msg.payload);

            // Step 2: Decrypt Inner AES Layer using the Shared Key
            const audioDataBase64 = decryptAES(
              recoveredAESString,
              audioSenderData.aes.sharedKey
            );

            // Decode base64 audio data
            const audioBuffer = Buffer.from(audioDataBase64, "base64");

            // Save to temporary file
            const tempDir = path.join(process.cwd(), "temp");
            if (!fs.existsSync(tempDir)) {
              fs.mkdirSync(tempDir, { recursive: true });
            }
            const tempFile = path.join(tempDir, `audio_${Date.now()}.wav`);
            fs.writeFileSync(tempFile, audioBuffer);

            console.log(`\n🎵 [${msg.sender}]: Playing audio message...`);

            // Play audio using system command (macOS: afplay, Linux: aplay/paplay, Windows: start)
            const platform = process.platform;
            let playCommand: string;

            if (platform === "darwin") {
              playCommand = `afplay "${tempFile}"`;
            } else if (platform === "linux") {
              playCommand = `paplay "${tempFile}" || aplay "${tempFile}"`;
            } else if (platform === "win32") {
              playCommand = `start "" "${tempFile}"`;
            } else {
              console.log(`\n⚠️ Audio playback not supported on ${platform}`);
              rl.prompt();
              break;
            }

            exec(playCommand, (error) => {
              if (error) {
                console.log(`\n⚠️ Failed to play audio: ${error.message}`);
              } else {
                console.log(`\n✅ Audio played successfully`);
              }
              // Clean up temp file after a delay
              setTimeout(() => {
                try {
                  fs.unlinkSync(tempFile);
                } catch (e) {
                  // Ignore cleanup errors
                }
              }, 5000);
            });
          } catch (e) {
            console.log(
              `\n🎵 [${msg.sender}]: (Audio Decryption Failed - Integrity Check Error)`
            );
          }
        } else {
          console.log(
            `\n🎵 [${msg.sender}]: (Locked Audio Message - No Shared AES Key)`
          );
        }
        rl.prompt();
        break;

      case MessageTypesToReceive.AUDIO_STREAM_START:
        handleAudioStreamStart(msg.sender, msg.payload);
        rl.prompt();
        break;

      case MessageTypesToReceive.AUDIO_STREAM_CHUNK:
        handleAudioStreamChunk(msg.sender, msg.payload);
        rl.prompt();
        break;

      case MessageTypesToReceive.AUDIO_STREAM_END:
        handleAudioStreamEnd(msg.sender, msg.payload);
        rl.prompt();
        break;

      case MessageTypesToReceive.ERROR:
        console.log(`\n⚠️ Error: ${msg.payload}`);
        rl.prompt();
        break;
    }
  });

  rl.on("line", (line) => {
    const parts = line.trim().split(" ");
    const cmd = parts[0];

    if (cmd === "/name") {
      ws.send(
        JSON.stringify({
          type: MessageTypesToSent.SET_USERNAME,
          payload: parts[1],
        })
      );
    } else if (cmd === "/add") {
      ws.send(
        JSON.stringify({
          type: MessageTypesToSent.ADD_FRIEND,
          payload: parts[1],
        })
      );
    } else if (cmd === "/accept") {
      ws.send(
        JSON.stringify({
          type: MessageTypesToSent.ACCEPT_INVITE,
          payload: parts[1],
        })
      );
    } else if (cmd === "/users") {
      ws.send(
        JSON.stringify({ type: MessageTypesToSent.GET_ALL_USERS, payload: 100 })
      );
    } else if (cmd === "/list") {
      console.log("\nFriends:");
      friendsMap.forEach((v, k) =>
        console.log(`- ${k} ${v.aes?.sharedKey ? "🔒" : "⚠️"}`)
      );
    } else if (cmd === "/audio") {
      // Format: /audio <username> <file_path>
      const targetUser = parts[1];
      const filePath = parts[2];

      if (!targetUser || !filePath) {
        console.log("Usage: /audio <username> <file_path>");
        rl.prompt();
        return;
      }

      const friend = friendsMap.get(targetUser);
      if (!friend || !friend.aes?.sharedKey) {
        console.log(`User '${targetUser}' not found or no secure session.`);
        rl.prompt();
        return;
      }

      try {
        // Read audio file
        if (!fs.existsSync(filePath)) {
          console.log(`File not found: ${filePath}`);
          rl.prompt();
          return;
        }

        const audioBuffer = fs.readFileSync(filePath);
        const audioBase64 = audioBuffer.toString("base64");

        // Step 1: AES Encryption (Inner Layer)
        const encAES = encryptAES(audioBase64, friend.aes.sharedKey);

        // Step 2: HQC Encryption (Outer Layer)
        const doubleEncrypted = HqcEncrypt(friend.pk, encAES);

        ws.send(
          JSON.stringify({
            type: MessageTypesToSent.AUDIO_MESSAGE,
            targetPk: targetUser,
            payload: doubleEncrypted,
          })
        );

        console.log(`\n🎵 Audio message sent to ${targetUser}`);
      } catch (e: any) {
        console.log(`\n⚠️ Failed to send audio: ${e.message}`);
      }
    } else {
      // Chat: <username> <message>
      const targetUser = parts[0];
      const text = parts.slice(1).join(" ");
      if (targetUser) {
        const friend = friendsMap.get(targetUser);

        if (friend && friend.aes?.sharedKey) {
          // Step 1: AES Encryption (Inner Layer)
          const encAES = encryptAES(text, friend.aes.sharedKey);

          // Step 2: HQC Encryption (Outer Layer)
          // We encrypt the AES ciphertext string using the friend's Public Key
          const doubleEncrypted = HqcEncrypt(friend.pk, encAES);

          ws.send(
            JSON.stringify({
              type: MessageTypesToSent.MESSAGE,
              targetPk: targetUser,
              payload: doubleEncrypted,
            })
          );
        } else {
          console.log(`User '${targetUser}' not found or no secure session.`);
        }
      }
    }
    rl.prompt();
  });
}
