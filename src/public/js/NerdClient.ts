/* 
Official client for NerdLock by Mester
Feel free to copy this code and potentially use it for your own custom client, I guess
Anyway, enough talk, have fun looking at my "amazing" code
*/

import CryptoHelper from "./CryptoHelper.js";
import NerdCache from "./NerdCache.js";
import NerdUtils from "./NerdUtils.js";

/* Constans */
/**
 * NerdLock server versions the client should accept
 */
const acceptVersions = ["1.0.2"];

/**
 * The main entry point of the NerdLock API
 */
const APIBase = "/_nerdlock";

/**
 * NerdLock API endpoints
 */
const APIEndpoints = {
    info: APIBase + "/info",
    users: {
        root: APIBase + "/users",
        login: APIBase + "/users/login",
        register: APIBase + "/users/register",
        info: APIBase + "/users/:userId",
        x3dh: APIBase + "/users/:userId/x3dh",
        secretRequest: APIBase + "/users/:userId/secretRequest",
        secretMessage: APIBase + "/users/:userId/secretMessage",
        mfa: {
            totp: APIBase + "/users/mfa/totp",
            u2f: {
                register: APIBase + "/users/mfa/regU2F",
                auth: APIBase + "/users/mfa/authU2F"
            }
        }
    },
    sse: APIBase + "/sse",
    rooms: {
        sync: APIBase + "/rooms/sync",
        create: APIBase + "/rooms/create",
        message: APIBase + "/rooms/:roomId/message",
        messages: APIBase + "/rooms/:roomId/messages",
        invite: APIBase + "/rooms/:roomId/invite/:userId",
        join: APIBase + "/rooms/join/:roomId",
    }
}

export interface NerdMessageFile {
    name: string;
    type: string;
    data: string;
    size: number;
}

export interface NerdMessageContent {
    text?: string;
    files?: NerdMessageFile[];
}

export interface NerdMessage {
    messageId: string;
    roomId: string;
    authorId: string;
    createdAt: number;
    lastModifiedAt: number;
    content: NerdMessageContent;
    verified: boolean;
}

export interface NerdRawMessage {
    messageId: string;
    roomId: string;
    authorId: string;
    createdAt: number;
    lastModifiedAt: number;
    cipherText: string;
    signature: string;
}

export interface NerdRoom {
    roomId: string;
    name: string;
    secret: string;
    messages: NerdMessage[];
    members: NerdRoomMember[];
}

export interface NerdRoomMember {
    memberId: string;
    permissions: number;
}

export interface NerdUser {
    username: string;
    accessToken: string;
    userId: string;
    public: NerdUserPublicData;
    rooms: Map<string, NerdRoom>;
    mfa: {
        totp: boolean;
        u2f: boolean;
    };
}

export interface NerdPublicUser {
    username: string;
    userId: string;
    identity: string;
    identityKey: CryptoKey;
    online: boolean;
}

type NerdSecretMessageType = "roomInvite";

interface NerdUserLoginOpt {
    totp?: string;
}

interface NerdUserRegOpt extends NerdUserPublicData {
    mastKey: string;
}

interface NerdUserPublicData {
    idenKey: { private: string; public: string; };
    preKey: { private: string; public: string; sign: string; }
    oneTimeKeys: { id: number; private: string; public: string; }[];
}

interface NerdUserX3DHData {
    idenKey: { public: string; };
    otKey: { id: number; public: string; };
    preKey: { public: string; sign: string; };
    userId: string;
    username: string;
}

interface NerdSecretRequest {
    from: string;
    identityKey: string;
    ephemeralKey: string;
    preMessage: string;
    otKeyId: number;
    id: string;
}

interface NerdSecretMessage {
    from: string;
    message: string;
}
/* -------- */

/**
 * Class for the client, which connects all APIs together
 */
class NerdClient {
    domain: string;
    rooms: RoomManager;
    user: NerdUser;
    sse: EventSource;
    userSecrets: UserSecretManager;
    userStore: UserStore;
    #masterKey: CryptoKey;

    constructor(domain: string) {
        this.domain = domain;
    }

    /**
     * Main function for authenticating with a Nerdlock server
     * @param username The username
     * @param password The password
     * @param mode login or register
     * @param opt Extra options for registration and login which could include indentity keys, 2fa codes etc.
     * @returns A NerdClient instance if authentication succeedes, otherwise null
     */
    async auth(username: string, password: string, mode: "login" | "register", opt?: NerdUserRegOpt | NerdUserLoginOpt) {
        try {
            console.log(`[Nerdlock] Authenticating user ${username}`);

            const passwordHash = CryptoHelper.enc.UintToString(await crypto.subtle.digest("SHA-512", new TextEncoder().encode(password)), "base64");

            const r = await fetch(this.domain + (mode === "login" ? APIEndpoints.users.login : APIEndpoints.users.register), {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password: passwordHash, opt: opt ?? undefined })
            });

            if (!r.ok)
                throw new Error("Server did not respond with an ok status");

            const data = await r.json() as NerdUser & {
                secretRequests: Array<NerdSecretRequest>;
                secretMessages: Array<{ from: string; message: string; }>;
                usedOneTimeKeys: Array<{ id: number; private: string; public: string }>;
                masterKey: string;
            }

            data.public.oneTimeKeys.concat(data.usedOneTimeKeys);
            const secretRequests = data.secretRequests;
            const secretMessages = data.secretMessages;
            const masterKeyEnc = data.masterKey;

            data.secretRequests = data.usedOneTimeKeys = data.secretMessages = data.masterKey = undefined;

            this.user = data;

            // here we've successfully authenticated
            console.log(`[Nerdlock] Successfully authenticated user ${username}!`);

            this.user.accessToken = `Bearer ${this.user.accessToken}`;

            let [iv, salt, cipherText] = masterKeyEnc.split(".");
            const key = await CryptoHelper.generatePBKDF2(password, CryptoHelper.enc.StringToUint(salt, "base64"), 1_000_000, 32, "SHA-256");
            const masterKeyDec = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: CryptoHelper.enc.StringToUint(iv, "base64") }, key, CryptoHelper.enc.StringToUint(cipherText, "base64"))
                .then(data => { return data; })
                .catch((err) => { throw new Error(`Failed to decrypt master key, this is a fatal issue: ${err}`); });

            const masterKey = this.#masterKey = await crypto.subtle.importKey("raw", masterKeyDec, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

            // decrypt private keys
            [iv, cipherText] = this.user.public.idenKey.private.split(".");
            this.user.public.idenKey.private = await crypto.subtle.decrypt({ name: "AES-GCM", iv: CryptoHelper.enc.StringToUint(iv, "base64") },
                masterKey, CryptoHelper.enc.StringToUint(cipherText, "base64"))
                .then(data => { return CryptoHelper.enc.UintToString(data, "base64"); });

            [iv, cipherText] = this.user.public.preKey.private.split(".");
            this.user.public.preKey.private = await crypto.subtle.decrypt({ name: "AES-GCM", iv: CryptoHelper.enc.StringToUint(iv, "base64") },
                masterKey, CryptoHelper.enc.StringToUint(cipherText, "base64"))
                .then(data => { return CryptoHelper.enc.UintToString(data, "base64"); });

            for (const otKey of this.user.public.oneTimeKeys) {
                [iv, cipherText] = otKey.private.split(".");
                otKey.private = await crypto.subtle.decrypt({ name: "AES-GCM", iv: CryptoHelper.enc.StringToUint(iv, "base64") },
                    masterKey, CryptoHelper.enc.StringToUint(cipherText, "base64"))
                    .then(data => { return CryptoHelper.enc.UintToString(data, "base64"); });
            }

            // check if we need to regenerate one time keys
            if (this.user.public.oneTimeKeys.length < 20) {
                console.log("[Nerdlock] Generating new one time keys")
                const newKeys = this.user.public.oneTimeKeys;

                for (let i = 0; i < 50; i++) {
                    if (newKeys.find(key => key.id === i)) continue;

                    const { privateKey, publicKey } = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey"]);

                    const iv = crypto.getRandomValues(new Uint8Array(32));
                    const encPrivKey = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, await crypto.subtle.exportKey("pkcs8", privateKey))
                        .then(data => { return `${CryptoHelper.enc.UintToString(iv, "base64")}.${CryptoHelper.enc.UintToString(data, "base64")}`; });

                    const publicKeyString = CryptoHelper.enc.UintToString(await crypto.subtle.exportKey("raw", publicKey), "base64");

                    newKeys.push({ id: i, private: encPrivKey, public: publicKeyString });
                }

                const r = await fetch(this.domain + APIEndpoints.users.root, {
                    method: "PATCH",
                    body: JSON.stringify({ oneTimeKeys: newKeys }),
                    headers: { "Authorization": this.user.accessToken, "Content-Type": "application/json" }
                });

                if (!r.ok)
                    console.error("Failed to update one time keys");
            }

            this.rooms = new RoomManager(this, NerdCache.messages);
            this.userSecrets = new UserSecretManager(this, secretRequests, secretMessages);
            this.userStore = new UserStore(this);

            // set up SSE
            const sseUrl = new URL(this.domain + APIEndpoints.sse);
            sseUrl.searchParams.append("auth", this.user.accessToken);
            this.sse = new EventSource(sseUrl);
            this.setupSSE();

            return this;
        } catch (err) {
            console.error(err);
            console.log(`Failed to authenticate at ${this.domain}. Please check if credientials are correct!`);
            return null;
        }
    }

    static async login(domain: string, username: string, password: string, opt?: { totp?: string }) {
        const client = await createClient(domain);
        if (!client) return false;
        return client.auth(username, password, "login", opt);
    }

    static async register(domain: string, username: string, password: string) {
        const client = await createClient(domain);
        if (!client) return false;
        try {
            // set up everything for the server
            console.log("[Nerdlock] Generating keys for X3DH");
            const masterKeyData = crypto.getRandomValues(new Uint8Array(32));
            const masterKey = await CryptoHelper.keyFromUint(masterKeyData);

            const idenKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-521" }, true, ["sign"]);
            const publicIdenKeyString = CryptoHelper.enc.UintToString(await crypto.subtle.exportKey("raw", idenKeyPair.publicKey), "base64");

            const preKeyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey"]);
            const publicPreKey = await crypto.subtle.exportKey("raw", preKeyPair.publicKey);
            const publicPreKeySignString = CryptoHelper.enc.UintToString(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-512" }, idenKeyPair.privateKey, publicPreKey), "base64");

            // encrypt private identity key with masterkey and masterkey with password
            let iv = crypto.getRandomValues(new Uint8Array(32));
            const privIdenKeyEnc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, await crypto.subtle.exportKey("pkcs8", idenKeyPair.privateKey))
                .then(data => { return `${CryptoHelper.enc.UintToString(iv, "base64")}.${CryptoHelper.enc.UintToString(data, "base64")}`; });

            iv = crypto.getRandomValues(new Uint8Array(32));
            const privPreKeyEnc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, await crypto.subtle.exportKey("pkcs8", preKeyPair.privateKey))
                .then(data => { return `${CryptoHelper.enc.UintToString(iv, "base64")}.${CryptoHelper.enc.UintToString(data, "base64")}`; });

            iv = crypto.getRandomValues(new Uint8Array(32));
            let salt = crypto.getRandomValues(new Uint8Array(64));
            const passwordKey = await CryptoHelper.generatePBKDF2(password, salt, 1_000_000, 32, "SHA-256");
            const masterKeyEnc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, passwordKey, masterKeyData)
                .then(data => { return `${CryptoHelper.enc.UintToString(iv, "base64")}.${CryptoHelper.enc.UintToString(salt, "base64")}.${CryptoHelper.enc.UintToString(data, "base64")}`; });

            // generate one time keys
            const oneTimeKeys: { id: number; private: string; public: string; }[] = [];
            for (let i = 0; i < 50; i++) {
                const { privateKey, publicKey } = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey"]);

                const iv = crypto.getRandomValues(new Uint8Array(32));
                const privateKeyEnc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, await crypto.subtle.exportKey("pkcs8", privateKey))
                    .then(data => { return `${CryptoHelper.enc.UintToString(iv, "base64")}.${CryptoHelper.enc.UintToString(data, "base64")}`; });

                const publicKeyString = CryptoHelper.enc.UintToString(await crypto.subtle.exportKey("raw", publicKey), "base64");

                oneTimeKeys.push({ id: i, private: privateKeyEnc, public: publicKeyString });
            }

            const opt: NerdUserRegOpt = {
                mastKey: masterKeyEnc,
                idenKey: { private: privIdenKeyEnc, public: publicIdenKeyString },
                preKey: { private: privPreKeyEnc, public: CryptoHelper.enc.UintToString(publicPreKey, "base64"), sign: publicPreKeySignString },
                oneTimeKeys
            }

            return client.auth(username, password, "register", opt);
        } catch (err) {
            console.error(err);
            if (err instanceof DOMException) {
                console.log("Couldn't create required cryptographic keys");
            }
        }
    }

    setupSSE() {
        this.sse.addEventListener("newMessage", (event) => {
            const message = JSON.parse(event.data) as NerdRawMessage;
            const room = this.rooms.get(message.roomId);
            if (!room) return;

            this.userStore.fetchUser(message.authorId).then((author) => {
                NerdUtils.decodeRawMessage(room, message, author);
            });
        });

        this.sse.addEventListener("secretRequest", (event) => {
            try {
                const message = JSON.parse(event.data) as NerdSecretRequest;
                this.userSecrets.addSecretRequest(message);
            } catch (err) {
                console.error(err);
                console.log("Failed to accept secret request");
            }
        });

        this.sse.addEventListener("secretMessage", (event) => {
            try {
                const message = JSON.parse(event.data) as NerdSecretMessage;
                this.userSecrets.addSecretMessage(message);
            } catch (err) {
                console.error(err);
                console.log("Failed to accept secret message");
            }
        });

        this.sse.addEventListener("userPresence", (event) => {
            try {
                const message = JSON.parse(event.data) as { userId: string, online: boolean };
                this.userStore.updateUser(message.userId, { online: message.online })
            } catch (err) {
                console.error(err);
                console.log(`Failed to update user`);
            }
        })
    }

    getMasterKey() {
        return this.#masterKey;
    }

    async totp(type: "register" | "activate", code?: string) {
        try {
            if (type === "activate" && !code)
                throw new Error("You can't activate TOTP without the code");

            const r = await fetch(APIEndpoints.users.mfa.totp, {
                method: "POST",
                headers: { "Authorization": this.user.accessToken, "Content-Type": "application/json" },
                body: type === "activate" ? JSON.stringify({ challenge: code }) : null
            });

            if (!r.ok)
                throw new Error("Non-ok response from server");

            if (type === "activate")
                this.user.mfa.totp = true;

            if (type === "register")
                return r.json() as Promise<{ challenge: string }>;
            else return true;
        } catch (err) {
            console.error(err);
            console.log(`Failed to ${type} TOTP`);
            return false;
        }
    }

    async u2f() {
        try {
            const r = await fetch(APIEndpoints.users.mfa.u2f.register, {
                headers: { "Authorization": this.user.accessToken }
            });

            if (!r.ok)
                throw new Error("Non-ok response from server");

            const regOptions = await r.json() as PublicKeyCredentialCreationOptions;

            //@ts-ignore
            regOptions.user.id = CryptoHelper.enc.StringToUint(regOptions.user.id);
            //@ts-ignore
            regOptions.challenge = CryptoHelper.enc.StringToUint(regOptions.challenge, "base64");

            const regResult = await navigator.credentials.create({
                publicKey: regOptions
            }).catch((err) => { throw err; }) as unknown as PublicKeyCredential;

            console.log(regResult);

            const r2 = await fetch(APIEndpoints.users.mfa.u2f.register, {
                headers: { "Authorization": this.user.accessToken, "Content-Type": "application/json" },
                method: "POST",
                body: JSON.stringify({
                    id: CryptoHelper.enc.UintToString(regResult.rawId, "base64"),
                    response: {
                        clientDataJSON: CryptoHelper.enc.UintToString(regResult.response.clientDataJSON, "base64"),
                        attestationObject: CryptoHelper.enc.UintToString((regResult.response as AuthenticatorAttestationResponse).attestationObject, "base64")
                    }
                })
            });

            if (!r2.ok)
                throw new Error("Non-ok response from server");

            return true;
        } catch (err) {
            console.error(err);
            console.log(`Failed to register U2F key`);
            return false;
        }
    }
}

/**
 * Class for managing rooms
 */
class RoomManager {
    #rooms: Map<string, NerdRoom>;
    #client: NerdClient;

    constructor(client: NerdClient, messages: NerdRawMessage[]) {
        this.#client = client;
        this.#rooms = new Map<string, NerdRoom>();
        this.sync().then(async () => {
            for (const [_, room] of this.#rooms) {
                for (const m of messages.filter(x => x.roomId === room.roomId)) {
                    const author = await this.#client.userStore.fetchUser(m.authorId);
                    await NerdUtils.decodeRawMessage(room, m, author);
                }
            }
        })
    }

    async getRooms() {
        const rooms: NerdRoom[] = [];
        for (const [_, room] of this.#rooms)
            rooms.push(room);
        return rooms;
    }

    /**
     * Method for creating a new Nerdlock room
     * It automatically generates a 256-bit long room secret
     */
    async create(options: {
        roomName: string
    }) {
        try {
            // generate a random room secret and iv
            const secret = crypto.getRandomValues(new Uint8Array(32));
            const iv = crypto.getRandomValues(new Uint8Array(16));

            // encrypt the secret with the master key
            const masterKey = this.#client.getMasterKey();

            const encryptedSecret = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, secret)
                .then(data => { return `${CryptoHelper.enc.UintToString(iv, "base64")}.${CryptoHelper.enc.UintToString(data, "base64")}`; })
                .catch((err) => { throw err; });

            // send the room create request
            const r = await fetch(this.#client.domain + APIEndpoints.rooms.create, {
                body: JSON.stringify({ name: options.roomName, roomSecret: encryptedSecret }),
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": this.#client.user.accessToken }
            });

            if (!r.ok)
                throw new Error("Non-ok response from server");

            await this.sync();
        } catch (err) {
            console.error(err);
            console.log(`Failed to create room`);
        }
    }

    get(roomid: string) {
        return this.#rooms.get(roomid);
    }

    async sendMessage(roomId: string, message: NerdMessageContent) {
        try {
            const room = this.get(roomId);
            if (!room) return null;

            // verify message
            const keys = Object.keys(message)
            if (keys.length === 0 || keys.find(k => !["text", "files"].includes(k)))
                throw new Error("Invalid message structure");

            const key = await CryptoHelper.keyFromUint(CryptoHelper.enc.StringToUint(room.secret, "base64"));
            const iv = crypto.getRandomValues(new Uint8Array(32));
            const cipherText = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, CryptoHelper.enc.StringToUint(JSON.stringify(message)))
                .then(data => { return `${CryptoHelper.enc.UintToString(iv, "base64")}.${CryptoHelper.enc.UintToString(data, "base64")}`; })
                .catch(err => { throw err; });

            // create signature
            const idenKeyPriv = await crypto.subtle.importKey("pkcs8", CryptoHelper.enc.StringToUint(this.#client.user.public.idenKey.private, "base64"), { name: "ECDSA", namedCurve: "P-521" }, false, ["sign"]);
            const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-512" }, idenKeyPriv, CryptoHelper.enc.StringToUint(cipherText))
                .then(data => { return CryptoHelper.enc.UintToString(data, "base64") });

            const r = await fetch(this.#client.domain + APIEndpoints.rooms.message.replace(":roomId", room.roomId), {
                method: "POST",
                headers: { "Authorization": this.#client.user.accessToken, "Content-Type": "application/json" },
                body: JSON.stringify({ cipherText, signature })
            });

            if (!r.ok)
                throw new Error("Non-ok response from server");

            return r.json() as Promise<{ status: string; message: NerdRawMessage }>;
        }
        catch (err) {
            console.error(err);
            console.log(`Failed to send message to room ${roomId}`);
            return null;
        }
    }

    async loadMessages(roomId: string, options?: { before?: number, after?: number }) {
        try {
            const room = this.get(roomId);
            if (!room) return;

            const destination = new URL(this.#client.domain + APIEndpoints.rooms.messages.replace(":roomId", room.roomId));
            if (options?.before) destination.searchParams.append("before", options.before.toString());
            if (options?.after) destination.searchParams.append("after", options.after.toString());

            // load messages
            const r = await fetch(destination.toString(), {
                headers: { Authorization: this.#client.user.accessToken },
            })
                .then(r => { return r; })
                .catch(err => {
                    console.error(err);
                    console.log(`Couldn't load messages for room ${roomId}`);
                });

            if (!r) return;

            const data: { messages: NerdRawMessage[] } = await r.json();

            // load users
            let fetches: Array<Promise<NerdPublicUser>> = [];
            for (const userId of data.messages.map(m => m.authorId).filter((value, index, self) =>
                index === self.findIndex(t => t === value)
            )) {
                fetches.push(this.#client.userStore.fetchUser(userId))
            }
            await Promise.all(fetches);

            // decrypt messages
            const key = await CryptoHelper.keyFromUint(CryptoHelper.enc.StringToUint(room.secret, "base64"));

            for (const message of data.messages) {
                if (room.messages.find(m => m.messageId === message.messageId)) continue;
                const author = await this.#client.userStore.fetchUser(message.authorId);
                await NerdUtils.decodeRawMessage(room, message, author, key, true);
            }

            room.messages = room.messages.sort((a, b) => a.createdAt - b.createdAt);
            room.messages = room.messages.filter((value, index, self) => self.findIndex(m => m.messageId === value.messageId) === index);
            return data.messages.length;
        } catch (err) {
            console.error(err);
            console.log(`Failed to load messages for ${roomId}`);
        }
    }

    async sync() {
        try {
            // get the rooms
            const roomsData = await fetch(this.#client.domain + APIEndpoints.rooms.sync, {
                headers: { "Authorization": this.#client.user.accessToken }
            })
                .then(r => { return r.json() as Promise<{ secrets: { roomSecret: string, roomId: string }[], rooms: NerdRoom[] }>; })
                .catch(err => {
                    console.error(err);
                    console.log("Couldn't fetch rooms");
                })

            if (!roomsData) return;

            const combinedArray: Array<NerdRoom> = [];
            for (const { roomSecret: secret, roomId: id } of roomsData.secrets) {
                const room = roomsData.rooms.find(x => x.roomId === id);
                room.messages = [];

                const masterKey = this.#client.getMasterKey();

                // decrypt secret
                const [iv, encryptedSecret] = secret.split(".");
                const decryptedSecret = await crypto.subtle.decrypt({ name: "AES-GCM", iv: CryptoHelper.enc.StringToUint(iv, "base64") },
                    masterKey, CryptoHelper.enc.StringToUint(encryptedSecret, "base64"))
                    .then(data => { return CryptoHelper.enc.UintToString(data, "base64"); })
                    .catch((err) => { console.log(`Failed to decrypt secret of room ${id}`, err); });
                if (!decryptedSecret) continue;

                combinedArray.push(Object.assign({}, { secret: decryptedSecret }, room));
            }

            // combine the secrets and room datas into a map
            const combined = new Map<string, NerdRoom>(combinedArray.map(x => [x.roomId, x]));

            this.#rooms = combined;

            window.dispatchEvent(new CustomEvent("nerdlock.roomSync"));
            return true;
        } catch (err) {
            console.error(err);
            console.log("Failed to sync rooms");
            return false;
        }
    }

    async inviteUser(roomId: string, userId: string) {
        try {
            const room = this.#rooms.get(roomId);
            if (!room) return;

            const r = await fetch(this.#client.domain + APIEndpoints.rooms.invite.replace(":roomId", room.roomId).replace(":userId", userId), {
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": this.#client.user.accessToken },
            });

            if (!r.ok)
                throw new Error(`Server did not respond with an ok status when inviting ${userId}`);

            const inviteData = JSON.stringify({ roomSecret: room.secret, roomName: room.name, roomId: room.roomId });
            return this.#client.userSecrets.sendSecretMessage(userId, { type: "roomInvite", data: inviteData });
        } catch (err) {
            console.error(err);
            console.log(`Couldn't create invite for room ${roomId}`);
            return false;
        }
    }

    async joinRoom(roomId: string) {
        try {
            const r = await fetch(this.#client.domain + APIEndpoints.rooms.join.replace(":roomId", roomId), {
                headers: { "Authorization": this.#client.user.accessToken }
            });

            if (!r.ok)
                throw new Error("Server didn't respond with an ok status when joining room");

            await this.sync();
            return true;
        } catch (err) {
            console.error(err);
            console.log(`Couldn't join room ${roomId}`);
            return false;
        }
    }
}

/**
 * Class for managing user secrets
 */
class UserSecretManager {
    #client: NerdClient;
    #secrets: Map<string, string>;
    #requests: Array<NerdSecretRequest>;
    #messages: Array<NerdSecretMessage>;

    constructor(client: NerdClient, secretReqs?: Array<NerdSecretRequest>, secretMessages?: Array<NerdSecretMessage>) {
        this.#client = client;
        this.#requests = secretReqs || [];
        this.#secrets = new Map<string, string>();
        this.#messages = secretMessages || [];
        for (const request of this.#requests) {
            this.addSecretRequest(request);
        }
        this.#processMessages();
    }

    /**
     * Private function for performing an X3DH protocol run with the user id provided
     * @param userId id of the user
     */
    async #deriveUserSecret(userId: string) {
        try {
            const r = await fetch(this.#client.domain + APIEndpoints.users.x3dh.replace(":userId", userId), {
                headers: { "Authorization": this.#client.user.accessToken }
            });

            if (!r.ok)
                throw new Error("Server didn't respond with an ok status while requesting public keys");

            const publicInfo = await r.json() as NerdUserX3DHData;

            // step 1: verify prekey
            const signIdenKey = await crypto.subtle.importKey("raw", CryptoHelper.enc.StringToUint(publicInfo.idenKey.public, "base64"), { name: "ECDSA", namedCurve: "P-521" }, false, ["verify"]);
            if (!await crypto.subtle.verify(
                { name: "ECDSA", hash: "SHA-512" },
                signIdenKey,
                CryptoHelper.enc.StringToUint(publicInfo.preKey.sign, "base64"),
                CryptoHelper.enc.StringToUint(publicInfo.preKey.public, "base64")
            )) throw new Error("Prekey signature verification failed, aborting...");

            // step 2: generate ephemeral key and set up keys
            const ephemeralKey = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveBits"]);

            const idenKey = await crypto.subtle.importKey("raw",
                CryptoHelper.enc.StringToUint(publicInfo.idenKey.public, "base64"),
                { name: "ECDH", namedCurve: "P-521" }, false, []);
            const ourIdenKey = await crypto.subtle.importKey("pkcs8",
                CryptoHelper.enc.StringToUint(this.#client.user.public.idenKey.private, "base64"),
                { name: "ECDH", namedCurve: "P-521" }, false, ["deriveBits"]);
            const preKey = await crypto.subtle.importKey("raw",
                CryptoHelper.enc.StringToUint(publicInfo.preKey.public, "base64"),
                { name: "ECDH", namedCurve: "P-521" }, false, []);
            const otKey = publicInfo.otKey ? await crypto.subtle.importKey("raw",
                CryptoHelper.enc.StringToUint(publicInfo.otKey.public, "base64"),
                { name: "ECDH", namedCurve: "P-521" }, false, []) : null;

            const DH1 = await crypto.subtle.deriveBits({ name: "ECDH", public: preKey }, ourIdenKey, 512);
            const DH2 = await crypto.subtle.deriveBits({ name: "ECDH", public: idenKey }, ephemeralKey.privateKey, 512);
            const DH3 = await crypto.subtle.deriveBits({ name: "ECDH", public: preKey }, ephemeralKey.privateKey, 512);
            const DH4 = otKey ? await crypto.subtle.deriveBits({ name: "ECDH", public: otKey }, ephemeralKey.privateKey, 512) : null;

            // time to put them all together
            const keyData = NerdUtils.joinUint(DH1, DH2, DH3, DH4);

            const secretKey = await crypto.subtle.importKey("raw", keyData, { name: "HKDF" }, false, ["deriveKey"]);
            const secretSalt = crypto.getRandomValues(new Uint8Array(64));
            const secret = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-512", salt: secretSalt, info: new TextEncoder().encode("Nerdlock :)") }, secretKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

            const preMessageRaw = {
                userId: this.#client.user.userId,
                identity: this.#client.user.public.idenKey.public
            }

            const iv = crypto.getRandomValues(new Uint8Array(32));
            const preMessage = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, secret, new TextEncoder().encode(JSON.stringify(preMessageRaw)))
                .then(data => { return `${CryptoHelper.enc.UintToString(secretSalt, "base64")}.${CryptoHelper.enc.UintToString(iv, "base64")}.${CryptoHelper.enc.UintToString(data, "base64")}` });
            const ephKeyString = CryptoHelper.enc.UintToString(await crypto.subtle.exportKey("raw", ephemeralKey.publicKey), "base64");

            // send request to server
            const r2 = await fetch(this.#client.domain + APIEndpoints.users.secretRequest.replace(":userId", userId), {
                method: "POST",
                headers: { "Authorization": this.#client.user.accessToken, "Content-Type": "application/json" },
                body: JSON.stringify({ ephKey: ephKeyString, preMessage, idenKey: this.#client.user.public.idenKey.public, otKeyId: publicInfo.otKey?.id ?? undefined })
            });

            if (!r2.ok)
                throw new Error("Server didn't respond with an ok status when sending back X3DH message");

            // save secret
            const secretString = CryptoHelper.enc.UintToString(await crypto.subtle.exportKey("raw", secret), "base64")
            this.#secrets.set(userId, secretString);
        } catch (err) {
            console.error(err);
            if (err instanceof DOMException) {
                return console.log("Error with SubtleCrypto :(");
            }
            console.log(`Failed to derive user secret with ${userId}`);
        }
    }

    async #acceptSecretRequest(request: NerdSecretRequest) {
        try {
            // set up keys
            const idenKey = await crypto.subtle.importKey("raw",
                CryptoHelper.enc.StringToUint(request.identityKey, "base64"),
                { name: "ECDH", namedCurve: "P-521" }, false, []);
            const ephKey = await crypto.subtle.importKey("raw",
                CryptoHelper.enc.StringToUint(request.ephemeralKey, "base64"),
                { name: "ECDH", namedCurve: "P-521" }, false, []);
            const ourIdenKey = await crypto.subtle.importKey("pkcs8",
                CryptoHelper.enc.StringToUint(this.#client.user.public.idenKey.private, "base64"),
                { name: "ECDH", namedCurve: "P-521" }, false, ["deriveBits"]);
            const preKey = await crypto.subtle.importKey("pkcs8",
                CryptoHelper.enc.StringToUint(this.#client.user.public.preKey.private, "base64"),
                { name: "ECDH", namedCurve: "P-521" }, false, ["deriveBits"]);
            const otKey = request.otKeyId ? await crypto.subtle.importKey("pkcs8",
                CryptoHelper.enc.StringToUint(this.#client.user.public.oneTimeKeys.find(key => key.id === request.otKeyId).private, "base64"),
                { name: "ECDH", namedCurve: "P-521" }, false, ["deriveBits"]) : null;

            // perform Diffie Hellmann
            const DH1 = await crypto.subtle.deriveBits({ name: "ECDH", public: idenKey }, preKey, 512);
            const DH2 = await crypto.subtle.deriveBits({ name: "ECDH", public: ephKey }, ourIdenKey, 512);
            const DH3 = await crypto.subtle.deriveBits({ name: "ECDH", public: ephKey }, preKey, 512);
            const DH4 = otKey ? await crypto.subtle.deriveBits({ name: "ECDH", public: ephKey }, otKey, 512) : null;

            // put the keys together and derive with HKDF
            const keyData = NerdUtils.joinUint(DH1, DH2, DH3, DH4);

            const secretKey = await crypto.subtle.importKey("raw", keyData, { name: "HKDF" }, false, ["deriveKey"]);
            const [secretSalt, iv, cipherText] = request.preMessage.split(".").map(c => CryptoHelper.enc.StringToUint(c, "base64"));
            const secret = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-512", salt: secretSalt, info: new TextEncoder().encode("Nerdlock :)") }, secretKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

            const preMessage = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, secret, cipherText)
                .then(data => {
                    try {
                        return JSON.parse(CryptoHelper.enc.UintToString(data)) as { userId: string; identity: string; };
                    } catch (err) {
                        throw err;
                    }
                });

            const secretString = CryptoHelper.enc.UintToString(await crypto.subtle.exportKey("raw", secret), "base64");
            if (preMessage.identity !== request.identityKey) {
                alert("Security error detected in one of the secret requests, check console for more details");
                console.warn(`Original request data: ${{ userId: request.from, identity: request.identityKey }}`);
                console.warn(`Premessage: ${preMessage}`);
                throw new Error("Data in premessage does not match request (possible MITM attack)");
            }

            this.#secrets.set(request.from, secretString);

            this.#processMessages();
        } catch (err) {
            console.error(err);
            if (err instanceof DOMException) {
                return console.log("Error with SubtleCrypto :(");
            }
            console.log(`Failed to accept user secret from ${request.from}`);
            throw err;
        }
    }

    addSecretRequest(request: NerdSecretRequest) {
        this.#acceptSecretRequest(request);
    }

    addSecretMessage(message: NerdSecretMessage) {
        this.#messages.push(message);
        this.#decodeSecretMessage(message);
    }

    async sendSecretMessage(userId: string, messageObj: { type: NerdSecretMessageType, data: string }) {
        try {
            let userSecret = this.#secrets.get(userId);
            if (!userSecret) {
                await this.#deriveUserSecret(userId);
                userSecret = this.#secrets.get(userId);
            }

            const message = JSON.stringify(messageObj);

            const secretKey = await CryptoHelper.keyFromUint(CryptoHelper.enc.StringToUint(userSecret, "base64"));

            const iv = crypto.getRandomValues(new Uint8Array(32));
            const messageEnc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, secretKey, CryptoHelper.enc.StringToUint(message))
                .then(data => { return `${CryptoHelper.enc.UintToString(iv, "base64")}.${CryptoHelper.enc.UintToString(data, "base64")}`; });

            const r = await fetch(this.#client.domain + APIEndpoints.users.secretMessage.replace(":userId", userId), {
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": this.#client.user.accessToken },
                body: JSON.stringify({ message: messageEnc })
            });

            if (!r.ok)
                throw new Error("Non-ok response from server");

            return true;
        }
        catch (err) {
            console.error(err);
            console.log(`Failed to send secret message to user ${userId}`);
            return false;
        }
    }

    async #decodeSecretMessage(message: NerdSecretMessage) {
        try {
            const userSecret = this.#secrets.get(message.from);
            if (!userSecret)
                return console.warn("No user secret with message's owner was not found, waiting for secret...");

            const secretKey = await CryptoHelper.keyFromUint(CryptoHelper.enc.StringToUint(userSecret, "base64"));

            const [iv, cipherText] = message.message.split(".");
            const messageDecoded = await crypto.subtle.decrypt({ name: "AES-GCM", iv: CryptoHelper.enc.StringToUint(iv, "base64") }, secretKey, CryptoHelper.enc.StringToUint(cipherText, "base64"))
                .then(data => { return JSON.parse(CryptoHelper.enc.UintToString(data)) as { type: NerdSecretMessageType; data: string; } });

            switch (messageDecoded.type) {
                case "roomInvite": {
                    const data = JSON.parse(messageDecoded.data) as { roomId: string, roomSecret: string, roomName: string; };

                    const user = await this.#client.userStore.fetchUser(message.from);

                    NerdUtils.waitForFocus().then(async () => {
                        if (prompt(`${user.username} has invited you to ${data.roomName}. Type "yes" to join`) !== "yes") return;

                        const masterKey = this.#client.getMasterKey();

                        // encrypt room secret with masterkey
                        const iv = crypto.getRandomValues(new Uint8Array(32));
                        const roomSecretEnc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, CryptoHelper.enc.StringToUint(data.roomSecret, "base64"))
                            .then(data => { return `${CryptoHelper.enc.UintToString(iv, "base64")}.${CryptoHelper.enc.UintToString(data, "base64")}` });

                        const r = await fetch(this.#client.domain + APIEndpoints.users.root, {
                            method: "PATCH",
                            headers: { "Content-Type": "application/json", "Authorization": this.#client.user.accessToken },
                            body: JSON.stringify({ rooms: [{ roomId: data.roomId, roomSecret: roomSecretEnc }] })
                        });

                        if (!r.ok)
                            throw new Error(`Failed to save room secret for room ${data.roomId}`);

                        this.#client.rooms.joinRoom(data.roomId);

                        this.#client.rooms.sync();
                    });
                    break;
                }
            }

            return true;
        } catch (err) {
            console.error(err);
            console.log(`Failed to decode secret message`);
        }
    }

    async #processMessages() {
        for (const message of this.#messages) {
            if (await this.#decodeSecretMessage(message))
                this.#messages.splice(this.#messages.indexOf(message), 1);
        }
    }
}

/**
 * Class for storing users
 */
class UserStore {
    #users: Map<string, NerdPublicUser>;
    #client: NerdClient;

    constructor(client: NerdClient) {
        this.#client = client;
        this.#users = new Map();
    }

    async fetchUser(userId: string, force: boolean = false) {
        if (this.#users.has(userId) && !force) return this.#users.get(userId);
        try {
            const r = await fetch(this.#client.domain + APIEndpoints.users.info.replace(":userId", userId), {
                headers: { "Authorization": this.#client.user.accessToken }
            });

            if (!r.ok) throw new Error("Non-ok response from server");

            const user = await r.json() as NerdPublicUser;

            const identityKey = await crypto.subtle.importKey("raw", CryptoHelper.enc.StringToUint(user.identity, "base64"), { name: "ECDSA", namedCurve: "P-521" }, false, ["verify"]);
            user.identityKey = identityKey;

            this.#users.set(userId, user);

            return user;
        } catch (err) {
            console.error(err);
            console.log(`Couldn't fetch user ${userId}`);
            return null;
        }
    }

    updateUser(userId: string, newUser: { online?: boolean }) {
        const user = this.#users.get(userId);
        if (!user) return;

        if (newUser.online) user.online = newUser.online;

        window.dispatchEvent(new CustomEvent("nerdlock.userSync"));
    }
}

/**
 * Static function for creating a NerdLock client
 * @param domain The domain name of the g
 */
async function createClient(domain: string) {
    try {
        // validate domain
        const serverUrl = new URL(domain);

        // use serverUrl.origin to ignore unnecessary stuff
        const serverInfo = await fetch(serverUrl.origin + APIEndpoints.info)
            .then(r => { return r.json(); })
            .catch(err => {
                console.log(err);
                throw new Error("Couldn't fetch NerdLock server info (perhaps a bad domain or host is down)")
            });

        if (!serverInfo.version || !acceptVersions.includes(serverInfo.version)) {
            throw new Error("Couldn't verify NerdLock server version (it either doesn't exist or it's not allowed by the client)");
        }

        const client = new NerdClient(serverUrl.origin);

        return client;
    } catch (err) {
        console.error(err);
        return null;
    }
}

export default NerdClient;