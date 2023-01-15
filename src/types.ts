import { ExpectedAttestationResult } from "fido2-lib";

declare module "express-session" {
    interface SessionData {
        u2fRegExpectation: ExpectedAttestationResult
    }
}

export interface ServerConfig {
    port: number;
    dbSecret: string;
    dbUrl: string;
    dbKey: string;
    sslCert: string;
    sslKey: string;
    sslChain: string;
    allowReg: boolean;
    useHttps: boolean;
    origin: string;
}

export interface NerdUser {
    username: string,
    password: string,
    salt: string,
    accessToken: string,
    userId: string,
    masterKey: string,
    public: {
        idenKey: { public: string; private: string; }
        preKey: { public: string; private: string; sign: string; expiration: number; }
        oneTimeKeys: { id: number; private: string; public: string; }[]
    };
    usedOneTimeKeys: { id: number; private: string; }[];
    secretRequests: NerdSecretRequest[];
    secretMessages: NerdUserSecretMessage[];
    rooms: Array<NerdUserRoomData>;
    userSecrets: { userId: string; secret: string; }[];
}

export interface NerdMFA {
    userId: string;
    mfaEnabled: boolean;
    totp: {
        enabled: boolean;
        secret: string;
    };
    u2f: {
        enabled: boolean;
        publicKey: string;
    }
}

export interface NerdUserRoomData {
    roomId: string;
    roomSecret: string; // encrypted room secret that only the user's master password can decrypt and used here as permanent storage
}

export interface NerdRoomMember {
    memberId: string,
    permissions: number,
}

export interface NerdRoomInvite {
    from: string;
    to: string;
}

export interface NerdRoom {
    name: string;
    roomId: string;
    members?: Array<NerdRoomMember>;
    invites: Array<NerdRoomInvite>;
}

export interface NerdMessage {
    roomId: string;
    messageId: string;
    authorId: string;
    content: string;
    attachments: {
        data: string;
        attachmentId: string;
    }[];
    signature: string;
    createdAt: number;
    lastModifiedAt: number;
}

export interface NerdSecretRequest {
    from: string;
    identityKey: string;
    ephemeralKey: string;
    otKeyId: number;
    preMessage: string;
    id: string;
}

export interface NerdUserSecretMessage {
    from: string;
    message: string;
}