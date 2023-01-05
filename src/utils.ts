import { randomBytes } from "crypto";
import { NextFunction, Request, Response } from "express";
import { existsSync } from "fs";
import jwt from "jsonwebtoken";
import yup from "yup";
import MFA from "./database/MFA.js";
import Room from "./database/Room.js";
import User, { INerdUser } from "./database/User.js";
import { nerdServer } from "./index.js";
import { NerdUser, ServerConfig } from "./types.js";
const { sign, verify } = jwt;

export function validateServerConfig(config: ServerConfig) {
    if (!config.dbSecret || !config.dbUrl || !config.port || ((!config.sslCert || !config.sslKey) && config.useHttps) || !config.origin)
        return "Some required settings are not set";

    if (config.useHttps && (!existsSync(config.sslCert) || !existsSync(config.sslKey)))
        return "Some of the files do not exist, please make sure they do or try to use absolute paths";

    if (config.port < 1 || config.port > 65535)
        return "Port is not in an allowed range (1-65535)";

    return null;
}

export async function authUser(req: Request, res: Response, next: NextFunction) {
    if (!req.headers.authorization && !req.query.auth)
        return res.status(401).json({ error: "Missing Authorization parameter" });

    const authHeader = req.headers.authorization || (typeof req.query.auth === "string" ? req.query.auth : req.query.auth[0]);
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Incorrect Authorization parameter format" });

    verify(token, nerdServer.config.dbSecret, async (err: Error, userId: string) => {
        if (err) return res.sendStatus(401);

        // try to find user
        const user = await User.findOne({ userId }, {
            _id: 0,
            __v: 0,
        });
        if (!user) return res.sendStatus(401);

        req.lockUser = await sanitizeUser(user);

        next();
    });
}

export async function authRoom(req: Request, res: Response, next: NextFunction) {
    const roomId = req.params.roomId;

    if (!/^\d+$/.test(roomId))
        return res.status(400).json({ error: "Room ID does not match a valid Snowflake" });

    const room = await Room.findOne({ roomId });
    if (!room)
        return res.status(404).json({ error: "Room was not found!" });

    if (!room.members.find(m => m.memberId === req.lockUser.userId))
        return res.status(403).json({ error: "You are not a member of the room!" });

    next();
}

export function generateAccessToken(id: string) {
    return sign(id, nerdServer.config.dbSecret);
}

export const verifyReq = (schema: yup.ObjectSchema<{ body?: yup.AnySchema, query?: yup.AnySchema, params?: yup.AnySchema }>) => async (req: Request, res: Response, next: NextFunction) => {
    try {
        await schema.validate({
            body: req.body,
            query: req.query,
            params: req.params
        });
        return next();
    } catch (err) {
        return res.status(400).json({ type: err.name, message: err.message })
    }
}

const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
export function generateRandomString(length: number) {
    let string = "";
    for (let i = 0; i < length; i++) {
        string += characters[randomBytes(4).readUint8() % characters.length];
    }
    return string;
}

export async function sanitizeUser(user: INerdUser): Promise<NerdUser & { mfa: { totp: boolean; u2f: boolean; } }> {
    const endUser = user.toObject<NerdUser>({ versionKey: false });
    delete endUser._id;

    endUser.password = endUser.salt = endUser.rooms = undefined;

    const mfa = await MFA.findOne({ userId: endUser.userId });

    return Object.assign({}, endUser, { mfa: { totp: mfa?.totp.enabled ?? false, u2f: mfa?.u2f.enabled ?? false } });
}