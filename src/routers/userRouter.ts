import { pbkdf2Sync, randomBytes, randomUUID, timingSafeEqual } from "crypto";
import { Router } from "express";
import { AttestationResult } from "fido2-lib";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import yup from "yup";
import MFA from "../database/MFA.js";
import User from "../database/User.js";
import { nerdServer } from "../index.js";
import { sseSessions } from "../sse.js";
import { NerdSecretRequest, NerdUserSecretMessage } from "../types.js";
import { authUser, generateAccessToken, sanitizeUser, verifyReq } from "../utils.js";
import rateLimit from "express-rate-limit";

const router = Router();

router.get("/:userId", rateLimit({
    windowMs: 60000,
    max: 60,
    standardHeaders: true
}), authUser, async (req, res) => {
    try {
        req.lockUser.rooms = undefined;
        if (req.params.userId === "me")
            return res.json(req.lockUser);

        let finalUser: { username?: string; userId: string; online?: boolean; identity?: string; } = {
            userId: req.params.userId
        };

        const user = await User.findOne({ userId: req.params.userId });
        if (!user) {
            finalUser.username = "Deleted Account";
        } else {
            finalUser.username = user.username;
            finalUser.online = sseSessions.has(req.params.userId);
            finalUser.identity = user.public.idenKey.public;
        }

        res.json(finalUser);
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
});

const userPatchSchema = yup.object({
    body: yup.object({
        oneTimeKeys: yup.array().of(yup.object({
            private: yup.string().required(),
            public: yup.string().required(),
            id: yup.number().integer().min(0).max(50).required()
        })).notRequired(),
        preKey: yup.object({
            private: yup.string(),
            public: yup.string(),
            id: yup.number().integer().min(0).max(50),
            expiration: yup.number().integer()
        }).notRequired(),
        rooms: yup.array().of(yup.object({
            roomId: yup.string().required(),
            roomSecret: yup.string().required()
        })).notRequired()
    })
})
router.patch("/", rateLimit({
    windowMs: 60000,
    max: 5,
    standardHeaders: true
}), authUser, verifyReq(userPatchSchema), async (req, res) => {
    const user = await User.findOne({ userId: req.lockUser.userId });

    try {
        if (req.body.oneTimeKeys) user.public.oneTimeKeys = req.body.oneTimeKeys;
        if (req.body.preKey) user.public.preKey = req.body.preKey;
        if (req.body.rooms) user.rooms.push(...req.body.rooms);

        await user.save();

        res.json({ status: "ok" });
    } catch (err) {
        return res.sendStatus(500);
    }
});

router.get("/:userId/x3dh", rateLimit({
    windowMs: 60000,
    max: 5,
    standardHeaders: true
}), authUser, async (req, res) => {
    const userId = req.params.userId;
    const user = await User.findOne({ userId });
    if (!user) return res.sendStatus(404);

    // get one of the one time keys
    const index = randomBytes(1).readUint8() % user.public.oneTimeKeys.length;
    const otKey = user.public.oneTimeKeys.splice(index, 1)[0];

    if (otKey && !sseSessions.get(user.userId))
        user.usedOneTimeKeys.push({ id: otKey.id, private: otKey.private });

    await user.save();

    otKey.private = undefined;

    const finalUser = Object.assign({}, user.public, { username: user.username, userId: user.userId, otKey: otKey });
    finalUser.idenKey.private = finalUser.preKey.private = finalUser.oneTimeKeys = undefined;

    res.json(finalUser);
});

const secretReqSchema = yup.object({
    body: yup.object({
        idenKey: yup.string().required(),
        ephKey: yup.string().required(),
        preMessage: yup.string().required(),
        otKeyId: yup.number().min(0).max(100).integer()
    })
})
router.post("/:userId/secretRequest", rateLimit({
    windowMs: 60000,
    max: 5,
    standardHeaders: true
}), authUser, verifyReq(secretReqSchema), async (req, res) => {
    const from = req.lockUser.userId;
    const to = req.params.userId;

    const user = await User.findOne({ userId: to });

    if (!user)
        return res.status(403).send({ error: "User was not found" });

    const request: NerdSecretRequest = {
        from,
        ephemeralKey: req.body.ephKey,
        preMessage: req.body.preMessage,
        identityKey: req.body.idenKey,
        otKeyId: req.body.otKeyId,
        id: randomUUID()
    }

    // if the user is connected to the server, just send it directly, without saving it
    const sessions = sseSessions.get(to);
    if (sessions) {
        for (const session of sessions) {
            session.res.write("event: secretRequest\n");
            session.res.write(`data: ${JSON.stringify(request)}\n\n`)
        }
    }
    else {
        user.secretRequests.push(request);
        await user.save();
    }

    res.json({ status: "ok" });
});

const secretMessageSchema = yup.object({
    body: yup.object({
        message: yup.string().required()
    })
})
router.post("/:userId/secretMessage", rateLimit({
    windowMs: 60000,
    max: 5,
    standardHeaders: true
}), authUser, verifyReq(secretMessageSchema), async (req, res) => {
    const user = await User.findOne({ userId: req.params.userId });
    if (!user)
        return res.status(404).json({ error: "User was not found" });

    const message: NerdUserSecretMessage = {
        from: req.lockUser.userId,
        message: req.body.message
    }

    const sessions = sseSessions.get(user.userId);
    if (sessions) {
        for (const session of sessions) {
            session.res.write("event: secretMessage\n");
            session.res.write(`data: ${JSON.stringify(message)}\n\n`);
        }
    } else {
        user.secretMessages.push(message);
        await user.save();
    }

    res.json({ status: "ok" });
})

const loginSchema = yup.object({
    body: yup.object({
        username: yup.string().required(),
        password: yup.string().required(),
        opt: yup.object({
            totp: yup.number().integer().notRequired()
        }).notRequired()
    })
})
router.post("/login", rateLimit({
    windowMs: 60000,
    max: 2,
    standardHeaders: true
}), verifyReq(loginSchema), async (req, res) => {
    const username = String(req.body.username);
    const password = String(req.body.password);

    const user = await User.findOne({ username });

    if (!user) return res.status(404).send({ error: "User doesn't exist" });

    const mfa = await MFA.findOne({ userId: user.userId });
    if (mfa) {
        if (mfa.totp.enabled && !req.body.opt?.totp)
            return res.status(401).send({ error: "TOTP code not provided" });

        if (mfa.totp.enabled && !authenticator.verify({ token: req.body.opt.totp, secret: mfa.totp.secret }))
            return res.status(401).send({ error: "TOTP code invalid" });
    }

    const hashedPass = pbkdf2Sync(password, Buffer.from(user.salt, "base64"), 1_000_000, 64, "sha3-512");

    if (!timingSafeEqual(Buffer.from(user.password, "base64"), hashedPass))
        return res.sendStatus(401);

    if (!user.accessToken) {
        user.accessToken = generateAccessToken(user.userId);
        await user.save();
    }

    res.json(await sanitizeUser(user));

    user.usedOneTimeKeys = user.secretMessages = user.secretRequests = [];
    await user.save();
});

const registerSchema = yup.object({
    body: yup.object({
        username: yup.string().required().min(4).max(24),
        password: yup.string().required().length(88),
        opt: yup.object({
            mastKey: yup.string().required(),
            idenKey: yup.object({
                private: yup.string().required(),
                public: yup.string().required()
            }),
            preKey: yup.object({
                private: yup.string().required(),
                public: yup.string().required(),
                sign: yup.string().required(),
                expiration: yup.number().integer().required()
            }),
            oneTimeKeys: yup.array().of(yup.object({
                id: yup.number().required().integer().min(0).max(50),
                private: yup.string().required(),
                public: yup.string().required()
            }))
        })
    })
})
router.post("/register", rateLimit({
    windowMs: 60000,
    max: 2,
    standardHeaders: true
}), verifyReq(registerSchema), async (req, res) => {
    if (!nerdServer.config.allowReg)
        return res.status(405).json({ error: "Registering is disabled on this server" });

    const username = String(req.body.username);
    const password = String(req.body.password);
    const opt = req.body.opt as {
        mastKey: string;
        idenKey: { private: string; public: string; };
        preKey: { private: string; public: string; sign: string; };
        oneTimeKeys: { id: number; private: string; public: string; }[]
    }

    // check if user exists
    if (await User.findOne({ username })) {
        res.status(400).send({ error: "User already exists" });
        return;
    }

    // generate salt and password
    const salt = randomBytes(64);
    const hashedPass = pbkdf2Sync(password, salt, 1_000_000, 64, "sha3-512").toString("base64");

    const id = nerdServer.snowflake.getUniqueID().toString();

    // generate access token
    const accessToken = generateAccessToken(id);

    try {
        // save user
        const user = await User.create({
            accessToken,
            password: hashedPass,
            salt: salt.toString("base64"),
            username,
            userId: id,
            masterKey: opt.mastKey,
            public: {
                idenKey: opt.idenKey,
                preKey: opt.preKey,
                oneTimeKeys: opt.oneTimeKeys
            }
        });

        res.send(await sanitizeUser(user));
    } catch (err) {
        return res.sendStatus(400);
    }
});

const totpRegisterSchema = yup.object({
    body: yup.object({
        challenge: yup.string().notRequired()
    })
})
router.post("/mfa/totp", rateLimit({
    windowMs: 60000,
    max: 2,
    standardHeaders: true
}), authUser, verifyReq(totpRegisterSchema), async (req, res) => {
    try {
        let mfa = await MFA.findOne({ userId: req.lockUser.userId });
        if (!mfa) mfa = await MFA.create({ userId: req.lockUser.userId });
        else if (mfa.totp.enabled) return res.status(403).send({ error: "TOTP has already been enabled" });

        const challenge = req.body.challenge as string;

        if (!challenge) {
            const secret = authenticator.generateSecret();
            const keyUri = authenticator.keyuri(req.lockUser.username, "Nerdlock", secret);

            QRCode.toDataURL(keyUri, (err, uri) => {
                if (err) throw err;

                res.send({ challenge: uri });
            })

            mfa.totp.secret = secret;
            await mfa.save();
        } else {
            if (!mfa.totp.secret)
                return res.status(403).send({ error: "TOTP was not registered yet" });

            if (!authenticator.verify({ token: challenge, secret: mfa.totp.secret }))
                return res.status(401).send({ error: "Incorrect TOTP challenge" });

            mfa.mfaEnabled = true;
            mfa.totp.enabled = true;
            await mfa.save();

            res.send({ status: "ok" });
        }
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
});

router.get("/mfa/regU2F", rateLimit({
    windowMs: 60000,
    max: 1,
    standardHeaders: true
}), authUser, async (req, res) => {
    return res.status(501).send({ error: "Under development" });
    try {
        let mfa = await MFA.findOne({ userId: req.lockUser.userId });
        if (!mfa) mfa = await MFA.create({ userId: req.lockUser.userId });
        else if (mfa.u2f.enabled) return res.status(403).send({ error: "U2F has already been enabled" });

        const registrationOptions = await nerdServer.f2l.attestationOptions();
        registrationOptions.user = {
            id: randomUUID(),
            name: req.lockUser.username,
            displayName: req.lockUser.username
        }

        //@ts-ignore
        registrationOptions.challenge = Buffer.from(registrationOptions.challenge).toString("base64");

        req.session.u2fRegExpectation = {
            challenge: registrationOptions.challenge as any,
            origin: nerdServer.config.origin,
            factor: "either"
        }
        res.send(registrationOptions);
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
});

const u2fRegisterSchema = yup.object({
    body: yup.object({
        rawId: yup.string().required(),
        response: yup.object({
            clientDataJSON: yup.string().required(),
            attestationObject: yup.string().required()
        }).required()
    })
})
router.post("/mfa/regU2F", rateLimit({
    windowMs: 60000,
    max: 1,
    standardHeaders: true
}), authUser, verifyReq(u2fRegisterSchema), async (req, res) => {
    return res.status(501).send({ error: "Under development" });
    try {
        let mfa = await MFA.findOne({ userId: req.lockUser.userId });
        if (!mfa) mfa = await MFA.create({ userId: req.lockUser.userId });
        else if (mfa.u2f.enabled) return res.status(403).send({ error: "U2F has already been enabled" });

        if (!req.session.u2fRegExpectation)
            return res.status(403).send({ error: "You are not registering U2F right now" });

        nerdServer.f2l.attestationResult({
            //@ts-ignore
            id: Buffer.from(req.body.id, "base64").buffer,
            response: {
                clientDataJSON: Buffer.from(req.body.response.clientDataJSON, "base64").toString("base64url"),
                attestationObject: Buffer.from(req.body.response.attestationObject, "base64").toString("base64url")
            }
        }, req.session.u2fRegExpectation)
            .then((result) => {
                const key = result.clientData.get("credentialPublicKeyPem") as string;
                const counter = result.clientData.get("counter") as number;

                console.log(key, counter);
            })
            .catch((err) => {
                console.error(err);
                return res.status(401).send({ error: "Failed to verify U2F attestation" });
            })
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
})

export default router;