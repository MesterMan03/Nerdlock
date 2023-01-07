import { Router } from "express";
import { FilterQuery } from "mongoose";
import * as yup from "yup";
import Message, { INerdMessage } from "../database/Message.js";
import Room from "../database/Room.js";
import User from "../database/User.js";
import { nerdServer } from "../index.js";
import { sseSessions } from "../sse.js";
import { NerdMessage, NerdRoom, NerdRoomInvite, NerdRoomMember, NerdUserRoomData } from "../types.js";
import { authRoom, authUser, verifyReq } from "../utils.js";
import rateLimit from "express-rate-limit";

const router = Router();

router.use("*", authUser);

router.post("/create", rateLimit({
    windowMs: 60_000,
    max: 5,
    standardHeaders: true
}), async (req, res) => {
    try {
        if (!req.body.name || !req.body.roomSecret) {
            res.sendStatus(400);
            return;
        }

        const roomOptions = {
            name: req.body.name as string,
            roomId: nerdServer.snowflake.getUniqueID().toString()
        };

        const member: NerdRoomMember = {
            memberId: req.lockUser.userId,
            permissions: 1, // create administrator perms
        }

        // create room
        await Room.create({
            name: roomOptions.name,
            roomId: roomOptions.roomId,
            members: [member]
        });

        // save room secret to user
        await User.findOneAndUpdate({ userId: req.lockUser.userId }, {
            $push: {
                rooms: {
                    roomId: roomOptions.roomId,
                    roomSecret: req.body.roomSecret
                }
            }
        });

        // send the room's id back
        res.json({ status: "ok", roomid: roomOptions.roomId });
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
});

router.get("/sync", rateLimit({
    windowMs: 60_000,
    max: 10,
    standardHeaders: true
}), authUser, async (req, res) => {
    const user = await User.findOne({ userId: req.lockUser.userId });

    // get all rooms the user is in
    // this is unfortunately really messy, but I couldn't find a better way
    const rooms = new Array<NerdRoom>();
    const secrets = new Array<NerdUserRoomData>();
    for (const rawRoom of user.rooms) {
        const room = await Room.findOne({ roomId: rawRoom.roomId }, { _id: 0, __v: 0 });
        if (!room) continue;

        const roomObject = room.toObject<NerdRoom>();
        delete roomObject._id;

        const ourMember = roomObject.members.find(m => m.memberId === user.userId);
        if (!ourMember) // wtf
            continue;

        for (const member of roomObject.members.filter(m => m.memberId !== ourMember.memberId)) {
            // hide details about other members (unless the user has permission)
            if (ourMember.permissions === 1) continue;
            member.permissions = undefined;
        }

        rooms.push(roomObject);
        secrets.push(rawRoom);
    }

    res.json({ secrets, rooms });
})

const messagesSchema = yup.object({
    query: yup.object({
        before: yup.number().notRequired().integer(),
        after: yup.number().notRequired().integer()
    })
})
router.get("/:roomId/messages", rateLimit({
    windowMs: 60_000,
    max: 20,
    standardHeaders: true
}), authRoom, verifyReq(messagesSchema), async (req, res) => {
    try {
        const roomId = req.params.roomId;

        const before = req.query.before ? Number.parseInt(req.query.before.toString()) : null;
        const after = req.query.after ? Number.parseInt(req.query.after.toString()) : null;

        // this is extremely ugly and I'm sorry
        let filter: FilterQuery<INerdMessage>;
        if (before && after) filter = { roomId, createdAt: { $lt: before, $gt: after } }
        if (before && !after) filter = { roomId, createdAt: { $lt: before } }
        if (!before && after) filter = { roomId, createdAt: { $gt: after } }
        if (!before && !after) filter = { roomId }

        const messages = (await Message.find(filter, { _id: 0, __v: 0 }).sort({ date: 1 })).map(m => m.toObject<NerdMessage>());

        res.json({ messages: messages.slice(-50) });
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
})

const messageSchema = yup.object({
    body: yup.object({
        cipherText: yup.string().required(),
        signature: yup.string().required()
    })
})
router.post("/:roomId/message", rateLimit({
    windowMs: 60_000,
    max: 30,
    standardHeaders: true
}), authRoom, verifyReq(messageSchema), async (req, res) => {
    try {
        const roomId = String(req.params.roomId);
        const cipherText = String(req.body.cipherText);
        const signature = String(req.body.signature);

        const room = await Room.findOne({ roomId });

        const messageId = nerdServer.snowflake.getUniqueID().toString();
        const date = Date.now();

        const messageObj: NerdMessage = {
            messageId,
            roomId,
            authorId: req.lockUser.userId,
            cipherText,
            signature,
            createdAt: date,
            lastModifiedAt: date
        }
        await Message.create(messageObj);

        // send out the message to all currently listening clients
        for (const member of room.members) {
            const sseMembers = sseSessions.get(member.memberId);
            if (!sseMembers) continue;

            for (const m of sseMembers) {
                m.res.write("event: newMessage\n");
                m.res.write(`data: ${JSON.stringify(messageObj)}\n\n`);
            }
        }

        res.json({ status: "ok", message: messageObj });
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
})

const inviteSchema = yup.object({
    params: yup.object({
        userId: yup.string().required().matches(/^\d+$/)
    })
})
router.post("/:roomId/invite/:userId", rateLimit({
    windowMs: 60_000,
    max: 15,
    standardHeaders: true
}), authRoom, verifyReq(inviteSchema), async (req, res) => {
    try {
        const roomId = req.params.roomId;
        const room = await Room.findOne({ roomId });

        const invite: NerdRoomInvite = {
            from: req.lockUser.userId,
            to: req.params.userId.toString()
        }

        room.invites.push(invite);
        await room.save();

        res.json({ status: "ok" });
    } catch (err) {
        console.error(err);
        return res.sendStatus(500);
    }
});

router.get("/join/:roomId", rateLimit({
    windowMs: 60_000,
    max: 10,
    standardHeaders: true
}), async (req, res) => {
    try {
        const room = await Room.findOne({ roomId: req.params.roomId.toString(), invites: { $elemMatch: { to: req.lockUser.userId } } });
        if (!room)
            return res.status(404).json({ error: "Room doesn't exist or you're not invited" });

        if (room.members.find(m => m.memberId === req.lockUser.userId))
            return res.status(403).json({ error: "You are already a member of the room" });

        const member: NerdRoomMember = {
            memberId: req.lockUser.userId,
            permissions: 1
        }

        room.members.push(member);
        room.invites.splice(room.invites.findIndex(i => i.to === req.lockUser.userId), 1);
        await room.save();

        res.json({ status: "ok" });
    } catch (err) {
        console.error(err);
        return res.sendStatus(500);
    }
})

export default router;