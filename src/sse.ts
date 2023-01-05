import { Request, Response } from "express";
import Room from "./database/Room.js";
import { NerdUser } from "./types.js";

interface sseData {
    req: Request;
    res: Response;
    user: NerdUser;
}

export const sseSessions = new Map<string, sseData[]>();

export default async function register(req: Request, res: Response) {
    // set up SSE
    res.set({
        "Cache-Control": "no-cache",
        "Content-Type": "text/event-stream",
        "Connection": "keep-alive"
    });
    res.flushHeaders();

    res.write("retry: 1000\n\n");

    res.write(`:Welcome to Nerdlock, ${req.lockUser.username}!\n\n`);

    if (!sseSessions.has(req.lockUser.userId))
        sseSessions.set(req.lockUser.userId, []);

    sseSessions.get(req.lockUser.userId).push({ req, res, user: req.lockUser });

    const heartBeat = setInterval(() => {
        res.write(":\n\n");
    }, 30_000);

    res.once("close", () => {
        const sessions = sseSessions.get(req.lockUser.userId);
        sessions.splice(sessions.findIndex(x => x.req.reqId === req.reqId), 1);

        if (sessions.length === 0) {
            sseSessions.delete(req.lockUser.userId);
            updatePresence(req, false);
        }

        clearInterval(heartBeat);
    });

    updatePresence(req, true);
}

async function updatePresence(req: Request, online: boolean) {
    const memberIds: string[] = [];
    for (const room of (await Room.find({ members: { $elemMatch: { memberId: req.lockUser.userId } } }))) {
        memberIds.push(...room.members.map(m => m.memberId));
    }

    const filteredIds: string[] = [];
    for (const memberId of memberIds.filter((value, index, self) =>
        index === self.findIndex(t => t === value)
    )) {
        filteredIds.push(memberId);
    }

    for (const memberId of filteredIds) {
        if (!sseSessions.has(memberId)) continue;
        for (const session of sseSessions.get(memberId)) {
            session.res.write("event: userPresence\n");
            session.res.write(`data: ${JSON.stringify({ userId: req.lockUser.userId, online })}\n\n`);
        }
    }
}