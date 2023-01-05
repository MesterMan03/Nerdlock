import { NerdUser } from "../src/types.js";

declare global {
    namespace Express {
        export interface Request {
            lockUser: NerdUser;
            reqId: string;
        }
    }
}

export { };
