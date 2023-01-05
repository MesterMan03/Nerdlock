import mongoose, { Document, SchemaTypes } from "mongoose";
import { NerdRoom } from "../types.js";

export interface IRoom extends NerdRoom, Document { };

export default mongoose.model("Room", new mongoose.Schema<IRoom>({
    name: {
        type: SchemaTypes.String,
        required: true,
    },
    roomId: {
        type: SchemaTypes.String,
        required: true,
    },
    members: {
        type: [{
            permissions: {
                type: SchemaTypes.Number,
                required: true
            },
            memberId: {
                type: SchemaTypes.String,
                required: true
            }
        }],
        _id: false,
        default: []
    },
    invites: {
        type: [{
            from: {
                type: SchemaTypes.String,
                required: true
            },
            to: {
                type: SchemaTypes.String,
                required: true
            }
        }],
        _id: false,
        default: []
    }
}));