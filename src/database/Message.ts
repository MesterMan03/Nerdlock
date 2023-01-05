import mongoose, { Document, Schema, SchemaTypes } from "mongoose";
import { NerdMessage } from "../types.js";

export interface INerdMessage extends NerdMessage, Document { }

export default mongoose.model("Message", new Schema<INerdMessage>({
    roomId: {
        type: SchemaTypes.String,
        required: true
    },
    messageId: {
        type: SchemaTypes.String,
        required: true
    },
    authorId: {
        type: SchemaTypes.String,
        required: true
    },
    cipherText: {
        type: SchemaTypes.String,
        required: true
    },
    signature: {
        type: SchemaTypes.String,
        required: true
    },
    createdAt: {
        type: SchemaTypes.Number,
        required: true
    },
    lastModifiedAt: {
        type: SchemaTypes.Number,
        required: true  
    }
}))