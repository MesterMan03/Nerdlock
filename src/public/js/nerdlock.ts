import CryptoHelper from "./CryptoHelper.js";
import NerdClient, { NerdMessage, NerdMessageFile } from "./NerdClient.js";
globalThis.NerdClient = NerdClient;
globalThis.CryptoHelper = CryptoHelper;

let client: NerdClient;
let currentRoom: string;

const dateFormat: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'numeric', day: 'numeric', hour: "numeric", minute: "numeric", second: "numeric" };

const messagesDiv = document.getElementById("messages") as HTMLDivElement;
const roomsDiv = document.getElementById("rooms") as HTMLDivElement;
const messageInput = document.getElementById("messageinput") as HTMLDivElement;
const membersDiv = document.getElementById("members") as HTMLDivElement;
const filesDiv = document.getElementById("files") as HTMLDivElement;
const contextMenu = document.getElementById("contextmenu") as HTMLDivElement;
const messageInfo = document.getElementById("messageinfo") as HTMLTextAreaElement;

let filesToUpload: NerdMessageFile[] = [];
let replyingTo: string;
let loadingRoom: boolean = false;

(document.getElementById("homeserver") as HTMLInputElement).value = location.origin;

document.addEventListener("click", (e) => {
    if (e.target != messageInfo && messageInfo.classList.contains("visible")) {
        return messageInfo.classList.remove("visible");
    }

    //@ts-expect-error
    if (e.target.offsetParent != contextMenu && contextMenu.classList.contains("visible")) {
        return contextMenu.classList.remove("visible");
        contextMenu.style.top = "0px";
        contextMenu.style.left = "0px";
    }
})

document.getElementById("authform").addEventListener("submit", async (event) => {
    event.preventDefault();

    document.getElementById("authform").style.display = "none";

    document.getElementById("userid").innerText = "Loading...";

    const homeServer = (document.getElementById("homeserver") as HTMLInputElement).value;
    const username = (document.getElementById("username") as HTMLInputElement).value;
    const password = (document.getElementById("password") as HTMLInputElement).value;
    const totp = (document.getElementById("totpcode") as HTMLInputElement).value;
    const type = (document.getElementById("authtype") as HTMLSelectElement).value;

    const newClient = type === "login" ? await NerdClient.login(homeServer, username, password, { totp: totp === "" ? undefined : totp }) : await NerdClient.register(homeServer, username, password);
    if (!newClient) {
        document.getElementById("authform").style.display = "flex";
        alert("Failed to authenticate, please check the console");
        return;
    }
    else client = newClient;

    document.getElementById("userid").innerText = `User ID: ${client.user.userId}`;

    document.getElementById("usercontainer").style.display = "none";
    reloadRooms();
});

//#region settings
document.getElementById("enabletotp").addEventListener("click", async () => {
    if (!client) return;

    if (client.user.mfa.totp)
        return alert("You already have TOTP 2FA enabled");

    const { challenge } = await client.totp("register") as { challenge: string };
    if (!challenge) return alert("Failed to request TOTP 2FA qr code");

    const popup = createPopup();

    const img = document.createElement("img");
    img.src = challenge;
    popup.appendChild(img);

    const input = document.createElement("input");
    input.placeholder = "Enter the code here";
    input.title = "Enter the code from your Authenticator";
    input.pattern = "^\d{6}$";
    popup.appendChild(input);

    input.focus();

    input.addEventListener("keydown", async (ev) => {
        if (ev.key !== "Enter") return;

        const result = await client.totp("activate", input.value);
        if (result)
            alert("TOTP 2FA has been enabled!");
        else
            alert("There was an error while trying to enable TOTP 2FA, please check the Console");

        popup.remove();
    })
});

document.getElementById("enableu2f").addEventListener("click", async () => {
    // under development
    return;

    if (!client) return;

    await client.u2f();
})
//#endregion

document.getElementById("createroom").onclick = async () => {
    if (!client) return;

    const name = prompt("Name of room?");
    if (!name || name === "") return;

    await client.rooms.create({ roomName: name });
    reloadRooms();
}

document.getElementById("replyingto").onclick = () => {
    document.getElementById("replyingto").innerText = "";
    replyingTo = null;
}

async function sendMessage() {
    if (!client) return;

    const room = client.rooms.get(currentRoom);
    if (!room) return;

    const content = messageInput.innerText.trim();
    if (content === "" && filesToUpload.length === 0) return;

    const files: NerdMessageFile[] = [];
    loadfiles: for (const f of filesToUpload) {
        if (f.size > 10_000_000) // skip file if it's over 10 mb
            continue;

        if (files.map(f => f.size).reduce((prev, curr) => prev + curr, 0) > 10_000_000) // stop calculating files if total is already over 10 mb
            break loadfiles;

        files.push(f);

        if (files.map(f => f.size).reduce((prev, curr) => prev + curr, 0) > 10_000_000) // remove last file if total is already over 10 mb
            files.pop();
    }

    filesToUpload = [];
    filesDiv.innerText = "";
    messageInput.innerText = "";
    document.getElementById("replyingto").innerText = "";

    client.rooms.sendMessage(room.roomId, { text: content, files, replyingTo });
    replyingTo = null;
}

messageInput.addEventListener("keypress", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
});
document.getElementById("sendmessage").addEventListener("click", (event) => {
    event.preventDefault();
    sendMessage();
});

document.getElementById("messageinput").addEventListener("paste", async (event: ClipboardEvent) => {
    if (event.clipboardData.files.length !== 0)
        event.preventDefault();

    for (const f of event.clipboardData.files) {
        const file: NerdMessageFile = {
            data: CryptoHelper.enc.UintToString(await f.arrayBuffer(), "base64"),
            type: f.type,
            name: f.name,
            size: f.size
        }

        addFile(file);
    }
});

document.getElementById("room").ondrop = async function (event: DragEvent) {
    event.preventDefault();

    for (const f of [...event.dataTransfer.files]) {
        const file: NerdMessageFile = {
            data: CryptoHelper.enc.UintToString(await f.arrayBuffer(), "base64"),
            type: f.type,
            name: f.name,
            size: f.size
        }

        addFile(file);
    }
};

document.getElementById("invitemember").addEventListener("click", async () => {
    if (!client) return;

    const room = client.rooms.get(currentRoom);
    if (!room) return;

    const userId = prompt("ID of user to invite");
    if (userId === "" || !userId) return;

    client.rooms.inviteUser(room.roomId, userId);
});

messagesDiv.addEventListener("scroll", () => {
    if (messagesDiv.scrollTop === 0) {
        loadPrevMessages();
    }
});

document.getElementById("loadprev").addEventListener("click", loadPrevMessages);

document.getElementById("togglemembers").addEventListener("click", () => {
    if (membersDiv.style.display == "none") membersDiv.style.display = "block";
    else membersDiv.style.display = "none";
});

document.getElementById("uploadfile").addEventListener("click", () => {
    if (!client) return;

    const input = document.createElement("input");
    input.type = "file";
    input.multiple = true;

    input.onchange = async () => {
        for (let i = 0; i < input.files.length; i++) {
            const rawFile = input.files.item(i);
            const file: NerdMessageFile = {
                name: rawFile.name,
                size: rawFile.size,
                type: rawFile.type,
                data: CryptoHelper.enc.UintToString(await rawFile.arrayBuffer(), "base64")
            }

            addFile(file);
        }
        input.remove();
    }

    input.click();
});

window.addEventListener("nerdlock.newMessage", (event: CustomEvent<NerdMessage>) => {
    const room = client.rooms.get(currentRoom);
    if (!room || currentRoom !== event.detail.roomId) return;

    room.messages = room.messages.sort((a, b) => a.createdAt - b.createdAt);

    addMessage(event.detail, shouldAddInfo(room.messages, event.detail)).then(() => {
        // only scroll down, if the user is already scrolled down (the plus 50 is added so a small scroll will still trigger)
        if (messagesDiv.scrollTop + messagesDiv.clientHeight + 50 >= messagesDiv.scrollHeight)
            scrollToBottom();
    });
});

window.addEventListener("nerdlock.roomSync", () => {
    reloadRooms();
});

window.addEventListener("nerdlock.userSync", reloadMembers);

window.ondrop = function (event: DragEvent) {
    event.preventDefault();
}

window.ondragover = function (event: DragEvent) {
    event.preventDefault();
}

async function reloadRooms() {
    roomsDiv.innerHTML = "";
    for (const room of await client.rooms.getRooms()) {
        const button = document.createElement("button");
        button.innerText = room.name;
        roomsDiv.appendChild(button);

        button.onclick = async () => {
            if (loadingRoom) return;

            loadingRoom = true;
            document.getElementById("roomname").innerText = "Loading room, please wait...";

            if (currentRoom === room.roomId) return;
            currentRoom = room.roomId;

            const realRoom = client.rooms.get(currentRoom);

            messagesDiv.innerHTML = "";

            await reloadMembers();
            await client.rooms.loadMessages(realRoom.roomId, { after: realRoom.messages.slice(-1)[0]?.createdAt });
            for (const m of realRoom.messages) {
                await addMessage(m, shouldAddInfo(realRoom.messages, m));
            }

            messagesDiv.scrollTop = messagesDiv.scrollHeight;
            loadingRoom = false;
            document.getElementById("roomname").innerText = realRoom.name;
        }
    }
}

async function reloadMembers() {
    const room = client.rooms.get(currentRoom);
    if (!room) return;

    document.getElementById("members.online").innerText = "";
    document.getElementById("members.offline").innerText = "";

    for (const memberObj of room.members) {
        const member = await client.userStore.fetchUser(memberObj.memberId);

        const p = document.createElement("p");
        p.innerText = member.username;

        if (member.online) document.getElementById("members.online").appendChild(p);
        else document.getElementById("members.offline").appendChild(p);
    }
}

async function addMessage(message: NerdMessage, needInfo: boolean) {
    if (currentRoom !== message.roomId) return;

    const author = await client.userStore.fetchUser(message.authorId);
    const messageDiv = document.createElement("div");
    messageDiv.id = `message.${message.messageId}`;
    messageDiv.classList.add("message");

    if (!message.verified) messageDiv.classList.add("unverified");

    if ((message.content.files ?? []).length !== 0) needInfo = true;
    if (message.content.replyingTo) needInfo = true;

    addReply: if (message.content.replyingTo) {
        const repliedMessage = client.rooms.get(currentRoom).messages.find(m => m.messageId === message.content.replyingTo);

        const reply = document.createElement("div");
        reply.classList.add("reply");
        if (!repliedMessage) {
            reply.innerText = `Message couldn't be loaded`;
            break addReply;
        }

        reply.onclick = () => {
            const message = document.getElementById(`message.${repliedMessage.messageId}`);
            messagesDiv.scroll({ top: message.offsetTop - 100, behavior: "smooth" });

            message.classList.add("highlight");
            setTimeout(() => {
                message.classList.remove("highlight");
            }, 800);
        }

        const author = await client.userStore.fetchUser(repliedMessage.authorId);
        reply.innerText = `${author.username}: `;

        if (repliedMessage.content.text)
            reply.innerText += `${repliedMessage.content.text}`;
        else if (repliedMessage.content.files?.length !== 0)
            reply.innerText += `${repliedMessage.content.files.length} files uploaded`;

        messageDiv.appendChild(reply);
    }

    if (needInfo) {
        const messageInfo = document.createElement("p");
        messageInfo.classList.add("messageinfo");
        messageInfo.innerText = author.username;
        messageInfo.innerHTML += `<span class="date">(${new Date(message.createdAt).toLocaleString("en-US", dateFormat)})</span>`;
        messageDiv.appendChild(messageInfo);
    }

    const content = document.createElement("p");
    content.classList.add("content");
    content.innerText = `${message.content?.text ?? message.content}`;
    messageDiv.appendChild(content);

    for (const f of message.content?.files ?? []) {
        if (f.type.indexOf("image") !== -1 || f.type.indexOf("video") !== -1) {
            const element = f.type.indexOf("image") !== -1 ? document.createElement("img") : document.createElement("video");

            element.src = `data:${f.type};base64,${f.data}`;
            if (element instanceof HTMLVideoElement) element.setAttribute("controls", "controls");

            messageDiv.appendChild(element);
        } else {
            const element = document.createElement("a");
            element.classList.add("file");

            // create file
            const blob = new Blob([CryptoHelper.enc.StringToUint(f.data, "base64")], { type: f.type });
            const objectURL = URL.createObjectURL(blob);

            element.innerText = f.name;
            element.download = f.name;
            element.href = objectURL;

            messageDiv.appendChild(element);
        }
    }

    // create context menu
    messageDiv.addEventListener("contextmenu", (event) => {
        if (event.target instanceof HTMLImageElement || event.target instanceof HTMLVideoElement || event.target instanceof HTMLAnchorElement)
            return;

        event.preventDefault();

        contextMenu.classList.add("visible");

        const { clientX: mouseX, clientY: mouseY } = event;
        const { xNorm, yNorm } = normalizeContextPosition(mouseX, mouseY);

        contextMenu.style.left = `${xNorm}px`;
        contextMenu.style.top = `${yNorm}px`;
        contextMenu.focus();

        document.getElementById("replymessage").onclick = () => {
            contextMenu.classList.remove("visible");

            document.getElementById("replyingto").innerText = `Replying to ${author.username}`;
            replyingTo = message.messageId;
        }

        document.getElementById("showmessageinfo").onclick = () => {
            contextMenu.classList.remove("visible");

            messageInfo.value = JSON.stringify(message);
            setTimeout(() => messageInfo.classList.add("visible"), 100);
        }

        document.getElementById("copymessageid").onclick = () => {
            contextMenu.classList.remove("visible");

            navigator.clipboard.writeText(message.messageId);
        }
    })

    messagesDiv.appendChild(messageDiv);
}

function scrollToBottom() {
    messagesDiv.scroll({ behavior: "smooth", top: messagesDiv.scrollHeight });
}

function addFile(file: NerdMessageFile) {
    filesToUpload.push(file);

    if (filesToUpload.length === 1) filesDiv.innerText = "Uploading files: ";

    const p = document.createElement("p");
    p.innerText = file.name;
    filesDiv.appendChild(p);

    p.onclick = () => {
        filesToUpload.splice(filesToUpload.indexOf(file), 1);
        p.remove();

        if (filesToUpload.length === 0) filesDiv.innerText = "";
    }
}

async function loadPrevMessages() {
    const room = client.rooms.get(currentRoom);
    if (!room) return;

    const newMessages = await client.rooms.loadMessages(room.roomId, { before: room.messages[0]?.createdAt ?? Date.now() });
    if (newMessages === 0) return;

    const currentScroll = messagesDiv.scrollHeight - messagesDiv.clientHeight - messagesDiv.scrollTop;

    messagesDiv.innerHTML = "";
    for (const m of room.messages) {
        await addMessage(m, shouldAddInfo(room.messages, m));
    }

    messagesDiv.scrollTop = messagesDiv.scrollHeight - messagesDiv.clientHeight - currentScroll;
}

function createPopup() {
    const popup = document.createElement("div");
    popup.classList.add("popup");
    document.body.appendChild(popup);

    return popup;
}

function shouldAddInfo(messages: NerdMessage[], message: NerdMessage, index?: number) {
    const previous = messages[index ? (index - 1) : (messages.findIndex(m => m.messageId === message.messageId) - 1)];
    if (!previous) return true;

    return message.authorId !== previous.authorId || (message.createdAt - previous.createdAt) > 5 * 60 * 1000; // if there are 5 minutes between the two messages, include info again
}

const normalizeContextPosition = (mouseX: number, mouseY: number) => {
    const xNorm = mouseX + contextMenu.scrollWidth >= window.innerWidth
        ? window.innerWidth - contextMenu.scrollWidth - 20
        : mouseX;
    const yNorm = mouseY + contextMenu.scrollHeight >= window.innerHeight
        ? window.innerHeight - contextMenu.scrollHeight - 20
        : mouseY;

    return { xNorm, yNorm };
}


// set up service worker
await navigator.serviceWorker.register("/service.js", {
    type: "module",
    scope: "."
}).catch(console.error);