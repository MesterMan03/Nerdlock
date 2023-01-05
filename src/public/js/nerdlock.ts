import CryptoHelper from "./CryptoHelper.js";
import NerdClient, { NerdMessage, NerdMessageFile } from "./NerdClient.js";
globalThis.NerdClient = NerdClient;
globalThis.CryptoHelper = CryptoHelper;

let client: NerdClient;
let currentRoom: string;

const dateFormat: Intl.DateTimeFormatOptions = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: "numeric", minute: "numeric", second: "numeric" };

const messagesDiv = document.getElementById("messages") as HTMLDivElement;
const roomsDiv = document.getElementById("rooms") as HTMLDivElement;
const messageInput = document.getElementById("messageinput") as HTMLDivElement;
const membersDiv = document.getElementById("members") as HTMLDivElement;
const filesDiv = document.getElementById("files") as HTMLDivElement;
const contextMenu = document.getElementById("contextmenu") as HTMLDivElement;
const messageInfo = document.getElementById("messageinfo") as HTMLTextAreaElement;

let filesToUpload: NerdMessageFile[] = [];

document.addEventListener("click", (e) => {
    if (e.target != messageInfo && messageInfo.classList.contains("visible")) {
        return messageInfo.classList.remove("visible");
    }

    //@ts-expect-error
    if (e.target.offsetParent != contextMenu && contextMenu.classList.contains("visible")) {
        return contextMenu.classList.remove("visible");
    }
})

document.getElementById("closeuser").addEventListener("click", () => {
    document.getElementById("usercontainer").style.display = "none";
})

document.getElementById("authform").addEventListener("submit", async (event) => {
    event.preventDefault();

    document.getElementById("authform").style.display = "none";

    document.getElementById("userinfo").style.display = "flex";
    document.getElementById("userid").innerText = "Loading...";

    const homeServer = (document.getElementById("homeserver") as HTMLInputElement).value;
    const username = (document.getElementById("username") as HTMLInputElement).value;
    const password = (document.getElementById("password") as HTMLInputElement).value;
    const totp = (document.getElementById("totpcode") as HTMLInputElement).value;
    const type = (document.getElementById("authtype") as HTMLSelectElement).value;

    const newClient = type === "login" ? await NerdClient.login(homeServer, username, password, { totp: totp === "" ? undefined : totp }) : await NerdClient.register(homeServer, username, password);
    if (!newClient) {
        document.getElementById("authform").style.display = "flex";
        document.getElementById("userinfo").style.display = "none";
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

    input.addEventListener("keydown", (ev) => {
        if (ev.key !== "Enter") return;

        const result = client.totp("activate", input.value);
        if (result)
            alert("TOTP 2FA has been enabled!");
        else
            alert("There was an error while trying to enable TOTP 2FA, please check the Console");

        popup.remove();
    })
});

document.getElementById("enableu2f").addEventListener("click", async () => {
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

async function sendMessage(event: MouseEvent | KeyboardEvent) {
    if (!client) return;

    const room = client.rooms.get(currentRoom);
    if (!room) return;

    if ((event instanceof KeyboardEvent && event.key === "Enter" && !event.shiftKey) || event instanceof MouseEvent) {
        event.preventDefault();

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
        client.rooms.sendMessage(room.roomId, { text: content, files });
    }
}

messageInput.addEventListener("keypress", sendMessage);
document.getElementById("sendmessage").addEventListener("click", sendMessage);

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

    addMessage(event.detail, room.messages[room.messages.findIndex(m => m.messageId === event.detail.messageId) - 1]?.authorId !== event.detail.authorId).then(() => {
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
            if (currentRoom === room.roomId) return;
            currentRoom = room.roomId;

            const realRoom = client.rooms.get(currentRoom);

            messagesDiv.innerHTML = "";

            reloadMembers();
            await client.rooms.loadMessages(realRoom.roomId, { after: realRoom.messages.slice(-1)[0]?.createdAt });
            await Promise.all(realRoom.messages.map((m, index, self) => addMessage(m, self[index - 1]?.authorId !== m.authorId)));

            messagesDiv.scrollTop = messagesDiv.scrollHeight;
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
    messageDiv.classList.add("message");

    if (!message.verified) messageDiv.classList.add("unverified");

    if ((message.content?.files ?? []).length !== 0) needInfo = true;

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

        contextMenu.style.left = "0px";
        contextMenu.style.top = "0px";

        contextMenu.style.left = `${Math.min(event.clientX, document.body.clientWidth - contextMenu.clientWidth) - 20}px`;
        contextMenu.style.top = `${Math.min(event.clientY, document.body.clientHeight - contextMenu.clientHeight) - 20}px`;
        contextMenu.focus();
        contextMenu.classList.add("visible");

        document.getElementById("showmessageinfo").onclick = () => {
            messageInfo.value = JSON.stringify(message);
            contextMenu.classList.remove("visible");

            setTimeout(() => messageInfo.classList.add("visible"), 100);
        }

        document.getElementById("copymessageid").onclick = () => {
            navigator.clipboard.writeText(message.messageId);
            contextMenu.classList.remove("visible");
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
    await Promise.all(room.messages.map((m, index, self) => addMessage(m, self[index - 1]?.authorId !== m.authorId)));

    messagesDiv.scrollTop = messagesDiv.scrollHeight - messagesDiv.clientHeight - currentScroll;
}

function createPopup() {
    const popup = document.createElement("div");
    popup.classList.add("popup");
    document.body.appendChild(popup);

    return popup;
}


// set up service worker
await navigator.serviceWorker.register("/service.js", {
    type: "module",
    scope: "."
}).catch(console.error);