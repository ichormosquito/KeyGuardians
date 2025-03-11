let selectedfriend = ''; 
// let sender = 

const friends = document.querySelector('.friends-sidebar');

friends.addEventListener('click', selectFriend);

function selectFriend(event) {
    // Check if item clicked is part of .friend class 
    if (event.target && event.target.classList.contains('friend')) {
        // Get the name of the friend
        selectedfriend = event.target.textContent; 
        console.log("Friend selected: ", selectedfriend); 
        // Load chat history with selected friend
        loadChatHistory(selectedfriend); 
        pollingFunction();
    }
}

//populates 'friends list' with accounts that user has message history with 
function initializeMessaging() {
    fetch('/get_messages')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error("Error:", data.error);
                return;
            }
            const messages = data.messages;
            //gather unique account names that user has messages with
            const friendsSet = new Set();
            const loggedInUser = data.username;
            messages.forEach(msg => {
                if (msg.sender !== loggedInUser) {
                    friendsSet.add(msg.sender);
                }
                if (msg.recipient !== loggedInUser) {
                    friendsSet.add(msg.recipient);
                }
            });
            const friendsList = document.getElementById('friends-list');
            //populate friends list with unique account names
            friendsSet.forEach(friend => {
                const friendDiv = document.createElement('div');
                friendDiv.classList.add('friend');
                friendDiv.textContent = friend;
                friendDiv.onclick = () => {
                    selectedfriend = friend; 
                    loadChatHistory(friend);
                    pollingFunction();
                };
                friendsList.appendChild(friendDiv);
            });
        })
        .catch(error => console.error("Error:", error));
}

//Populates chat box with messages between user and selected friend
function loadChatHistory(friend) {
    fetch('/get_messages')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error("Error:", data.error);
                return;
            }
            const messages = data.messages;
            const loggedInUser = data.username;
            const chatBox = document.querySelector(".chat-box");
            chatBox.innerHTML = '';
            messages.forEach(msg => {
                if ((msg.sender === friend && msg.recipient === loggedInUser) || (msg.sender === loggedInUser && msg.recipient === friend)) {
                    const messageDiv = document.createElement('div');
                    messageDiv.classList.add(msg.sender === loggedInUser ? 'user-message' : 'recieved-message');
                    messageDiv.textContent = `${msg.sender}: ${msg.message}`;
                    chatBox.appendChild(messageDiv);
                }
            });
            document.getElementById("input-container").style.display = "flex";
            loadReceivedFiles();
        })
        .catch(error => console.error("Error:", error));
}

function sendMessage() {
    let message = document.getElementById("messageInput").value; 

    if (!selectedfriend){
        console.log("No friend Chosen, picked default")
    }

    // No empty messages sent 
    if (message.trim() === ""){
        return;
    } 

    fetch('/send_message', {
        method: 'POST',
        body: JSON.stringify({ "message": message, "recipient": selectedfriend }),
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            console.error("Error:", data.error);
            return;
        }
        let chat_box = document.querySelector(".chat-box"); 
        let newMessage = document.createElement("div"); 
        newMessage.classList.add("user-message"); 
        newMessage.textContent = `${data.sender}: ${data.message}`; 
        chat_box.appendChild(newMessage); 

        document.getElementById("messageInput").value = ""; 
    })
    .catch(error => console.error("Error:", error)); 
}

//sends "hi" to new friend and loads chat history
function startConversation() {
    let newFriend = document.getElementById("newFriendUsername").value;
    
    //handle empty input
    if (newFriend.trim() === "") {
        return;
    }
    
    fetch('/send_message', {
        method: 'POST',
        body: JSON.stringify({ "message": "hi", "recipient": newFriend }),
        headers: {
            'Content-Type': 'application/json'}})
    .then(response => response.json())
    .then(data =>{
        if (data.error){
            console.error("Error:", data.error);
            document.getElementById("newFriendError").textContent = data.error;
            return;}
        document.getElementById("newFriendError").textContent = "";
        loadChatHistory(newFriend);})
    .catch(error => console.error("Error:", error));}
function uploadFile(){// functionality for file upload
    let fileInput = document.getElementById("fileInput");
    let file = fileInput.files[0];
    if(!file){
        console.log("No file selected");
        return;}
    let formData= new FormData();
    formData.append("file", file);
    formData.append("recipient", selectedfriend);
    fetch('/upload_file', {
        method: 'POST',
        body: formData})
    .then(response=> response.json())
    .then(data =>{
        if (data.error) {
            console.error("Error:", data.error);
            return;}
        console.log("File uploaded successfully");
        loadReceivedFiles();})
    .catch(error => console.error("Error:", error));}
function loadReceivedFiles(){// loads the received files
    fetch('/get_messages')
        .then(response =>response.json())
        .then(data =>{
            if (data.error) {
                console.error("Error:", data.error);
                return;}
            const messages =data.messages;
            const loggedInUser= data.username;
            const fileList =document.getElementById("file-list");
            fileList.innerHTML = '';
            messages.forEach(msg =>{
                if(msg.recipient=== loggedInUser && msg.filename) {
                    let listItem= document.createElement("li");
                    let downloadLink= document.createElement("a");
                    downloadLink.href =`/download_file/${msg.filename}`;
                    downloadLink.textContent= `Download ${msg.filename}`;
                    listItem.appendChild(downloadLink);
                    fileList.appendChild(listItem);}});})
        .catch(error => console.error("Error:",error));}
let ajaxPollingInterval; 
let messageCountUpdate = 0; 
function pollingFunction(){
    clearInterval(ajaxPollingInterval);
    ajaxPollingInterval =setInterval(() => {
        fetch('/get_messages')
            .then(response=> response.json())
            .then(data =>{
                if (data.error) {
                    console.error("Error:", data.error);
                    return;}
                const messages =data.messages.filter(message =>
                    (message.sender ===selectedfriend &&message.recipient=== data.username)||(message.sender===data.username&&message.recipient ===selectedfriend));
                if(messages.length!== messageCountUpdate){
                    messageCountUpdate = messages.length;
                    const chatBox =document.querySelector(".chat-box");
                    chatBox.innerHTML ='';
                    messages.forEach(message => {
                        const messageDiv = document.createElement('div');
                        messageDiv.classList.add(message.sender === data.username ? 'user-message' : 'received-message');
                        messageDiv.textContent = `${message.sender}: ${message.message}`;
                        chatBox.appendChild(messageDiv);
                    });}})
            .catch(error => console.error("Error:", error));
    }, 3000);}  //polling every 3 seconds

// function updateChat(){
//     const request = new XMLHttpRequest(); 
// }
