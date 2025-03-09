let selectedfriend = ''; 
// let sender = 

const friends = document.querySelector('.friends-sidebar');

friends.addEventListener('click', selectFriend)

function selectFriend(event){
    // Check if item clicked has is part of .friend class 
    if (event.target && event.target.classList.contains('friend')) {
        // Get the name of the friend
        selectedfriend = event.target.textContent; 
        console.log("Friend selected: ", selectedfriend); 
        // Load chat history with selected friend
        loadChatHistory(selectedfriend); 
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
                friendDiv.onclick = () => loadChatHistory(friend);
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
        return
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
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            console.error("Error:", data.error);
            document.getElementById("newFriendError").textContent = data.error;
            return;
        }
        document.getElementById("newFriendError").textContent = "";
        loadChatHistory(newFriend);
    })
    .catch(error => console.error("Error:", error));
}

// function updateChat(){
//     const request = new XMLHttpRequest(); 
// }