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
    }
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
        newMessage.textContent = data.message; 
        chat_box.appendChild(newMessage); 

        document.getElementById("messageInput").value = ""; 
    })
    .catch(error => console.error("Error:", error)); 
}




// function updateChat(){
//     const request = new XMLHttpRequest(); 
// }