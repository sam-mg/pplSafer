const fileInput = document.getElementById("fileInput");
const fileList = document.getElementById("fileList");
const emptyState = document.getElementById("emptyState");
const message = document.getElementById("message");
const uploadBtn = document.getElementById("uploadBtn");

let selectedFile = null;

// When a file is chosen
fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];

    if (file) {
        selectedFile = file;
        renderFileList();
    }
});

// Render file list with remove option
function renderFileList() {
    fileList.innerHTML = "";

    if (!selectedFile) {
        emptyState.style.display = "block";
        return;
    }

    emptyState.style.display = "none";

    const fileItem = document.createElement("div");
    fileItem.className = "file-item";
    fileItem.innerHTML = `
        <span>${selectedFile.name}</span>
        <button class="remove-btn">❌</button>
    `;

    fileItem.querySelector(".remove-btn").addEventListener("click", () => {
        selectedFile = null;
        fileInput.value = "";  // reset input so new selection works
        renderFileList();
    });

    fileList.appendChild(fileItem);
}

// Upload handler
async function uploadFiles() {
    if (!selectedFile) {
        alert("Please select a file first!");
        return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
        const response = await fetch("/upload", {
            method: "POST",
            body: formData,
        });

        const result = await response.json();
        message.textContent = result.message;
        message.className = "message success";
    } catch (error) {
        message.textContent = "Upload failed.";
        message.className = "message error";
    }
}

// Attach upload button click
uploadBtn.addEventListener("click", uploadFiles);
