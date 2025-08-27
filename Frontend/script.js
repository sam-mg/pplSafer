let selectedFiles = [];

// File input change handler
document.getElementById('fileInput').addEventListener('change', function(e) {
    const newFiles = Array.from(e.target.files);
    
    // Add new files to the existing list
    newFiles.forEach(file => {
        // Check if file is already in the list (by name and size)
        const isDuplicate = selectedFiles.some(existing => 
            existing.name === file.name && existing.size === file.size
        );
        
        if (!isDuplicate) {
            selectedFiles.push(file);
        }
    });
    
    // Reset the input value to allow selecting the same file again
    e.target.value = '';
    
    updateFileList();
});

function updateFileList() {
    const fileList = document.getElementById('fileList');
    const emptyState = document.getElementById('emptyState');
    
    if (selectedFiles.length === 0) {
        fileList.innerHTML = '<div class="empty-state" id="emptyState">No file chosen</div>';
        return;
    }
    
    let html = '';
    selectedFiles.forEach((file, index) => {
        const sizeInMB = (file.size / (1024 * 1024)).toFixed(2);
        html += `
            <div class="file-item">
                <div class="file-info">
                    <div class="file-name">${escapeHtml(file.name)}</div>
                    <div class="file-size">${sizeInMB} MB</div>
                </div>
                <button class="remove-btn" onclick="removeFile(${index})" title="Remove file">
                    ✖
                </button>
            </div>
        `;
    });
    
    fileList.innerHTML = html;
}

function removeFile(index) {
    selectedFiles.splice(index, 1);
    updateFileList();
    hideMessage();
}

function uploadFiles() {
    if (selectedFiles.length === 0) {
        alert('Please select at least one APK file!');
        return;
    }
    
    const uploadBtn = document.getElementById('uploadBtn');
    const originalText = uploadBtn.innerHTML;
    
    // Show loading state
    uploadBtn.innerHTML = '<span class="loading"></span>Uploading...';
    uploadBtn.disabled = true;
    
    // Create FormData object
    const formData = new FormData();
    selectedFiles.forEach((file, index) => {
        formData.append('apkFiles', file);
    });
    
    // Send POST request
    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            return response.text();
        } else {
            throw new Error('Upload failed');
        }
    })
    .then(data => {
        showMessage('Files uploaded successfully!', 'success');
        selectedFiles = [];
        updateFileList();
    })
    .catch(error => {
        console.error('Upload error:', error);
        showMessage('Upload failed!', 'error');
    })
    .finally(() => {
        // Reset button state
        uploadBtn.innerHTML = originalText;
        uploadBtn.disabled = false;
    });
}

function showMessage(text, type) {
    const message = document.getElementById('message');
    message.className = `message ${type}`;
    message.textContent = text;
    
    // Auto-hide success messages after 3 seconds
    if (type === 'success') {
        setTimeout(hideMessage, 3000);
    }
}

function hideMessage() {
    const message = document.getElementById('message');
    message.className = 'message hidden';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Hide message when user interacts with the page
document.addEventListener('click', function(e) {
    if (!e.target.closest('.message')) {
        hideMessage();
    }
});