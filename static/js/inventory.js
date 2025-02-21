// Function to save the item
function saveItem() {
    const form = document.getElementById('addItemForm');
    const formData = new FormData(form);
    
    // Convert FormData to JSON object
    const data = {};
    formData.forEach((value, key) => {
        data[key] = value;
    });

    // Send POST request to Flask backend
    fetch('/add_item', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        // Close the modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('addItemModal'));
        modal.hide();
        
        // Refresh the page to show new item
        location.reload();
        
        // Show success message
        showAlert('Item saved successfully!', 'success');
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('Error saving item. Please try again.', 'danger');
    });
}

// Helper function to show alerts
function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.role = 'alert';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    const container = document.querySelector('.container');
    container.insertBefore(alertDiv, container.firstChild);
    
    // Auto dismiss after 3 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 3000);
}