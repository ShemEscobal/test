document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("registerForm").addEventListener("submit", async (e) => {
        e.preventDefault();
        
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;
        const email = document.getElementById("email").value.toLowerCase(); // Ensure consistent email format
        
        // Get the error element
        const errorElement = document.getElementById("registerError");
        
        // Validate username - no spaces allowed
        if (username.includes(' ')) {
            errorElement.textContent = "Username cannot contain spaces.";
            errorElement.classList.remove("d-none", "alert-success");
            errorElement.classList.add("alert-danger");
            return;
        }
        
        // Show loading state
        const submitButton = document.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;
        submitButton.disabled = true;
        submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Registering...';
        
        // Hide any previous error
        errorElement.classList.add("d-none");

        try {
            const response = await fetch("http://localhost:3000/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password, email }),
            });

            const data = await response.json();

            if (response.ok) {
                // Show success message
                errorElement.textContent = data.message || "Registration successful! Redirecting to login...";
                errorElement.classList.remove("d-none", "alert-danger");
                errorElement.classList.add("alert-success");
                
                // Redirect to login page after a delay
                setTimeout(() => window.location.href = "login.html", 2000);
            } else {
                // Show error message
                errorElement.textContent = data.message || "Registration failed. Please try again.";
                errorElement.classList.remove("d-none", "alert-success");
                errorElement.classList.add("alert-danger");
                
                // Reset button state
                submitButton.disabled = false;
                submitButton.innerHTML = originalButtonText;
            }
        } catch (error) {
            // Show error message for network/server issues
            errorElement.textContent = "Error connecting to server. Please try again.";
            errorElement.classList.remove("d-none", "alert-success");
            errorElement.classList.add("alert-danger");
            
            // Reset button state
            submitButton.disabled = false;
            submitButton.innerHTML = originalButtonText;
        }
    });
});
