(function () {
    var form = document.getElementById('login-form');
    form.addEventListener('submit', function (e) {
        e.preventDefault();
        var pwd = document.getElementById('password').value;
        var errorDiv = document.getElementById('login-error');

        // Use the generated OpenAPI client exclusively
        var cfg = new OpenApiClient.Configuration({ basePath: '/api', credentials: 'same-origin' });
        var client = new OpenApiClient.DefaultApi(cfg);

        client.loginPost({ loginRequest: { password: pwd } }).then(function (data) {
            try {
                localStorage.setItem('wg_access_token', data.access_token);
                window.location.href = '/dashboard';
                return;
            } catch (err) {
                // Update error div to show error
                console.error('Error processing login response:', err);
                errorDiv.textContent = 'Login error: ' + err.message;
                errorDiv.classList.remove('d-none');
            }
        }).catch(function (err) {
            console.error('Login error:', err);
            var status = err.response ? err.response.status : null;
            if (status === 403) {
                errorDiv.textContent = 'Invalid password';
            } else if (status === 429) {
                errorDiv.textContent = 'Too many failed login attempts, try again later';
            } else {
                errorDiv.textContent = err.message;
            }
            errorDiv.classList.remove('d-none');
        });
    })
}());
