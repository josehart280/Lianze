document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('loginForm');

  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;

      try {
        const response = await AuthService.login(email, password);
        
        if (response.success) {
          // Redirigir según el tipo de usuario
          if (response.user.userType === 'patient') {
            window.location.href = 'dashboard-patient.html';
          } else if (response.user.userType === 'psychologist') {
            window.location.href = 'dashboard-psychologist.html';
          }
        } else {
          alert('Credenciales incorrectas');
        }
      } catch (error) {
        alert(error.message || 'Error al iniciar sesión');
      }
    });
  }
});