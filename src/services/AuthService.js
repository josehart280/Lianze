
class AuthService {
  static async login(email, password) {
    try {
      const response = await fetch('http://localhost:3000/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Error en la autenticación');
      }

      return await response.json();
    } catch (error) {
      console.error('Error en AuthService:', error);
      throw error;
    }
  }
}