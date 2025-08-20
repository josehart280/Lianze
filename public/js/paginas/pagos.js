function getUserId() {
    const user = JSON.parse(localStorage.getItem('user'));
    return user ? user.id : null;
}

document.addEventListener('DOMContentLoaded', function() {
    // Cargar métodos de pago al iniciar
    loadPaymentMethods();

    // Configurar datos del psicólogo
    const urlParams = new URLSearchParams(window.location.search);
    const psychologist = JSON.parse(urlParams.get('psychologist') || localStorage.getItem('selectedPsychologist'));
    
    if (psychologist) {
        localStorage.setItem('selectedPsychologist', JSON.stringify(psychologist));
        
        document.getElementById('psychologistInitials').textContent = 
            (psychologist.firstName ? psychologist.firstName.charAt(0) : '') + 
            (psychologist.lastName ? psychologist.lastName.charAt(0) : '');
        
        document.getElementById('psychologistName').textContent = 
            `${psychologist.firstName} ${psychologist.lastName}`;
        
        const specialties = Array.isArray(psychologist.specialties) ? 
            psychologist.specialties.join(', ') : psychologist.specialties;
        document.getElementById('psychologistSpecialty').textContent = specialties;
        
        const hourlyRate = psychologist.hourlyRate || 0;
        document.getElementById('sessionFee').textContent = `$${hourlyRate.toFixed(2)}`;
        document.getElementById('totalAmount').textContent = `$${(hourlyRate + 5).toFixed(2)}`;
        document.getElementById('paymentButtonText').textContent = `Pagar $${(hourlyRate + 5).toFixed(2)}`;
    }
    
    // Configurar fecha de cita
    const now = new Date();
    const appointmentDate = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const options = { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' };
    document.getElementById('appointmentDateTime').textContent = 
        appointmentDate.toLocaleDateString('es-ES', options);

    // Event listener para el botón de pago
    const paymentButton = document.getElementById('processPaymentButton');
    if (paymentButton) {
        paymentButton.addEventListener('click', function() {
            const defaultCard = JSON.parse(localStorage.getItem('defaultPaymentMethod'));
            const cardNumber = document.getElementById('cardNumber').value;
            
            if (defaultCard && cardNumber.includes('••••')) {
                processPaymentWithDefaultCard(defaultCard);
            } else {
                processPayment();
            }
        });
    } else {
        console.error('Botón de pago no encontrado');
    }
});

async function loadPaymentMethods() {
    const userId = getUserId();
    if (!userId) {
        console.error('Usuario no autenticado');
        return;
    }

    try {
        const response = await fetch(`/api/payment-methods/${userId}`);
        if (!response.ok) throw new Error('Error al cargar métodos de pago');
        
        const data = await response.json();
        if (!Array.isArray(data)) throw new Error('Formato de datos inválido');

        const defaultCard = data.find(card => card.isDefault);
        
        if (defaultCard) {
            document.getElementById('defaultCardSection').classList.remove('hidden');
            document.getElementById('defaultCardPreview').textContent = defaultCard.cardNumber;
            document.getElementById('defaultCardName').textContent = defaultCard.cardHolder;
            localStorage.setItem('defaultPaymentMethod', JSON.stringify(defaultCard));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error al cargar métodos de pago. Inténtalo de nuevo.');
    }
}

function useDefaultCard() {
    const defaultCard = JSON.parse(localStorage.getItem('defaultPaymentMethod'));
    if (!defaultCard) return;

    document.getElementById('cardNumber').value = defaultCard.cardNumber.replace(/\d{4}(?= \d{4})/g, "••••");
    document.getElementById('cardName').value = defaultCard.cardHolder;
    document.getElementById('cardExpiry').value = `${defaultCard.expirationMonth.toString().padStart(2, '0')}/${defaultCard.expirationYear.toString().slice(-2)}`;
    
    document.getElementById('card-preview-number').textContent = defaultCard.cardNumber.replace(/\d{4}(?= \d{4})/g, "••••");
    document.getElementById('card-preview-name').textContent = defaultCard.cardHolder.toUpperCase();
    document.getElementById('card-preview-expiry').textContent = `${defaultCard.expirationMonth.toString().padStart(2, '0')}/${defaultCard.expirationYear.toString().slice(-2)}`;
}

async function processPaymentWithDefaultCard(card) {
    const paymentButton = document.querySelector('#paymentForm button');
    const originalText = paymentButton.textContent;
    
    paymentButton.disabled = true;
    paymentButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Procesando pago...';
    
    try {
        const psychologist = JSON.parse(localStorage.getItem('selectedPsychologist'));
        const amount = psychologist.hourlyRate + 5;
        
        const response = await fetch('/api/payments/process', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({
                cardId: card.id,
                amount: amount,
                psychologistId: psychologist.id,
                description: `Cita con ${psychologist.firstName} ${psychologist.lastName}`
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Error al procesar el pago');
        }
        
        const paymentResult = await response.json();
        alert(`Pago exitoso. ID: ${paymentResult.transactionId}`);
        window.location.href = 'appointments.html';
    } catch (error) {
        console.error('Error:', error);
        alert('Error al procesar el pago: ' + error.message);
    } finally {
        paymentButton.disabled = false;
        paymentButton.textContent = originalText;
    }
}

async function processPayment() {
    const cardNumber = document.getElementById('cardNumber').value.replace(/\s+/g, '');
    const cardName = document.getElementById('cardName').value;
    const cardExpiry = document.getElementById('cardExpiry').value;
    const cardCvc = document.getElementById('cardCvc').value;
    const userId = getUserId();

    // Validaciones
    if (!cardNumber || cardNumber.length < 16) {
        alert('Número de tarjeta inválido');
        return;
    }
    
    if (!cardName) {
        alert('Ingresa el nombre en la tarjeta');
        return;
    }
    
    if (!cardExpiry || cardExpiry.length < 5) {
        alert('Fecha de expiración inválida');
        return;
    }
    
    if (!cardCvc || cardCvc.length < 3) {
        alert('Código CVC inválido');
        return;
    }
    
    if (!userId) {
        alert('Usuario no autenticado');
        return;
    }

    const paymentButton = document.querySelector('#paymentForm button');
    const originalText = paymentButton.textContent;
    paymentButton.disabled = true;
    paymentButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Procesando...';

    try {
        const psychologist = JSON.parse(localStorage.getItem('selectedPsychologist'));
        const amount = psychologist.hourlyRate + 5;
        const [expMonth, expYear] = cardExpiry.split('/');

        const response = await fetch('/api/payments/process', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({
                userId: userId,
                cardNumber: cardNumber,
                cardHolder: cardName,
                expirationMonth: parseInt(expMonth),
                expirationYear: parseInt(expYear),
                cvv: cardCvc,
                amount: amount,
                psychologistId: psychologist.id,
                description: `Cita con ${psychologist.firstName} ${psychologist.lastName}`
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Error al procesar el pago');
        }

        const paymentResult = await response.json();
        alert(`Pago exitoso. ID: ${paymentResult.transactionId}`);
        window.location.href = 'appointments.html';
    } catch (error) {
        console.error('Error:', error);
        alert('Error: ' + error.message);
    } finally {
        paymentButton.disabled = false;
        paymentButton.textContent = originalText;
    }
}

let sinpePaymentState = 'init'; // init, verify, complete
let sinpeTransactionId = null;

// Función para iniciar el pago con SINPE
function initSinpePayment() {
    // Verificar si el usuario ya tiene un teléfono asociado
    const userId = getUserId();
    if (!userId) {
        alert('Debes iniciar sesión para usar SINPE Móvil');
        return;
    }

    // Mostrar modal
    document.getElementById('sinpeModal').classList.remove('hidden');
    document.getElementById('sinpeVerificationSection').classList.add('hidden');
    document.getElementById('sinpeActionButton').textContent = 'Continuar con SINPE';
    sinpePaymentState = 'init';
}

// Función para cerrar el modal
function closeSinpeModal() {
    document.getElementById('sinpeModal').classList.add('hidden');
    sinpePaymentState = 'init';
    sinpeTransactionId = null;
}

// Función principal para procesar acciones SINPE
async function processSinpeAction() {
    const userId = getUserId();
    const phoneNumber = document.getElementById('sinpePhone').value.replace(/\s+/g, '');
    const verificationCode = document.getElementById('sinpeVerificationCode').value;
    const button = document.getElementById('sinpeActionButton');
    const originalText = button.textContent;

    if (!userId) {
        alert('Usuario no autenticado');
        return;
    }

    button.disabled = true;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Procesando...';

    try {
        if (sinpePaymentState === 'init') {
            // Paso 1: Verificar/Asociar teléfono
            if (!phoneNumber || phoneNumber.length < 8) {
                throw new Error('Número de teléfono inválido');
            }

            // Verificar si el teléfono ya está asociado y verificado
            const response = await fetch(`/api/sinpe/check-phone?userId=${userId}&phone=${phoneNumber}`);
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Error verificando número');
            }

            const data = await response.json();
            
            if (data.isVerified) {
                // Teléfono ya verificado, proceder directamente al pago
                await completeSinpePayment(userId, phoneNumber);
            } else {
                // Enviar código de verificación
                const verifyResponse = await fetch('/api/sinpe/send-code', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${localStorage.getItem('token')}`
                    },
                    body: JSON.stringify({
                        userId,
                        phoneNumber
                    })
                });

                if (!verifyResponse.ok) {
                    const errorData = await verifyResponse.json();
                    throw new Error(errorData.message || 'Error enviando código');
                }

                // Mostrar campo para código de verificación
                document.getElementById('sinpeVerificationSection').classList.remove('hidden');
                document.getElementById('sinpeActionButton').textContent = 'Verificar Código';
                sinpePaymentState = 'verify';
            }
        } else if (sinpePaymentState === 'verify') {
            // Paso 2: Verificar código
            if (!verificationCode || verificationCode.length !== 6) {
                throw new Error('Código de verificación inválido');
            }

            const verifyResponse = await fetch('/api/sinpe/verify-code', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    userId,
                    phoneNumber,
                    verificationCode
                })
            });

            if (!verifyResponse.ok) {
                const errorData = await verifyResponse.json();
                throw new Error(errorData.message || 'Error verificando código');
            }

            // Proceder con el pago
            await completeSinpePayment(userId, phoneNumber);
        }
    } catch (error) {
        console.error('Error en proceso SINPE:', error);
        alert('Error: ' + error.message);
    } finally {
        button.disabled = false;
        button.textContent = originalText;
    }
}

// Función para completar el pago con SINPE
async function completeSinpePayment(userId, phoneNumber) {
    const psychologist = JSON.parse(localStorage.getItem('selectedPsychologist'));
    const amount = psychologist.hourlyRate + 5; // Tarifa + comisión

    if (!psychologist || !psychologist.id) {
        alert('Error: No se ha seleccionado un psicólogo válido');
        return;
    }

    try {
        const response = await fetch('/api/sinpe/make-payment', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({
                userId,
                phoneNumber,
                amount,
                psychologistId: psychologist.id, // Asegurarse de que es el ID del perfil, no del usuario
                description: `Cita con ${psychologist.firstName} ${psychologist.lastName}`
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Error procesando pago');
        }

        const paymentResult = await response.json();
        
        // Mostrar confirmación
        alert(`Pago con SINPE Móvil exitoso. Referencia: ${paymentResult.reference}`);
        
        // Cerrar modal y redirigir
        closeSinpeModal();
        window.location.href = 'appointments.html';
    } catch (error) {
        console.error('Error en completeSinpePayment:', error);
        alert('Error: ' + error.message);
    }
}
async function verifySinpePhone(userId, phoneNumber) {
    try {
        const response = await fetch(`/api/sinpe/check-phone?userId=${userId}&phone=${phoneNumber}`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Error verificando número');
        }
        
        return await response.json();
    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
}

// Función para enviar código de verificación
async function sendSinpeVerificationCode(userId, phoneNumber) {
    try {
        const response = await fetch('/api/sinpe/send-code', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ userId, phoneNumber })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Error enviando código');
        }
        
        return await response.json();
    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
}

// Función para verificar código SINPE
async function verifySinpeCode(userId, phoneNumber, verificationCode) {
    try {
        const response = await fetch('/api/sinpe/verify-code', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ userId, phoneNumber, verificationCode })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Error verificando código');
        }
        
        return await response.json();
    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
}

// Función para guardar tarjeta como predeterminada
async function setDefaultPaymentMethod(userId, cardId) {
    try {
        // Primero quitar cualquier predeterminado existente
        await fetch('/api/payment-methods/set-default', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ userId, cardId })
        });
        
        return true;
    } catch (error) {
        console.error('Error:', error);
        return false;
    }
}