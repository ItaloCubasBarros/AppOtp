function verifyOtp() {
    const otpValue = document.getElementById('otpInput').value.trim();

    if (!otpValue) {
        document.getElementById('verificationMessage').innerText = "Por favor, insira o OTP.";
        return;
    }

    fetch('http://192.168.1.64:5000/verify-otp', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ otp: otpValue })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('verificationMessage').innerText = data.message;
    })
    .catch(error => {
        console.error('Erro ao verificar OTP:', error);
        document.getElementById('verificationMessage').innerText = "Erro ao verificar OTP.";
    });
}
