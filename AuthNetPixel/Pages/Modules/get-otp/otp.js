let otpTimeout;

function fetchOtp() {
    fetch('http://192.168.1.64:5000/generate-otp')
        .then(response => response.json())
        .then(data => {
            document.getElementById('otp').innerText = `Seu código OTP: ${data.otp}`;
            document.getElementById('message').innerText = "Outro código surgirá daqui 120 segundos.";
            startLoading(); // Reinicia a barra de carregamento
        })
        .catch(error => console.error('Erro ao gerar OTP:', error));
}

function startLoading() {
    const progress = document.querySelector('.progress'); // Seleciona pelo nome da classe
    progress.style.width = '0'; // Reseta a largura
    progress.style.transition = 'none'; // Remove a transição para o reset

    // Atraso pequeno para garantir que o reset aconteça antes de iniciar a animação
    setTimeout(() => {
        progress.style.transition = 'width 120s linear'; // Reativa a transição
        progress.style.width = '100%'; // Preenche a barra
    }, 10);

    // Reinicia a barra após 120 segundos
    otpTimeout = setTimeout(() => {
        progress.style.transition = 'none'; // Remove a transição para o reset
        progress.style.width = '0'; // Reseta a largura novamente
        fetchOtp(); // Gera um novo OTP
    }, 120000); 
}

window.onload = function() {
    fetchOtp(); // Gera o primeiro OTP ao carregar a página
};

